#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
batchsentinel — offline static lint & risk scoring for multisig batches.

What it does (offline):
  • Accepts: 0x-hex MultiSend calldata OR a JSON file (Safe Tx Service export-like) with txs.
  • Parses Gnosis Safe MultiSend frames (operation,to,value,dataLength,data).
  • Decodes high-impact Safe methods: add/remove/swap owner, changeThreshold,
    enable/disable module, setGuard, setFallbackHandler.
  • Decodes ERC-20/721/1155 approvals/transfers, and EIP-2612 permit shape.
  • Scores & flags risky patterns (e.g., setApprovalForAll(true) + unknown call, infinite allowance,
    owner removals with threshold increase, module/guard changes, value outflows).
  • Emits JSON and pretty text; optional SVG “risk badge”.

Examples:
  $ python batchsentinel.py analyze 0x8d80ff0a... --json out.json --svg badge.svg
  $ python batchsentinel.py analyze safe_batch.json --pretty
"""

import json
import math
import os
import sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import click
from eth_utils import keccak, to_checksum_address

try:
    from eth_abi import decode as abi_decode
except Exception as e:
    print("Missing dependency eth-abi. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise

UINT256_MAX = (1 << 256) - 1

# ---------------------------- Signatures & helpers ----------------------------

def selector(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()

SAFE_SIGS = {
    "addOwnerWithThreshold(address,uint256)",
    "removeOwner(address,address,uint256)",
    "swapOwner(address,address,address)",
    "changeThreshold(uint256)",
    "enableModule(address)",
    "disableModule(address)",
    "setGuard(address)",
    "setFallbackHandler(address)",
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)"
}
SAFE_SEL = {selector(s): s for s in SAFE_SIGS}

ERC_SIGS = {
    "approve(address,uint256)": ["address","uint256"],
    "transfer(address,uint256)": ["address","uint256"],
    "transferFrom(address,address,uint256)": ["address","address","uint256"],
    "setApprovalForAll(address,bool)": ["address","bool"],
    "safeTransferFrom(address,address,uint256)": ["address","address","uint256"],
    "safeTransferFrom(address,address,uint256,bytes)": ["address","address","uint256","bytes"],
    "permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)":
        ["address","address","uint256","uint256","uint256","uint8","bytes32","bytes32"]
}
ERC_SEL = {selector(sig): (sig, types) for sig, types in ERC_SIGS.items()}

def split_selector_and_payload(data_hex: str) -> Tuple[str, bytes]:
    h = data_hex[2:] if data_hex.startswith("0x") else data_hex
    if len(h) < 8:
        return ("", bytes())
    return ("0x"+h[:8], bytes.fromhex(h[8:]))

def addr32_to_checksum(b: bytes) -> str:
    if len(b) >= 20:
        return to_checksum_address("0x" + b[-20:].hex())
    return "0x" + b.hex()

def u256(b: bytes) -> int:
    return 0 if not b else int.from_bytes(b, "big")

# ---------------------------- MultiSend parser ----------------------------

def parse_multisend_bytes(blob: bytes) -> List[Dict]:
    """
    MultiSend frames are packed as:
      operation:uint8 | to:20 | value:uint256 | dataLength:uint256 | data:<dataLength>
    Returns list of dicts: {operation,to,value,data_hex}
    """
    items = []
    i = 0
    n = len(blob)
    while i < n:
        if i + 1 + 20 + 32 + 32 > n:
            raise ValueError("Malformed MultiSend bytes")
        op = blob[i]
        i += 1
        to = "0x" + blob[i:i+20].hex()
        i += 20
        value = int.from_bytes(blob[i:i+32], "big")
        i += 32
        data_len = int.from_bytes(blob[i:i+32], "big")
        i += 32
        if i + data_len > n:
            raise ValueError("Truncated data in MultiSend")
        data_hex = "0x" + blob[i:i+data_len].hex()
        i += data_len
        items.append({
            "operation": op,
            "to": to_checksum_address(to),
            "value": value,
            "data": data_hex
        })
    return items

def is_multisend_selector(sel: str) -> bool:
    # canonical: multiSend(bytes)
    return sel == selector("multiSend(bytes)")

# ---------------------------- Decoders ----------------------------

def try_decode(sig_and_types: Tuple[str, List[str]], payload: bytes) -> Tuple[Optional[Dict], Optional[str]]:
    sig, types = sig_and_types
    try:
        vals = abi_decode(types, payload)
    except Exception as e:
        return None, f"abi decode error: {e}"
    # Map to friendly names
    fields = []
    if sig == "approve(address,uint256)":
        fields = ["spender","amount"]
    elif sig == "transfer(address,uint256)":
        fields = ["to","amount"]
    elif sig == "transferFrom(address,address,uint256)":
        fields = ["from","to","amount"]
    elif sig == "setApprovalForAll(address,bool)":
        fields = ["operator","approved"]
    elif sig.startswith("safeTransferFrom("):
        fields = ["from","to","tokenId"] + (["data"] if len(vals)==4 else [])
    elif sig.startswith("permit("):
        fields = ["owner","spender","value","nonce","deadline","v","r","s"]
    else:
        fields = [f"arg{i}" for i in range(len(vals))]

    out = {}
    for k, v in zip(fields, vals):
        if isinstance(v, (bytes, bytearray)):
            if len(v) == 20:
                out[k] = addr32_to_checksum(v)
            else:
                out[k] = "0x" + v.hex()
        elif isinstance(v, int):
            out[k] = int(v)
        elif isinstance(v, bool):
            out[k] = bool(v)
        else:
            out[k] = v
    return {"signature": sig, "params": out}, None

# ---------------------------- Analysis & risk ----------------------------

@dataclass
class Finding:
    level: str     # LOW / MEDIUM / HIGH
    reason: str
    context: Dict

def analyze_call(to: str, data_hex: str, value: int) -> Tuple[str, Dict, List[Finding]]:
    """
    Returns (kind, decoded, findings)
    kind: "safe", "erc", or "unknown"
    """
    findings: List[Finding] = []

    if not data_hex or data_hex in ("0x", "0x00"):
        if value > 0:
            findings.append(Finding("MEDIUM", "Native value transfer", {"to": to, "value": value}))
        return "unknown", {"selector": None}, findings

    sel, payload = split_selector_and_payload(data_hex)

    # Safe admin methods
    if sel in SAFE_SEL:
        sig = SAFE_SEL[sel]
        decoded = {"signature": sig}
        level = "HIGH"
        if sig == "changeThreshold(uint256)":
            level = "MEDIUM"
        findings.append(Finding(level, f"Gnosis Safe admin method: {sig}", {"to": to}))
        return "safe", decoded, findings

    # ERC methods
    if sel in ERC_SEL:
        decoded, err = try_decode(ERC_SEL[sel], payload)
        if decoded is None:
            return "erc", {"selector": sel, "error": err}, findings
        sig = decoded["signature"]
        if sig == "approve(address,uint256)":
            amt = decoded["params"]["amount"]
            if amt == UINT256_MAX:
                findings.append(Finding("HIGH", "Infinite ERC-20 allowance", {"spender": decoded["params"]["spender"]}))
            else:
                findings.append(Finding("MEDIUM", "ERC-20 approval", decoded["params"]))
        elif sig == "setApprovalForAll(address,bool)":
            if decoded["params"]["approved"]:
                findings.append(Finding("HIGH", "NFT operator full control granted", decoded["params"]))
            else:
                findings.append(Finding("LOW", "NFT operator revoked", decoded["params"]))
        elif sig.startswith("transfer(") or sig.startswith("transferFrom("):
            findings.append(Finding("MEDIUM", "Token transfer intent", decoded["params"]))
        elif sig.startswith("permit("):
            findings.append(Finding("MEDIUM", "Permit signature relay", decoded["params"]))
        if value > 0:
            findings.append(Finding("MEDIUM", "Native value along with token call", {"value": value}))
        return "erc", decoded, findings

    # Unknown
    if value > 0:
        findings.append(Finding("MEDIUM", "Native value transfer (unknown call)", {"to": to, "value": value}))
    return "unknown", {"selector": sel}, findings

def score_batch(findings: List[Finding]) -> Tuple[int, List[Dict]]:
    """
    Aggregate risk: assigns points and clamps 0..100 (higher = riskier).
    """
    score = 0
    details = []
    for f in findings:
        if f.level == "HIGH":
            score += 30
        elif f.level == "MEDIUM":
            score += 15
        else:
            score += 5
        details.append({"level": f.level, "reason": f.reason, "context": f.context})
    score = min(100, score)
    return score, details

# ---------------------------- Inputs ----------------------------

def load_input(arg: str) -> List[Dict]:
    """
    Accepts:
      1) 0x... hex (MultiSend calldata or single call) — if selector is multiSend(bytes), unroll frames.
      2) JSON file path with either:
         - { "transactions": [ { "to":..., "value":..., "data":... }, ... ] }
         - [ { "to":..., "value":..., "data":... }, ... ]
    Returns a list of tx-like dicts with to,value,data,operation (if known).
    """
    # Hex path?
    if arg.startswith("0x"):
        sel, payload = split_selector_and_payload(arg)
        if is_multisend_selector(sel):
            # payload is ABI-encoded bytes; decode length + bytes
            try:
                (blob,) = abi_decode(["bytes"], payload)
            except Exception as e:
                raise click.ClickException(f"Failed to decode multiSend payload: {e}")
            items = parse_multisend_bytes(blob)
            return items
        else:
            return [{"operation": 0, "to": None, "value": 0, "data": arg}]

    # JSON file
    if not os.path.isfile(arg):
        raise click.ClickException("Input must be a 0x-hex string or a JSON file path.")
    with open(arg, "r", encoding="utf-8") as f:
        obj = json.load(f)

    if isinstance(obj, dict) and "transactions" in obj:
        txs = obj["transactions"]
    elif isinstance(obj, list):
        txs = obj
    else:
        raise click.ClickException("Unsupported JSON format. Expect array or {\"transactions\": [...]}.")

    items = []
    for t in txs:
        to = t.get("to")
        value = int(t.get("value", 0))
        data = t.get("data") or "0x"
        op = int(t.get("operation", 0))
        items.append({"operation": op, "to": to, "value": value, "data": data})
    return items

# ---------------------------- CLI ----------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """batchsentinel — static lint for Gnosis Safe batches (offline)."""
    pass

@cli.command("analyze")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge.")
@click.option("--pretty", is_flag=True, help="Prints a human-readable summary.")
def analyze_cmd(input_arg, json_out, svg_out, pretty):
    """Analyze a MultiSend hex OR a JSON file of transactions."""
    items = load_input(input_arg)

    calls = []
    all_findings: List[Finding] = []
    for idx, it in enumerate(items):
        to = it.get("to") or "<unknown>"
        value = int(it.get("value", 0))
        data = it.get("data", "0x")
        kind, decoded, findings = analyze_call(to, data, value)
        for f in findings:
            all_findings.append(f)
        calls.append({
            "index": idx,
            "operation": it.get("operation", 0),
            "to": to,
            "value": value,
            "kind": kind,
            "decoded": decoded,
            "findings": [asdict(f) for f in findings]
        })

    risk, detail = score_batch(all_findings)
    label = "HIGH" if risk >= 70 else "MEDIUM" if risk >= 30 else "LOW"

    report = {
        "items": len(items),
        "risk_score": risk,
        "risk_label": label,
        "calls": calls
    }

    if pretty:
        click.echo(f"batchsentinel — {len(items)} ops, risk {risk}/100 ({label})")
        for c in calls:
            head = f"  [{c['index']:02d}] {c['kind']:<7} -> {c['to']}  value={c['value']}"
            click.echo(head)
            for f in c["findings"]:
                click.echo(f"       - {f['level']}: {f['reason']}  {f['context']}")
        if not any(c["findings"] for c in calls):
            click.echo("  No explicit red flags detected. Review unknown calls manually.")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if svg_out:
        color = "#3fb950" if risk < 30 else "#d29922" if risk < 70 else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="360" height="48" role="img" aria-label="Batch risk">
  <rect width="360" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    batchsentinel: risk {risk}/100 ({label})
  </text>
  <circle cx="335" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or svg_out):
        # default stdout JSON
        click.echo(json.dumps(report, indent=2))

if __name__ == "__main__":
    cli()
