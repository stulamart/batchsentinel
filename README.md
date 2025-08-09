# batchsentinel — static lint for multisig batches (offline)

**batchsentinel** is a zero-RPC CLI that inspects **Gnosis Safe** batches
(MultiSend calldata or JSON exports) and flags risky changes before you sign:
owner/threshold changes, module/guard tweaks, approvals with infinite allowance,
`setApprovalForAll(true)`, raw value transfers, and unknown calls.

> Paste a 0x batch or point to a JSON file. Get a risk score and a readable diff of what's inside.

## Why this is useful

Phishing kits and rushed governance flows often hide dangerous actions inside a
"harmless-looking" multisend. This tool statically expands the batch and explains
each call in plain English — offline — so reviewers can catch problems early.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
