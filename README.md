# boundary-lifecycle-agent

An autonomous lifecycle scanner for agent boundaries.

Most agent safety checks inspect one surface: secrets, approvals, tool calls, receipts, or rollback. Real failures travel across the whole pathway. Untrusted input becomes admitted intent. Intent borrows authority. Authority becomes actuation. Actuation either leaves evidence and recovery, or it disappears into vibes.

`boundary-lifecycle-agent` maps that pathway.

## What It Does

The scanner reads a target repo or workspace without executing its tools. It looks for evidence across this lifecycle:

```text
input -> admission -> authority -> actuation -> receipt -> verification -> recovery -> retention
```

It writes:

```text
output/boundary-map.json
output/boundary-docket.md
output/gaps.md
output/lifecycle-ledger.jsonl
```

The ledger is hash-linked. Hidden credential files are skipped, and ordinary repo files are only reported by path and category. If a credential-like value appears in normal text, the authority boundary is marked `collapsed`, because the reasoning surface and the secret surface have become the same surface.

Authority checks now include an approval-budget pass. Generic phrases like `approval required` are treated as thin unless the repo names action classes such as `exact-call-human`, `typed-policy-auto`, `sandboxed-auto`, `break-glass-shell`, or `denied`, and also names an enforcement owner such as a wrapper, sandbox, gateway, firewall, or policy engine.

## Try It

```bash
python3 tools/boundary_lifecycle.py samples/good-lifecycle --out output/good --now 2026-05-05T00:00:00Z
python3 tools/boundary_lifecycle.py samples/generic-approval --out output/generic-approval --now 2026-05-05T00:00:00Z
python3 tools/boundary_lifecycle.py samples/missing-verification --out output/missing-verification --now 2026-05-05T00:00:00Z
python3 tools/boundary_lifecycle.py samples/stale-approval --out output/stale-approval --now 2026-05-05T00:00:00Z
python3 tools/boundary_lifecycle.py samples/collapsed-credential --out output/collapsed-credential --now 2026-05-05T00:00:00Z
```

Scan another agent:

```bash
python3 tools/boundary_lifecycle.py /path/to/agent --out output/scan
```

## Fixtures

- `samples/good-lifecycle` has input, policy admission, authority, actuation, receipt, verification, recovery, and retention signals.
- `samples/generic-approval` says approval is required but does not name an action-class budget, so authority is marked thin.
- `samples/missing-verification` acts and receipts but has no independent post-action check.
- `samples/manual-recovery-needed` has recovery evidence that explicitly names manual drills still needed, so recovery is marked thin.
- `samples/stale-approval` contains an expired approval artifact.
- `samples/collapsed-credential` contains a credential-like value inside ordinary tool text.

## Why This Exists

A boundary is not a single wall. It is a lifecycle. The important question is not "does this repo have a policy file?" The important question is whether every consequential pathway has admission, scoped authority, durable evidence, verification, recovery, and retention.

The scanner is intentionally conservative. It uses deterministic keyword evidence and produces a docket for human review. It is not a proof system. It is a map of where to look before an autonomous agent is trusted with real authority.

## Run As A Loop

This is built on `brain-loop`. Edit `config.sh`, then:

```bash
chmod +x brain-loop.sh
./brain-loop.sh
```

Drop repos, manifests, or scan notes into `context/`. The deterministic scanner can also be run directly from cron or CI.

## License

MIT
