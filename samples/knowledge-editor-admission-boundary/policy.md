# Editorial Boundary Policy

- input: new notes arrive in `context/`.
- admission: `output/admission-ledger.jsonl` records an intake receipt for every source item.
- authority: exact-call-human approval is required before publishing edited source notes.
- enforced_by: tools/knowledge_editor.py
- recovery: rejected or quarantined source items can be restored from the intake receipt.
- retention: accepted evidence is retained in `knowledge/`.
