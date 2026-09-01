# UI / UX Architecture

The UI is a calm enterprise application: warm neutral surfaces, readable serif page headings, restrained sans-serif controls, thin borders, visible focus states, and plain-English security explanations. It follows the requested RAGFort navigation rather than exposing implementation internals.

```text
RAGFort
  Ask
  Documents
  Security
  Activity
  Tests
  ─────────
  Settings
```

## Core experiences

```text
Ask your knowledge base
[ What would you like to know?                    ]
                 [ Ask securely → ]
✓ Access permissions and security policies are applied automatically.
```

An answer shows question, grounded answer, sources, and `✓ Security checks passed`; a disclosure reveals identity, access, documents, context, sensitive-data, and output outcomes. Authorized technical details can show redacted signals, request/event IDs, policy decisions, chunk IDs/hashes, trace, and latency—not raw rules or prompts.

Blocked state: `BLOCKED — This request appears to attempt to override application security rules. No protected information was accessed.` It includes risk/action and confirms retrieval/LLM were not called when true. Documents consistently use **SAFE**, **REVIEW**, **BLOCKED**, and **QUARANTINED**, with icon and text rather than color alone. The Security page has four meaningful KPIs, one trend, one attack breakdown, and recent events; Tests shows only actual run evidence.

## Interaction quality

Keyboard-operable navigation, semantic landmarks, labels, live-status announcements, high contrast, and clear empty/loading/error/unauthorized/safe-unavailable states are mandatory. Desktop uses a compact sidebar; tablet collapses it; mobile uses a menu drawer, stacked cards, and horizontally scrollable tables. The browser only calls authenticated FastAPI APIs—never PostgreSQL, Qdrant, embedding services, LLMs, or security services.
