# Architecture

RAGFort uses zero trust and defense in depth: all input, documents, context, and output are untrusted. The browser communicates only with the API; privileged data and model calls are server-side. Security enforcement is deterministic; detection is evidence-producing and may invoke a configured block, never authorization.

## High-level architecture

```mermaid
flowchart TD
    U[User] --> F[Next.js Frontend]
    F -->|HTTPS| A[FastAPI API]
    A --> I[Identity]
    I --> Q[Query Guard]
    Q --> P[Policy Engine]
    P --> R[Secure Retriever]
    R --> C[Context Firewall]
    C --> L[LLM]
    L --> O[Output Firewall]
    O --> U
    Q --> E[Security Event Bus]
    P --> E
    R --> E
    C --> E
    O --> E
    E --> DB[(PostgreSQL)]
    DB --> D[Security Dashboard]
    R --> V[(Qdrant)]
```

## Trust boundaries

```mermaid
flowchart LR
  U[User/device] -->|TB1: untrusted browser input| F[Frontend]
  F -->|TB2: authenticated HTTPS| A[API]
  A -->|TB3: validated claims/policy| P[Policy]
  P -->|TB4: authorized filters| V[Vector DB]
  V -->|TB5: untrusted retrieved data| C[Context Firewall]
  C -->|TB6: fixed policy + bounded context| L[LLM]
  L -->|TB7: untrusted generated output| O[Output Firewall]
  O --> U
  X[Document upload] -->|TB8: hostile file/content| G[Ingestion security]
  G --> V
```

## Query lifecycle

```mermaid
flowchart LR
  A[Authenticated request] --> Q[Query Guard]
  Q -->|block| B[Block + event]
  Q -->|allow/review policy| P[RBAC + ABAC]
  P -->|deny| D[Deny + audit]
  P -->|allow| R[Scoped retrieval]
  R --> C[Context firewall]
  C --> L[LLM]
  L --> O[Output firewall]
  O -->|allow/redact| S[Safe answer]
  O -->|block/failure| H[Withhold + event]
```

## Secure document lifecycle (Phase 3 design)

```mermaid
flowchart TD
  U[Upload] --> V[File validation]
  V --> X[Content extraction + normalization]
  X --> H[Hidden-content check]
  H --> S[Injection + PII/secret scans]
  S --> I[Provenance + SHA-256]
  I --> C[Classification + ACL metadata]
  C --> A[Approval]
  A -->|approved| E[Chunking + embedding]
  E --> Q[(Approved Qdrant index)]
  V -->|failure| Z[Quarantine]
  S -->|suspicious| Z
  I -->|mismatch| Z
```

## Service connection model

```mermaid
flowchart LR
  B[Browser] --> N[Next.js]
  N -->|authenticated API only| A[FastAPI]
  A --> P[(PostgreSQL)]
  A --> Q[(Qdrant)]
  A --> M[LLM provider]
  A --> S[Internal security services]
  B -. no direct access .-> P
  B -. no direct access .-> Q
  B -. no direct access .-> M
```

## Event flow and roadmap

```mermaid
flowchart LR
  G[Security stage] --> E[Versioned event]
  E --> O[Durable event/audit store]
  O --> M[Metrics + alerting]
  O --> D[Authorized dashboard]
```

```mermaid
flowchart LR
  P1[1 Architecture] --> P2[2 Baseline RAG] --> P3[3 Secure Ingestion] --> P4[4 Identity + Retrieval] --> P5[5 Detection] --> P6[6 Output + Monitoring] --> P7[7 Red team] --> P8[8 Production hardening]
```

## Failure policy

Auth, authorization, policy, malformed ACL/tenant, integrity, context security, output security, and security-event persistence fail closed (deny/quarantine/withhold). Vector or LLM outage returns a generic safe availability error—never an ungoverned model-only fallback. `/health/live` is process-only; readiness is minimal and internal/protected in production.
