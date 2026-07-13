# Obsidian Second Brain integration

The normative document identity, lifecycle, API and deployment rules are in
[Document corpus contract v1](document-contract-v1.md). Security controls and
test gates are in the [Obsidian bridge threat model](obsidian-threat-model.md).

Status: planned architecture; not implemented or enabled by default.

[Obsidian Second Brain](https://github.com/NestDevLab/obsidian-second-brain) is an
optional Agent Memory Fabric (AMF) client. It remains usable as a standalone
human workspace while gaining document ingestion, contextual search, memory
proposals, and selected PAM projections when connected to AMF.

## Component boundaries

```mermaid
flowchart LR
    subgraph OBSIDIAN["OBSIDIAN SECOND BRAIN"]
        VAULT["Vault Files"]
        BRIDGE["Backend Adapter"]
        VAULT <--> BRIDGE
    end

    subgraph CLIENTS["OTHER AMF CLIENTS"]
        AGENTS["Codex · Claude<br/>OpenClaw · Hermes"]
    end

    subgraph AMF["AGENT MEMORY FABRIC"]
        API["REST / MCP API"]
        DOCS["Document Service"]
        MEMORY["Memory Service"]
        SEARCH["Search Service"]
        DBPORT["Database Port"]

        API --> DOCS
        API --> MEMORY
        API --> SEARCH
        DOCS --> DBPORT
        MEMORY --> DBPORT
    end

    subgraph PAM["PORTABLE AGENT MEMORY"]
        PAMFILES["Curated Memory Files"]
    end

    subgraph DATABASE["DATABASE BACKEND — SELECT ONE"]
        SQLITE["SQLite"]
        POSTGRES["PostgreSQL"]
    end

    subgraph STORAGE["CONTENT STORAGE"]
        OBJECTS["Encrypted Files<br/>or Object Store"]
    end

    subgraph ENGINES["OPTIONAL RETRIEVAL ENGINES"]
        FULLTEXT["Full-text"]
        VECTOR["Vectors"]
        GRAPH["Graph"]
        MODELS["Local or Cloud Models"]
    end

    BRIDGE -->|"Direct standalone mode"| SQLITE
    BRIDGE -->|"AMF mode"| API
    API -->|"Selected projections"| BRIDGE
    AGENTS --> API

    DBPORT -->|"Choose one"| SQLITE
    DBPORT -->|"Choose one"| POSTGRES
    DOCS --> OBJECTS
    MEMORY <--> PAMFILES
    DOCS --> SEARCH
    PAMFILES --> SEARCH
    SEARCH --> FULLTEXT
    SEARCH --> VECTOR
    SEARCH --> GRAPH
    VECTOR --> MODELS

    classDef obsidian fill:#dbeafe,stroke:#2563eb,color:#172554,stroke-width:3px;
    classDef client fill:#e0f2fe,stroke:#0284c7,color:#082f49,stroke-width:2px;
    classDef amf fill:#ffedd5,stroke:#ea580c,color:#431407,stroke-width:3px;
    classDef pam fill:#dcfce7,stroke:#16a34a,color:#052e16,stroke-width:3px;
    classDef database fill:#fef3c7,stroke:#d97706,color:#451a03,stroke-width:2px;
    classDef storage fill:#f1f5f9,stroke:#64748b,color:#0f172a,stroke-width:2px;
    classDef engine fill:#ede9fe,stroke:#7c3aed,color:#2e1065,stroke-width:2px;

    class VAULT,BRIDGE obsidian;
    class AGENTS client;
    class API,DOCS,MEMORY,SEARCH,DBPORT amf;
    class PAMFILES pam;
    class SQLITE,POSTGRES database;
    class OBJECTS storage;
    class FULLTEXT,VECTOR,GRAPH,MODELS engine;
```

The product boundaries are intentional:

- **Obsidian Second Brain** owns the vault, editorial experience, and client
  adapter. It can use SQLite directly or connect to AMF like any other client.
- **AMF** owns the API, document corpus, memory orchestration, contextual search,
  health, and swappable backend contracts.
- **PAM** is the current canonical-memory implementation. It owns curated memory
  records, not Obsidian documents or RAW transcripts.
- **SQLite/PostgreSQL** implement the data-store contract. They catalog content
  and structured state; they do not become part of Markdown or RAW files.
- **Full-text, vector, and graph engines** are derived, rebuildable retrieval
  layers rather than canonical memory.

## Backend selection

Each steady-state deployment selects one active data path:

| Profile | Data path | Intended use |
|---|---|---|
| Simple | Obsidian → SQLite | Standalone and single-user |
| Local AMF | Obsidian → AMF → SQLite | Full local AMF behavior |
| Shared AMF | Obsidian → AMF → PostgreSQL | Shared and multi-agent |

The SQLite adapter may be reused by the direct provider and AMF, but independent
writers must never own the same database file concurrently. A durable outbox is
a delivery queue, not a second memory database. `shadow` is the only temporary
dual-path mode: the direct provider remains authoritative while AMF produces
diagnostic comparison evidence.

An AMF deployment does not require a second Obsidian-specific SQLite index. If
AMF is unavailable, the client can still use vault files, native search, existing
projections, and its outbox. An additional offline vector cache can be offered as
an explicit optional capability.

## Memory and knowledge layers

```mermaid
flowchart BT
    L0["L0 · SOURCE CONTENT<br/>Obsidian files · Attachments · RAW · Transcripts"]
    L1["L1 · STRUCTURED CATALOG<br/>Identity · Revisions · Checksums · Audit"]
    L2["L2 · CURATED MEMORY<br/>PAM claims · Provenance · Lifecycle"]
    L3["L3 · RETRIEVAL INDEXES<br/>Full-text · Vectors · Graph"]
    L4["L4 · ACCESS AND CONTEXT<br/>AMF REST / MCP · Ranking · Recall"]

    L0 -->|"Catalog metadata"| L1
    L0 -->|"Propose and curate"| L2
    L1 -->|"Build indexes"| L3
    L2 -->|"Build indexes"| L3
    L3 -->|"Retrieve candidates"| L4
    L2 -->|"Read canonical memory"| L4

    DB["SQLite or PostgreSQL"] -.-> L1
    PAMSTORE["PAM"] -.-> L2
    RETRIEVAL["Swappable Engines"] -.-> L3
    AMFACCESS["AMF"] -.-> L4

    classDef source fill:#dbeafe,stroke:#2563eb,color:#172554,stroke-width:3px;
    classDef catalog fill:#fef3c7,stroke:#d97706,color:#451a03,stroke-width:3px;
    classDef memory fill:#dcfce7,stroke:#16a34a,color:#052e16,stroke-width:3px;
    classDef retrieval fill:#ede9fe,stroke:#7c3aed,color:#2e1065,stroke-width:3px;
    classDef access fill:#ffedd5,stroke:#ea580c,color:#431407,stroke-width:3px;
    classDef label fill:#ffffff,stroke:#64748b,color:#0f172a,stroke-width:1px;

    class L0 source;
    class L1 catalog;
    class L2 memory;
    class L3 retrieval;
    class L4 access;
    class DB,PAMSTORE,RETRIEVAL,AMFACCESS label;
```

The layers separate authority from retrieval complexity:

1. L0 keeps source content in its native form.
2. L1 catalogs identity, revisions, checksums, cursors, and audit state.
3. L2 contains curated, lifecycle-aware canonical memory in PAM.
4. L3 provides replaceable full-text, vector, and graph indexes.
5. L4 exposes contextual retrieval to every client through AMF.

A database may physically host both catalog tables and derived indexes, but the
logical roles remain separate. Vector search is more sophisticated retrieval,
not more authoritative memory.

## Integration modes

- `standalone`: direct SQLite provider; no AMF service dependency.
- `shadow`: standalone behavior remains visible while AMF ingest and queries are
  compared diagnostically.
- `active`: AMF document ingestion, contextual search, memory proposals, and
  selected PAM projections are enabled.

Obsidian content remains editorial source material. Indexing a document does not
make every sentence canonical memory. Promotion still goes through an explicit
proposal and the normal AMF curation lifecycle.

## 0.6 rollout gate

1. Back up the catalog and encrypted RAW store, then build the reviewed merge
   commit as `agent-memory-fabric:0.6.0`.
2. Select exactly one document backend. Shared deployments set
   `AMF_DOCUMENT_BACKEND=postgresql` and reuse the least-privilege catalog URL;
   local deployments use a distinct SQLite path.
3. Start with Mem0 disabled and a synthetic vault in `shadow`. Require healthy
   document-store status, idempotent retry, tombstone replay, bounded snippets,
   cross-vault denial, and zero plaintext in logs.
4. Enable a real vault only after the client outbox is empty and the selected
   vault ID is present in the actor ACL. Vault paths and tokens remain external
   configuration, never repository defaults.
5. Roll back by stopping document delivery and restoring the prior image. Keep
   the client outbox and additive document tables for reconciliation; do not
   delete or rewrite source notes.
