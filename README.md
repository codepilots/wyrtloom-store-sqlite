# wyrtloom-store-sqlite

A SQLite-backed implementation of the
[`wyrtloom_core::persistence::PersistenceProvider`](../wyrtloom/crates/core/src/persistence.rs)
contract — a storage-agnostic document/collection store. Part of the Wyrtloom
dashboard ecosystem.

## Model

- A **collection** is a SQLite table of `id TEXT PRIMARY KEY, doc TEXT (JSON)`.
- A **record** is a string id plus an opaque `serde_json::Value` document.
- Each declared **indexed field** gets a secondary index over
  `json_extract(doc, '$.<field>')`, and is the only field queryable via
  `Query::ByField`.
- Declared collections (and their indexed-field allow-list) are persisted in a
  `__wyrtloom_collections` catalog and reloaded on `open`, so a disk-backed store
  exposes its collections after a restart without re-declaring them.

## Usage

```rust
use wyrtloom_core::persistence::{CollectionSpec, PersistenceProvider, Query, Record};
use wyrtloom_store_sqlite::SqliteStore;
use serde_json::json;

let store = SqliteStore::open("data/app.db")?; // or SqliteStore::in_memory()?

store.ensure_collection(&CollectionSpec {
    name: "users".into(),
    indexed_fields: vec!["username".into(), "role".into()],
})?;

store.put("users", Record { id: "u1".into(), doc: json!({"username": "alice", "role": "admin"}) })?;

let admins = store.query("users", &Query::ByField {
    field: "role".into(),
    value: json!("admin"),
})?;
```

## Security

Collection names and `Query::ByField` fields are SQL **identifiers** and cannot
be parameterized, so the store:

- validates every identifier with `is_valid_identifier` before it touches SQL
  (`InvalidIdentifier` otherwise);
- allow-lists `Query::ByField` fields against the collection's declared
  `indexed_fields` (`FieldNotIndexed` otherwise) — this also blocks
  full-table-scan DoS on un-indexed fields;
- builds the `json_extract` path only from an already-validated flat top-level
  key;
- always binds document **values** via `?n`, never interpolating them;
- enables WAL + a `busy_timeout` on open for safe two-process access;
- rejects `..` path traversal on real database paths;
- surfaces malformed JSON rows as `Storage` integrity errors, never panics.

## License

Apache-2.0. See [LICENSE](LICENSE).
