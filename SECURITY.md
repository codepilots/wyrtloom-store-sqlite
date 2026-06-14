# Security model — `wyrtloom-store-sqlite`

This crate is a SQLite-backed implementation of the `wyrtloom_core::persistence::PersistenceProvider`
trait: a storage-agnostic document/collection store. Each collection is a SQLite table of
`id TEXT PRIMARY KEY, doc TEXT (JSON)`, and each declared indexed field gets a secondary index over
`json_extract(doc, '$.<field>')`. Collection specs are persisted in a metadata catalog
(`__wyrtloom_collections`) so collections survive a reopen.

All line references below are to `src/lib.rs` unless otherwise noted.

---

## Threat model & scope

**What this store defends against.** The store builds SQL dynamically because some inputs are SQL
*identifiers* (table names, index names, JSON path keys) that **cannot be parameterized** by the SQLite
driver. The central threat is therefore **SQL injection via identifier interpolation** — a hostile or
buggy caller supplying a collection name, indexed-field name, or `Query::ByField` field designed to
break out of the `"..."`-quoted identifier and inject arbitrary SQL (e.g. `u"; DROP TABLE x--`). A
secondary threat is **denial of service** via unbounded or full-table-scan reads.

**What is in scope:**
- Untrusted/semi-trusted callers feeding collection names, field names, document IDs, and document
  values into the trait methods.
- A previously-written, possibly-corrupted on-disk database and catalog (rows that no longer parse,
  malformed `indexed_fields` JSON, malformed document JSON).
- Concurrent access from another process over the same database file.

**What is explicitly out of scope (caller's responsibility):**
- **The database file path.** `SqliteStore::open` runs `validate_db_path`, which is a `..`-traversal
  *screen*, not a confinement boundary — absolute paths and symlinks pass. The path must be
  operator-trusted (see Gotchas).
- **At-rest confidentiality.** There is no encryption layer; OS file permissions are the only
  boundary protecting stored documents.
- **The contents of documents.** This store is *not* an encryption or validation boundary for the
  data consumers put in it; it stores documents verbatim (see Secrets).
- **Bounding result-set size.** `Query::All` returns the whole collection; consumers must paginate
  large collections.

---

## Security mechanisms

### 1. Identifier validation on every code path (the central control)

Every value that reaches SQL as an *identifier* — collection name, declared indexed-field name,
`Query::ByField.field` — is validated with `wyrtloom_core::persistence::is_valid_identifier` before it
is interpolated. `is_valid_identifier` (in `wyrtloom/crates/core/src/persistence.rs`) accepts only
`[a-z][a-z0-9_]*` with length 1–64: the first character must be ASCII-lowercase, the rest lowercase /
digit / underscore. This rules out quotes, semicolons, dots, whitespace, `$`, and every other
SQL-significant character, so a validated identifier cannot break out of its `"..."` quoting.

Validation is applied on **every** entry point, not just the write path:

- `checked_collection` validates the collection name and is called first in `put`, `get`, `query`,
  and `delete` (lines 121–127, called at 168, 224, 241, 269, 339).
- `ensure_collection` validates the collection name *and* every declared indexed field **before any
  SQL runs**, so a single malicious field name aborts the whole operation with no partial schema
  (lines 168–176).
- `query` re-validates `Query::ByField.field` even though it is also allow-listed (lines 284–286).
- **The persisted-catalog reload (`load_specs`) re-validates on `open`** (lines 113–115). Identifiers
  read back from `__wyrtloom_collections` are *not* trusted just because they were once written; a
  catalog row whose name or fields no longer validate is skipped rather than fed into later SQL.

### 2. `ByField.field` allow-listed against declared `indexed_fields` (defense in depth)

Beyond passing `is_valid_identifier`, a `Query::ByField` field must also be one of the collection's
**declared** indexed fields, checked against the in-memory `specs` allow-list (lines 287–289,
returning `StoreError::FieldNotIndexed`). This:

- adds a second, independent gate so that even a hypothetical validation gap could not reach an
  arbitrary field; and
- **prevents full-table-scan DoS** — only fields with a backing `json_extract` index can be queried,
  so a `ByField` query always hits an index instead of scanning the whole collection.

The allow-list is populated by `ensure_collection` (line 219) and rebuilt from the catalog on reopen
by `load_specs` (line 114), so the same constraint holds across a process restart (test
`collections_survive_reopen`, line 698–709).

### 3. All values are bound, never interpolated

Document IDs and `ByField` query values are **always bound** via positional parameters (`?1`, `?n`),
never formatted into the SQL string:

- `put` binds `id` and the serialized `doc` (lines 232–235).
- `get` / `delete` bind `id` (lines 247–249, 344–347).
- `query` builds a `Vec<rusqlite::types::Value>` and binds it via `params_from_iter` (lines 275–321).
- The catalog insert binds `name` and `fields_json` (lines 211–216).

`json_value_to_sql` (lines 142–164) maps a scalar JSON value to the native SQLite type that
`json_extract` yields, so the bound needle compares like-for-like; objects/arrays are rejected rather
than coerced. Test `malicious_value_is_stored_literally_not_executed` (line 580) confirms a
`'); DROP TABLE users;--` *value* round-trips verbatim and is never executed.

### 4. JSON path built only from a validated flat key

The index expression and `ByField` predicate use `json_extract(doc, '$.<field>')` where `<field>` is an
already-validated identifier (lines 199–202, 300–309). Because `is_valid_identifier` forbids quotes,
dots, and `$`, the field is a single flat top-level key and cannot express a nested path or break out
of the JSON-path string.

### 5. Collision-free index names

SQLite index names are global within a database. Since both collection name and field are
`[a-z0-9_]` (and `_` is a legal interior char), a naive `idx_{name}_{field}` would let distinct pairs
collide — e.g. `(a_b, c)` and `(a, b_c)` both yield `idx_a_b_c`. The store instead uses a
**length-prefixed encoding**, `idx_{name.len()}_{name}_{field}` (line 198), making the split point
unambiguous so distinct `(name, field)` pairs always get distinct index names. Test
`index_names_do_not_collide_across_collections` (line 757) verifies both indexes physically exist.

### 6. Integrity: fail loud, never panic or silently coerce

- A malformed document row → `StoreError::Storage("integrity error: malformed JSON document")` in
  both `get` (lines 256–258) and `query` (lines 330–332), never a panic or a silently-dropped row.
  Test `malformed_json_row_is_integrity_error_not_panic` (line 606).
- A **corrupt catalog `indexed_fields` value** is *not* silently coerced to an empty allow-list:
  `load_specs` returns an integrity `StoreError` (lines 108–112). Silently emptying it would let a
  previously-valid `ByField` query start returning `FieldNotIndexed` after a reopen — failing loud is
  the safer choice. Test `malformed_catalog_indexed_fields_surfaces_on_reopen` (line 718).
- Mutex poisoning (a thread panicked while holding a lock) is mapped to
  `StoreError::Storage("lock poisoned")` by the `lock` helper (lines 37–40) rather than cascading the
  panic to every later caller.

### 7. Concurrency

`open` sets `PRAGMA journal_mode=WAL` and `PRAGMA busy_timeout=5000` (lines 53–55) so two processes
can safely share the database file: WAL allows concurrent readers with a writer, and the busy timeout
makes a contended write wait rather than fail immediately.

---

## Key decisions & rationale

- **Identifiers are validated, not escaped.** Rather than try to safely quote arbitrary identifiers,
  the store restricts identifiers to a conservative `[a-z][a-z0-9_]{0,63}` grammar. This is a far
  smaller, easier-to-audit trust surface than escaping, and it is enforced uniformly at every entry
  point including catalog reload.
- **Allow-list on top of validation for `ByField`.** Validation alone would prevent injection;
  layering the declared-field allow-list adds defense in depth *and* doubles as a DoS guard by
  forcing every field query onto an index.
- **Catalog reload is treated as untrusted input.** On-disk catalog rows get the same identifier
  validation as fresh API input, so tampering with the database file cannot smuggle a bad identifier
  back into the live SQL path.
- **Corrupt catalog fields fail loud.** Choosing an integrity error over a silent empty allow-list
  trades availability for a fail-safe, observable failure that does not silently change query
  semantics.
- **Values always bound.** Keeping every value on the parameter path means document content — which
  is fully attacker-controlled in many deployments — can never influence SQL structure.

---

## Gotchas / watch-outs

- **`validate_db_path` is a traversal screen, not confinement.** It only rejects path components
  equal to `..` (see `wyrtloom/crates/core/src/storage.rs`). **Absolute paths and symlinks pass.**
  The DB path must be supplied by trusted configuration/operator input, never derived from untrusted
  request data. Do not rely on this function to sandbox the store to a directory.
- **Unbounded reads are a DoS surface.** `Query::All` materializes the *entire* collection into a
  `Vec<Record>` (line 276, 326–335). Consumers should bound or paginate queries over large
  collections. The store does not impose any row-count limit.
- **Document size is unbounded.** A document is serialized and stored as-is; there is no size cap, so
  a single oversized document can consume memory/disk. Bound document size at the consumer if inputs
  are untrusted.
- **No encryption at rest.** Documents (and the catalog) are stored as plaintext JSON in the SQLite
  file. The only confidentiality boundary is OS file permissions on the database file and its
  `-wal` / `-shm` sidecars. Set restrictive permissions and place the file on appropriately
  protected storage.
- **The store is not an encryption boundary.** It holds whatever consumers put in it verbatim — e.g.
  argon2 password hashes from `wyrtloom-users`, or public-key-only client records from
  `wyrtloom-clientauth-tofu`. Hashing/encryption of sensitive material is the *consumer's*
  responsibility; this crate neither adds nor assumes any cryptographic protection of document
  contents.
