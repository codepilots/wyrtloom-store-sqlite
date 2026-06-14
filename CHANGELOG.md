# Changelog

All notable changes to `wyrtloom-store-sqlite` are documented here.

## [0.1.0] - 2026-06-14

Initial release: a SQLite-backed implementation of the
`wyrtloom_core::persistence::PersistenceProvider` contract.

### Added
- `SqliteStore` with `open(path)`, `in_memory()`, WAL + `busy_timeout=5000`
  enabled on open for safe two-process access.
- One table per collection (`id TEXT PRIMARY KEY, doc TEXT (JSON)`); declared
  indexed fields get an index over `json_extract(doc, '$.<field>')`.
- `ensure_collection`, `put`, `get`, `query` (`All` / `ById` / `ByField`),
  `delete`.
- A persistent `__wyrtloom_collections` catalog so declared collections and
  their indexed-field allow-list survive reopening a disk-backed database
  (the catalog is reloaded on `open`, with each entry re-validated).

### Fixed (pre-release review)
- Index names are now disambiguated (`idx_<namelen>_<name>_<field>`) so distinct
  collection/field pairs that share characters around `_` (e.g. `(a_b, c)` vs
  `(a, b_c)`) no longer collide on SQLite's global index namespace and silently
  skip an index.
- `Query::ByField` with a JSON-null value now uses `IS NULL` (rather than the
  never-true `= NULL`), matching records whose field is null or absent.

### Security
- All collection names and `Query::ByField` fields are validated as SQL
  identifiers via `is_valid_identifier` before being used in SQL; invalid ones
  are rejected with `InvalidIdentifier`.
- `Query::ByField` fields are additionally allow-listed against the collection's
  declared `indexed_fields` (`FieldNotIndexed` otherwise), preventing both
  identifier injection and full-table-scan DoS.
- The `json_extract` path is built only from an already-validated flat
  top-level key. Document values are always bound via `?n`, never interpolated.
- Real database paths are checked for `..` traversal via `validate_db_path`.
- Malformed JSON rows surface as `Storage` integrity errors, never a panic.
