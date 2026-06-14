//! SQLite-backed [`PersistenceProvider`] — a storage-agnostic document/collection store.
//!
//! Part of the Wyrtloom dashboard ecosystem. Each collection is a SQLite table of
//! `id TEXT PRIMARY KEY, doc TEXT (JSON)`; declared indexed fields get a secondary
//! index over `json_extract(doc, '$.<field>')`.
//!
//! # Security
//!
//! Collection names and `Query::ByField.field` are SQL **identifiers** and cannot be
//! parameterized. Every identifier is validated with
//! [`wyrtloom_core::persistence::is_valid_identifier`] before it touches SQL, and a
//! `ByField` field is additionally allow-listed against the collection's declared
//! `indexed_fields`. Document *values* are always bound via `?n`, never interpolated.
//! See `CHANGELOG.md` for the audit history.

use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};
use wyrtloom_core::persistence::{
    is_valid_identifier, CollectionSpec, PersistenceProvider, Query, Record, StoreError,
};
use wyrtloom_core::storage::validate_db_path;

/// SQLite-backed document store.
pub struct SqliteStore {
    conn: Mutex<Connection>,
    /// collection name -> declared indexed fields. Populated by `ensure_collection`
    /// and used to allow-list `Query::ByField` fields (prevents both SQL injection
    /// via identifiers and full-table-scan DoS on un-indexed fields).
    specs: Mutex<HashMap<String, Vec<String>>>,
}

/// Map a poisoned-lock error to a `StoreError` instead of panicking, so a thread
/// that panicked while holding a lock degrades into a clean error for callers
/// rather than cascading panics (mirrors the sibling clientauth crate).
fn lock<'a, T>(m: &'a Mutex<T>) -> Result<std::sync::MutexGuard<'a, T>, StoreError> {
    m.lock()
        .map_err(|_| StoreError::Storage("lock poisoned".into()))
}

impl SqliteStore {
    /// Open (or create) a store at `path`. The path is validated against traversal
    /// (`..`). Pass `":memory:"` for an in-memory store.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()
                .map_err(|_| StoreError::Storage("open in-memory failed".into()))?
        } else {
            validate_db_path(path).map_err(|e| StoreError::Storage(format!("invalid path: {e}")))?;
            Connection::open(path).map_err(|_| StoreError::Storage("open database failed".into()))?
        };
        // WAL + busy_timeout for safe two-process access.
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|_| StoreError::Storage("configure pragmas failed".into()))?;
        let store = Self {
            conn: Mutex::new(conn),
            specs: Mutex::new(HashMap::new()),
        };
        store.init_schema()?;
        store.load_specs()?;
        Ok(store)
    }

    /// Open a fresh in-memory store.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::open(":memory:")
    }

    /// Create the metadata catalog used to persist declared collection specs, so
    /// collections (and their indexed-field allow-list) survive a reopen of a
    /// disk-backed database.
    fn init_schema(&self) -> Result<(), StoreError> {
        lock(&self.conn)?
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS __wyrtloom_collections (
                name           TEXT PRIMARY KEY,
                indexed_fields TEXT NOT NULL
            );",
            )
            .map_err(|_| StoreError::Storage("init schema failed".into()))
    }

    /// Repopulate the in-memory spec allow-list from the persisted catalog so a
    /// reopened database exposes its previously declared collections without
    /// requiring `ensure_collection` to be called again.
    fn load_specs(&self) -> Result<(), StoreError> {
        let conn = lock(&self.conn)?;
        let mut stmt = conn
            .prepare("SELECT name, indexed_fields FROM __wyrtloom_collections")
            .map_err(|_| StoreError::Storage("load specs: prepare failed".into()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| StoreError::Storage("load specs: query failed".into()))?;
        let mut specs = lock(&self.specs)?;
        for row in rows {
            let (name, fields_json) =
                row.map_err(|_| StoreError::Storage("load specs: row read failed".into()))?;
            // A corrupt catalog row would otherwise poison every later operation;
            // skip names/fields that no longer validate as identifiers.
            //
            // A malformed `indexed_fields` JSON is NOT silently coerced to an empty
            // allow-list: doing so would let previously-valid `ByField` queries start
            // returning `FieldNotIndexed` after a reopen. Fail loud (integrity error),
            // consistent with the crate's other integrity-error handling.
            let fields: Vec<String> = serde_json::from_str(&fields_json).map_err(|_| {
                StoreError::Storage(format!(
                    "integrity error: malformed indexed_fields in catalog for collection {name:?}"
                ))
            })?;
            if is_valid_identifier(&name) && fields.iter().all(|f| is_valid_identifier(f)) {
                specs.insert(name, fields);
            }
        }
        Ok(())
    }

    /// Validate a collection name as a SQL identifier.
    fn checked_collection(name: &str) -> Result<&str, StoreError> {
        if is_valid_identifier(name) {
            Ok(name)
        } else {
            Err(StoreError::InvalidIdentifier(name.to_string()))
        }
    }

    /// Look up the declared indexed fields for a known collection.
    fn declared_fields(&self, collection: &str) -> Result<Vec<String>, StoreError> {
        let specs = lock(&self.specs)?;
        specs
            .get(collection)
            .cloned()
            .ok_or_else(|| StoreError::CollectionNotFound(collection.to_string()))
    }
}

/// Map a scalar JSON query value to the native SQLite type that
/// `json_extract(doc, '$.field')` would yield for the stored value, so a
/// `ByField` equality compares like-for-like.
fn json_value_to_sql(value: &serde_json::Value) -> Result<rusqlite::types::Value, StoreError> {
    use rusqlite::types::Value as V;
    use serde_json::Value as J;
    match value {
        J::String(s) => Ok(V::Text(s.clone())),
        J::Bool(b) => Ok(V::Integer(*b as i64)), // json_extract yields 0/1
        J::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(V::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(V::Real(f))
            } else {
                // u64 outside i64 range — fall back to text comparison.
                Ok(V::Text(n.to_string()))
            }
        }
        J::Null => Ok(V::Null),
        // Objects/arrays are not flat scalar fields and cannot be matched here.
        J::Object(_) | J::Array(_) => Err(StoreError::Storage(
            "ByField value must be a scalar (string/number/bool/null)".into(),
        )),
    }
}

impl PersistenceProvider for SqliteStore {
    fn ensure_collection(&self, spec: &CollectionSpec) -> Result<(), StoreError> {
        let name = Self::checked_collection(&spec.name)?;

        // Validate every declared indexed field *before* any SQL runs, so a single
        // malicious field name aborts the whole operation (no partial schema).
        for field in &spec.indexed_fields {
            if !is_valid_identifier(field) {
                return Err(StoreError::InvalidIdentifier(field.clone()));
            }
        }

        let conn = lock(&self.conn)?;

        // `name` is a validated identifier ([a-z0-9_], <=64). Safe to interpolate.
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS \"{name}\" (
                id  TEXT PRIMARY KEY,
                doc TEXT NOT NULL
            );"
        ))
        .map_err(|_| StoreError::Storage("create table failed".into()))?;

        for field in &spec.indexed_fields {
            // `field` is a validated identifier; the json path is built only from it,
            // restricted to a flat top-level key (no quotes/dots/`$`).
            //
            // SQLite index names are global within a database, so the name must be
            // unambiguous across (collection, field) pairs. Both parts are `[a-z0-9_]`,
            // where `_` is also a legal interior char, so a plain `idx_{name}_{field}`
            // would collide (e.g. `(a_b, c)` vs `(a, b_c)` → both `idx_a_b_c`). Encode
            // the collection-name length to make the split point unambiguous.
            let index_name = format!("idx_{}_{name}_{field}", name.len());
            conn.execute_batch(&format!(
                "CREATE INDEX IF NOT EXISTS \"{index_name}\" \
                 ON \"{name}\" (json_extract(doc, '$.{field}'));"
            ))
            .map_err(|_| StoreError::Storage("create index failed".into()))?;
        }

        // Persist the spec to the catalog so the collection survives a reopen, then
        // record it in the in-memory allow-list. Both happen only after the schema
        // is in place.
        let fields_json = serde_json::to_string(&spec.indexed_fields)
            .map_err(|_| StoreError::Storage("serialize spec failed".into()))?;
        conn.execute(
            "INSERT OR REPLACE INTO __wyrtloom_collections (name, indexed_fields) \
             VALUES (?1, ?2)",
            params![name, fields_json],
        )
        .map_err(|_| StoreError::Storage("persist spec failed".into()))?;
        drop(conn);

        lock(&self.specs)?.insert(name.to_string(), spec.indexed_fields.clone());
        Ok(())
    }

    fn put(&self, collection: &str, record: Record) -> Result<(), StoreError> {
        let name = Self::checked_collection(collection)?;
        // Collection must have been declared.
        self.declared_fields(name)?;

        let doc = serde_json::to_string(&record.doc)
            .map_err(|_| StoreError::Storage("serialize doc failed".into()))?;

        let conn = lock(&self.conn)?;
        conn.execute(
            &format!("INSERT OR REPLACE INTO \"{name}\" (id, doc) VALUES (?1, ?2)"),
            params![record.id, doc],
        )
        .map_err(|_| StoreError::Storage("insert failed".into()))?;
        Ok(())
    }

    fn get(&self, collection: &str, id: &str) -> Result<Record, StoreError> {
        let name = Self::checked_collection(collection)?;
        self.declared_fields(name)?;

        let conn = lock(&self.conn)?;
        let doc: Option<String> = conn
            .query_row(
                &format!("SELECT doc FROM \"{name}\" WHERE id = ?1"),
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Storage("query failed".into()))?;

        match doc {
            Some(s) => {
                let value: serde_json::Value = serde_json::from_str(&s).map_err(|_| {
                    StoreError::Storage("integrity error: malformed JSON document".into())
                })?;
                Ok(Record {
                    id: id.to_string(),
                    doc: value,
                })
            }
            None => Err(StoreError::NotFound(id.to_string())),
        }
    }

    fn query(&self, collection: &str, query: &Query) -> Result<Vec<Record>, StoreError> {
        let name = Self::checked_collection(collection)?;
        let declared = self.declared_fields(name)?;

        let conn = lock(&self.conn)?;

        // Build the statement. Identifiers are validated/allow-listed; values bound.
        let (sql, bind): (String, Vec<rusqlite::types::Value>) = match query {
            Query::All => (format!("SELECT id, doc FROM \"{name}\""), vec![]),
            Query::ById(id) => (
                format!("SELECT id, doc FROM \"{name}\" WHERE id = ?1"),
                vec![rusqlite::types::Value::Text(id.clone())],
            ),
            Query::ByField { field, value } => {
                // Defence in depth: the field must be a valid identifier AND one of
                // the collection's declared indexed fields.
                if !is_valid_identifier(field) {
                    return Err(StoreError::InvalidIdentifier(field.clone()));
                }
                if !declared.iter().any(|f| f == field) {
                    return Err(StoreError::FieldNotIndexed(field.clone()));
                }
                // `json_extract` returns a *native* SQLite scalar (text/integer/
                // real/null), so bind the value as the matching native type rather
                // than as JSON text. JSON-null is special: `= NULL` is never true in
                // SQLite's three-valued logic, so use `IS NULL` to match records
                // whose field is null (this also matches an absent key, since
                // `json_extract` of a missing key yields SQL NULL).
                let needle = json_value_to_sql(value)?;
                if matches!(needle, rusqlite::types::Value::Null) {
                    (
                        format!(
                            "SELECT id, doc FROM \"{name}\" \
                             WHERE json_extract(doc, '$.{field}') IS NULL"
                        ),
                        vec![],
                    )
                } else {
                    (
                        format!(
                            "SELECT id, doc FROM \"{name}\" \
                             WHERE json_extract(doc, '$.{field}') = ?1"
                        ),
                        vec![needle],
                    )
                }
            }
        };

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|_| StoreError::Storage("prepare failed".into()))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bind.iter()), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| StoreError::Storage("query failed".into()))?;

        let mut out = Vec::new();
        for row in rows {
            let (id, doc_str) =
                row.map_err(|_| StoreError::Storage("row read failed".into()))?;
            let value: serde_json::Value = serde_json::from_str(&doc_str).map_err(|_| {
                StoreError::Storage("integrity error: malformed JSON document".into())
            })?;
            out.push(Record { id, doc: value });
        }
        Ok(out)
    }

    fn delete(&self, collection: &str, id: &str) -> Result<(), StoreError> {
        let name = Self::checked_collection(collection)?;
        self.declared_fields(name)?;

        let conn = lock(&self.conn)?;
        // DELETE of an absent row affects 0 rows and is a no-op, as required.
        conn.execute(
            &format!("DELETE FROM \"{name}\" WHERE id = ?1"),
            params![id],
        )
        .map_err(|_| StoreError::Storage("delete failed".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store_with_users() -> SqliteStore {
        let store = SqliteStore::in_memory().unwrap();
        store
            .ensure_collection(&CollectionSpec {
                name: "users".into(),
                indexed_fields: vec!["username".into(), "role".into()],
            })
            .unwrap();
        store
    }

    fn rec(id: &str, doc: serde_json::Value) -> Record {
        Record {
            id: id.into(),
            doc,
        }
    }

    #[test]
    fn put_get_roundtrip() {
        let s = store_with_users();
        let doc = json!({"username": "alice", "role": "admin", "age": 30});
        s.put("users", rec("u1", doc.clone())).unwrap();
        let got = s.get("users", "u1").unwrap();
        assert_eq!(got.id, "u1");
        assert_eq!(got.doc, doc);
    }

    #[test]
    fn get_missing_is_not_found() {
        let s = store_with_users();
        let err = s.get("users", "nope").unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[test]
    fn put_replaces_existing() {
        let s = store_with_users();
        s.put("users", rec("u1", json!({"username": "a"}))).unwrap();
        s.put("users", rec("u1", json!({"username": "b"}))).unwrap();
        let got = s.get("users", "u1").unwrap();
        assert_eq!(got.doc, json!({"username": "b"}));
        assert_eq!(s.query("users", &Query::All).unwrap().len(), 1);
    }

    #[test]
    fn delete_removes_record() {
        let s = store_with_users();
        s.put("users", rec("u1", json!({"username": "alice"}))).unwrap();
        s.delete("users", "u1").unwrap();
        assert!(matches!(
            s.get("users", "u1").unwrap_err(),
            StoreError::NotFound(_)
        ));
    }

    #[test]
    fn delete_absent_is_noop() {
        let s = store_with_users();
        // Must not error.
        s.delete("users", "ghost").unwrap();
    }

    #[test]
    fn query_all_returns_everything() {
        let s = store_with_users();
        s.put("users", rec("u1", json!({"username": "a"}))).unwrap();
        s.put("users", rec("u2", json!({"username": "b"}))).unwrap();
        let all = s.query("users", &Query::All).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn query_by_id() {
        let s = store_with_users();
        s.put("users", rec("u1", json!({"username": "a"}))).unwrap();
        s.put("users", rec("u2", json!({"username": "b"}))).unwrap();
        let r = s.query("users", &Query::ById("u2".into())).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "u2");
    }

    #[test]
    fn query_by_indexed_field() {
        let s = store_with_users();
        s.put("users", rec("u1", json!({"username": "alice", "role": "admin"})))
            .unwrap();
        s.put("users", rec("u2", json!({"username": "bob", "role": "user"})))
            .unwrap();
        s.put("users", rec("u3", json!({"username": "carol", "role": "admin"})))
            .unwrap();

        let admins = s
            .query(
                "users",
                &Query::ByField {
                    field: "role".into(),
                    value: json!("admin"),
                },
            )
            .unwrap();
        let mut ids: Vec<_> = admins.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["u1", "u3"]);
    }

    #[test]
    fn query_by_field_numeric_value() {
        let s = SqliteStore::in_memory().unwrap();
        s.ensure_collection(&CollectionSpec {
            name: "items".into(),
            indexed_fields: vec!["qty".into()],
        })
        .unwrap();
        s.put("items", rec("a", json!({"qty": 5}))).unwrap();
        s.put("items", rec("b", json!({"qty": 7}))).unwrap();
        let r = s
            .query(
                "items",
                &Query::ByField {
                    field: "qty".into(),
                    value: json!(7),
                },
            )
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "b");
    }

    // ---- security tests ----

    #[test]
    fn injection_collection_name_rejected_on_ensure() {
        let s = SqliteStore::in_memory().unwrap();
        let err = s
            .ensure_collection(&CollectionSpec {
                name: "u\"; DROP TABLE x--".into(),
                indexed_fields: vec![],
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidIdentifier(_)));
    }

    #[test]
    fn injection_collection_name_rejected_on_query() {
        let s = store_with_users();
        let err = s
            .query("u\"; DROP TABLE users--", &Query::All)
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidIdentifier(_)));
    }

    #[test]
    fn injection_collection_name_rejected_on_put_get_delete() {
        let s = store_with_users();
        let bad = "users); DROP TABLE users--";
        assert!(matches!(
            s.put(bad, rec("x", json!({}))).unwrap_err(),
            StoreError::InvalidIdentifier(_)
        ));
        assert!(matches!(
            s.get(bad, "x").unwrap_err(),
            StoreError::InvalidIdentifier(_)
        ));
        assert!(matches!(
            s.delete(bad, "x").unwrap_err(),
            StoreError::InvalidIdentifier(_)
        ));
    }

    #[test]
    fn query_by_non_indexed_field_rejected() {
        let s = store_with_users();
        s.put("users", rec("u1", json!({"username": "a", "age": 30})))
            .unwrap();
        // `age` is a real document key but was NOT declared indexed.
        let err = s
            .query(
                "users",
                &Query::ByField {
                    field: "age".into(),
                    value: json!(30),
                },
            )
            .unwrap_err();
        assert!(matches!(err, StoreError::FieldNotIndexed(_)));
    }

    #[test]
    fn malicious_indexed_field_in_spec_rejected() {
        let s = SqliteStore::in_memory().unwrap();
        let err = s
            .ensure_collection(&CollectionSpec {
                name: "users".into(),
                indexed_fields: vec!["x'); DROP TABLE users--".into()],
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::InvalidIdentifier(_)));
        // And no `users` table/collection was registered.
        assert!(matches!(
            s.get("users", "any").unwrap_err(),
            StoreError::CollectionNotFound(_)
        ));
    }

    #[test]
    fn injection_in_byfield_field_rejected() {
        let s = store_with_users();
        let err = s
            .query(
                "users",
                &Query::ByField {
                    field: "username'); DROP TABLE users--".into(),
                    value: json!("x"),
                },
            )
            .unwrap_err();
        // Invalid identifier is caught before the allow-list check.
        assert!(matches!(err, StoreError::InvalidIdentifier(_)));
    }

    #[test]
    fn malicious_value_is_stored_literally_not_executed() {
        let s = store_with_users();
        let payload = "'); DROP TABLE users;--";
        s.put(
            "users",
            rec("u1", json!({"username": payload, "role": "admin"})),
        )
        .unwrap();
        // The table still exists and the value round-trips verbatim.
        let got = s.get("users", "u1").unwrap();
        assert_eq!(got.doc["username"], json!(payload));
        // Querying by that exact (indexed) value still works and returns it.
        let r = s
            .query(
                "users",
                &Query::ByField {
                    field: "username".into(),
                    value: json!(payload),
                },
            )
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "u1");
    }

    #[test]
    fn malformed_json_row_is_integrity_error_not_panic() {
        // A collection with no indexed fields, so the row's malformed JSON is not
        // rejected by an index expression at insert time and we can simulate a
        // corrupted-on-disk row.
        let s = SqliteStore::in_memory().unwrap();
        s.ensure_collection(&CollectionSpec {
            name: "blobs".into(),
            indexed_fields: vec![],
        })
        .unwrap();
        // Bypass `put` to write a row with invalid JSON directly.
        {
            let conn = s.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO \"blobs\" (id, doc) VALUES (?1, ?2)",
                params!["bad", "{not valid json"],
            )
            .unwrap();
        }
        let get_err = s.get("blobs", "bad").unwrap_err();
        assert!(matches!(get_err, StoreError::Storage(_)));
        let query_err = s.query("blobs", &Query::All).unwrap_err();
        assert!(matches!(query_err, StoreError::Storage(_)));
    }

    #[test]
    fn operations_on_undeclared_collection_fail() {
        let s = SqliteStore::in_memory().unwrap();
        // Valid identifier but never ensured.
        assert!(matches!(
            s.get("widgets", "x").unwrap_err(),
            StoreError::CollectionNotFound(_)
        ));
        assert!(matches!(
            s.query("widgets", &Query::All).unwrap_err(),
            StoreError::CollectionNotFound(_)
        ));
    }

    #[test]
    fn ensure_collection_is_idempotent() {
        let s = store_with_users();
        // Re-ensuring the same collection must not error.
        s.ensure_collection(&CollectionSpec {
            name: "users".into(),
            indexed_fields: vec!["username".into(), "role".into()],
        })
        .unwrap();
        s.put("users", rec("u1", json!({"username": "a"}))).unwrap();
        assert_eq!(s.query("users", &Query::All).unwrap().len(), 1);
    }

    #[test]
    fn path_traversal_rejected() {
        assert!(SqliteStore::open("../etc/evil.db").is_err());
    }

    #[test]
    fn collections_survive_reopen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wyrtloom_store_test_{}.db", std::process::id()));
        let path_str = path.to_str().unwrap().to_string();
        // Clean any stale file from a prior aborted run.
        let _ = std::fs::remove_file(&path);

        {
            let s = SqliteStore::open(&path_str).unwrap();
            s.ensure_collection(&CollectionSpec {
                name: "users".into(),
                indexed_fields: vec!["role".into()],
            })
            .unwrap();
            s.put("users", rec("u1", json!({"username": "alice", "role": "admin"})))
                .unwrap();
        } // store dropped — simulate process exit

        {
            // Fresh store over the same file: collection must be usable without
            // re-declaring it, and the indexed-field allow-list must be restored.
            let s = SqliteStore::open(&path_str).unwrap();
            let got = s.get("users", "u1").unwrap();
            assert_eq!(got.doc["username"], json!("alice"));
            let admins = s
                .query(
                    "users",
                    &Query::ByField {
                        field: "role".into(),
                        value: json!("admin"),
                    },
                )
                .unwrap();
            assert_eq!(admins.len(), 1);
            // A field that was never declared is still rejected after reload.
            assert!(matches!(
                s.query(
                    "users",
                    &Query::ByField {
                        field: "username".into(),
                        value: json!("alice")
                    }
                )
                .unwrap_err(),
                StoreError::FieldNotIndexed(_)
            ));
        }

        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_file(format!("{path_str}-wal"));
        let _ = std::fs::remove_file(format!("{path_str}-shm"));
    }

    #[test]
    fn malformed_catalog_indexed_fields_surfaces_on_reopen() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wyrtloom_store_badcat_{}.db", std::process::id()));
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);

        {
            let s = SqliteStore::open(&path_str).unwrap();
            s.ensure_collection(&CollectionSpec {
                name: "users".into(),
                indexed_fields: vec!["role".into()],
            })
            .unwrap();
            s.put("users", rec("u1", json!({"username": "alice", "role": "admin"})))
                .unwrap();
            // Corrupt the persisted indexed_fields JSON for the collection.
            let conn = s.conn.lock().unwrap();
            conn.execute(
                "UPDATE __wyrtloom_collections SET indexed_fields = ?1 WHERE name = ?2",
                params!["{not valid json", "users"],
            )
            .unwrap();
        } // store dropped — simulate process exit

        // Reopen must NOT silently drop the indexes (which would make the previously
        // valid `role` query start returning FieldNotIndexed). Instead it surfaces an
        // integrity error.
        match SqliteStore::open(&path_str) {
            Err(StoreError::Storage(m)) if m.contains("integrity error") => {}
            Err(e) => panic!("expected integrity error, got {e:?}"),
            Ok(_) => panic!("expected integrity error, but reopen succeeded"),
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{path_str}-wal"));
        let _ = std::fs::remove_file(format!("{path_str}-shm"));
    }

    #[test]
    fn index_names_do_not_collide_across_collections() {
        // `(a_b, c)` and `(a, b_c)` would collide under a naive `idx_{name}_{field}`
        // scheme; both indexed fields must end up actually indexed and queryable.
        let s = SqliteStore::in_memory().unwrap();
        s.ensure_collection(&CollectionSpec {
            name: "a_b".into(),
            indexed_fields: vec!["c".into()],
        })
        .unwrap();
        s.ensure_collection(&CollectionSpec {
            name: "a".into(),
            indexed_fields: vec!["b_c".into()],
        })
        .unwrap();
        s.put("a_b", rec("r1", json!({"c": "x"}))).unwrap();
        s.put("a", rec("r2", json!({"b_c": "y"}))).unwrap();

        let q1 = s
            .query("a_b", &Query::ByField { field: "c".into(), value: json!("x") })
            .unwrap();
        assert_eq!(q1.len(), 1);
        let q2 = s
            .query("a", &Query::ByField { field: "b_c".into(), value: json!("y") })
            .unwrap();
        assert_eq!(q2.len(), 1);

        // Confirm both indexes physically exist (distinct names in sqlite_master).
        let conn = s.conn.lock().unwrap();
        let idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(idx_count, 2);
    }

    #[test]
    fn query_by_field_null_matches_null_and_missing() {
        let s = SqliteStore::in_memory().unwrap();
        s.ensure_collection(&CollectionSpec {
            name: "users".into(),
            indexed_fields: vec!["status".into()],
        })
        .unwrap();
        s.put("users", rec("u1", json!({"status": null}))).unwrap();
        s.put("users", rec("u2", json!({"status": "active"}))).unwrap();
        s.put("users", rec("u3", json!({"username": "no_status"})))
            .unwrap(); // status key absent

        let nulls = s
            .query(
                "users",
                &Query::ByField {
                    field: "status".into(),
                    value: json!(null),
                },
            )
            .unwrap();
        // Matches both the explicit-null record and the missing-key record.
        let mut ids: Vec<_> = nulls.iter().map(|r| r.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["u1", "u3"]);
    }
}
