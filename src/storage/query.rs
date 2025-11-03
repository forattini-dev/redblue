// Simple query interface (NO full SQL parser - just what we need)
use super::engine::RedDB;
use std::io;

/// Query builder for RedDB
pub struct QueryBuilder {
    table: String,
    prefix: Option<Vec<u8>>,
    limit: Option<usize>,
}

impl QueryBuilder {
    pub fn new(table: &str) -> Self {
        Self {
            table: table.to_string(),
            prefix: None,
            limit: None,
        }
    }

    pub fn prefix(mut self, prefix: &[u8]) -> Self {
        self.prefix = Some(prefix.to_vec());
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn execute(self, db: &mut RedDB) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        // Build key prefix with table name
        let mut key_prefix = format!("{}:", self.table).into_bytes();
        if let Some(prefix) = self.prefix {
            key_prefix.extend_from_slice(&prefix);
        }

        // Execute scan
        let mut results = db.scan_prefix(&key_prefix)?;

        // Apply limit
        if let Some(limit) = self.limit {
            results.truncate(limit);
        }

        Ok(results)
    }
}

/// Simplified query interface
pub struct Query;

impl Query {
    /// Insert record
    /// Example: Query::insert(db, "scans", "192.168.1.1:80", "open")
    pub fn insert(db: &mut RedDB, table: &str, key: &str, value: &str) -> io::Result<()> {
        let full_key = format!("{}:{}", table, key);
        db.insert(full_key.as_bytes().to_vec(), value.as_bytes().to_vec())
    }

    /// Get record
    /// Example: Query::get(db, "scans", "192.168.1.1:80")
    pub fn get(db: &mut RedDB, table: &str, key: &str) -> io::Result<Option<String>> {
        let full_key = format!("{}:{}", table, key);
        match db.get(full_key.as_bytes())? {
            Some(value) => {
                let s = String::from_utf8(value)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    /// Delete record
    pub fn delete(db: &mut RedDB, table: &str, key: &str) -> io::Result<bool> {
        let full_key = format!("{}:{}", table, key);
        db.delete(full_key.as_bytes())
    }

    /// Select all records from table
    /// Example: Query::select(db, "scans")
    pub fn select(db: &mut RedDB, table: &str) -> io::Result<Vec<(String, String)>> {
        let prefix = format!("{}:", table);
        let results = db.scan_prefix(prefix.as_bytes())?;

        let mut parsed = Vec::new();
        for (key, value) in results {
            let key_str = String::from_utf8(key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let value_str = String::from_utf8(value)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            // Remove table prefix from key
            let trimmed_key = key_str.strip_prefix(&prefix).unwrap_or(&key_str);
            parsed.push((trimmed_key.to_string(), value_str));
        }

        Ok(parsed)
    }

    /// Select records with WHERE clause (prefix match)
    /// Example: Query::select_where(db, "scans", "192.168.1")
    pub fn select_where(
        db: &mut RedDB,
        table: &str,
        prefix: &str,
    ) -> io::Result<Vec<(String, String)>> {
        let full_prefix = format!("{}:{}", table, prefix);
        let results = db.scan_prefix(full_prefix.as_bytes())?;

        let table_prefix = format!("{}:", table);
        let mut parsed = Vec::new();
        for (key, value) in results {
            let key_str = String::from_utf8(key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let value_str = String::from_utf8(value)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            let trimmed_key = key_str.strip_prefix(&table_prefix).unwrap_or(&key_str);
            parsed.push((trimmed_key.to_string(), value_str));
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::RedDB;

    #[test]
    fn test_query_interface() {
        let path = "/tmp/reddb_query_test.db";
        let _ = std::fs::remove_file(path);

        let mut db = RedDB::open(path).unwrap();

        // Insert
        Query::insert(&mut db, "scans", "192.168.1.1:80", "open").unwrap();
        Query::insert(&mut db, "scans", "192.168.1.1:443", "open").unwrap();
        Query::insert(&mut db, "scans", "192.168.1.2:80", "closed").unwrap();

        // Get
        let value = Query::get(&mut db, "scans", "192.168.1.1:80")
            .unwrap()
            .unwrap();
        assert_eq!(value, "open");

        // Select all
        let results = Query::select(&mut db, "scans").unwrap();
        assert_eq!(results.len(), 3);

        // Select where
        let results = Query::select_where(&mut db, "scans", "192.168.1.1").unwrap();
        assert_eq!(results.len(), 2);

        std::fs::remove_file(path).unwrap();
        let _ = std::fs::remove_file(format!("{}.wal", path));
    }
}
