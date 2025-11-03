// RedDB Engine - Core database implementation
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::serializer::{Serializer, Record};
use super::wal::WriteAheadLog;

/// High-performance embedded database optimized for security scanning
pub struct RedDB {
    /// Data file path
    data_path: PathBuf,
    /// Data file handle
    data_file: File,
    /// In-memory index: primary key -> file offset
    index: BTreeMap<Vec<u8>, u64>,
    /// Write-ahead log for durability
    wal: WriteAheadLog,
    /// Next available offset
    next_offset: u64,
    /// Dirty flag (needs flush)
    dirty: bool,
}

impl RedDB {
    /// Open or create a database
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let data_path = path.as_ref().to_path_buf();
        let wal_path = data_path.with_extension("wal");

        let mut data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&data_path)?;

        let wal = WriteAheadLog::open(wal_path)?;

        // Get file size to know next offset
        let next_offset = data_file.seek(SeekFrom::End(0))?;

        let mut db = Self {
            data_path,
            data_file,
            index: BTreeMap::new(),
            wal,
            next_offset,
            dirty: false,
        };

        // Build index by scanning existing data
        db.rebuild_index()?;

        Ok(db)
    }

    /// Insert a record (append-only, very fast)
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> io::Result<()> {
        // Serialize record
        let record = Record { key: key.clone(), value };
        let serialized = Serializer::serialize(&record)?;

        // Write to WAL first (durability)
        self.wal.append(&serialized)?;

        // Write to data file
        let offset = self.next_offset;
        self.data_file.seek(SeekFrom::Start(offset))?;
        self.data_file.write_all(&serialized)?;

        // Update index
        self.index.insert(key, offset);
        self.next_offset += serialized.len() as u64;
        self.dirty = true;

        Ok(())
    }

    /// Get a record by key (O(log n) lookup)
    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        match self.index.get(key) {
            Some(&offset) => {
                self.data_file.seek(SeekFrom::Start(offset))?;

                // Read record length (first 4 bytes)
                let mut len_buf = [0u8; 4];
                self.data_file.read_exact(&mut len_buf)?;
                let len = u32::from_le_bytes(len_buf) as usize;

                // Read full record
                let mut buf = vec![0u8; len];
                self.data_file.read_exact(&mut buf)?;

                // Deserialize
                let record = Serializer::deserialize(&buf)?;
                Ok(Some(record.value))
            }
            None => Ok(None),
        }
    }

    /// Scan all records with key prefix (range query)
    pub fn scan_prefix(&mut self, prefix: &[u8]) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut results = Vec::new();

        // BTreeMap range query (very efficient)
        for (key, &offset) in self.index.range(prefix.to_vec()..) {
            if !key.starts_with(prefix) {
                break;
            }

            // Read record at offset
            self.data_file.seek(SeekFrom::Start(offset))?;
            let mut len_buf = [0u8; 4];
            self.data_file.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;

            let mut buf = vec![0u8; len];
            self.data_file.read_exact(&mut buf)?;

            let record = Serializer::deserialize(&buf)?;
            results.push((record.key, record.value));
        }

        Ok(results)
    }

    /// Delete a record (mark as tombstone, compaction happens later)
    pub fn delete(&mut self, key: &[u8]) -> io::Result<bool> {
        if self.index.remove(key).is_some() {
            self.dirty = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Flush changes to disk
    pub fn flush(&mut self) -> io::Result<()> {
        if self.dirty {
            self.data_file.sync_all()?;
            self.wal.sync()?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Rebuild index from data file (recovery)
    fn rebuild_index(&mut self) -> io::Result<()> {
        self.index.clear();
        self.data_file.seek(SeekFrom::Start(0))?;

        let mut offset = 0u64;
        loop {
            // Try to read record length
            let mut len_buf = [0u8; 4];
            match self.data_file.read_exact(&mut len_buf) {
                Ok(_) => {
                    let len = u32::from_le_bytes(len_buf) as usize;

                    // Read full record
                    let mut buf = vec![0u8; len];
                    self.data_file.read_exact(&mut buf)?;

                    // Deserialize to get key
                    let record = Serializer::deserialize(&buf)?;
                    self.index.insert(record.key, offset);

                    offset += 4 + len as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }

        self.next_offset = offset;
        Ok(())
    }

    /// Compact database (remove deleted records, rebuild file)
    pub fn compact(&mut self) -> io::Result<()> {
        // Create temporary file
        let temp_path = self.data_path.with_extension("tmp");
        let mut temp_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        let mut new_index = BTreeMap::new();
        let mut new_offset = 0u64;

        // Copy only live records
        for (key, &offset) in &self.index {
            self.data_file.seek(SeekFrom::Start(offset))?;

            let mut len_buf = [0u8; 4];
            self.data_file.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;

            let mut buf = vec![0u8; len];
            self.data_file.read_exact(&mut buf)?;

            // Write to new file
            temp_file.write_all(&len_buf)?;
            temp_file.write_all(&buf)?;

            new_index.insert(key.clone(), new_offset);
            new_offset += 4 + len as u64;
        }

        // Close old file and replace with new file
        drop(std::mem::replace(
            &mut self.data_file,
            OpenOptions::new().read(true).write(true).create(true).open("/dev/null")?
        ));
        std::fs::rename(&temp_path, &self.data_path)?;

        self.data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.data_path)?;

        self.index = new_index;
        self.next_offset = new_offset;
        self.dirty = false;

        Ok(())
    }

    /// Count total records
    pub fn count(&self) -> usize {
        self.index.len()
    }
}

impl Drop for RedDB {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_basic_operations() {
        let path = "/tmp/reddb_test.db";
        let _ = std::fs::remove_file(path);

        let mut db = RedDB::open(path).unwrap();

        // Insert
        db.insert(b"domain:example.com".to_vec(), b"192.168.1.1".to_vec()).unwrap();
        db.insert(b"domain:google.com".to_vec(), b"8.8.8.8".to_vec()).unwrap();

        // Get
        let value = db.get(b"domain:example.com").unwrap().unwrap();
        assert_eq!(value, b"192.168.1.1");

        // Scan prefix
        let results = db.scan_prefix(b"domain:").unwrap();
        assert_eq!(results.len(), 2);

        // Delete
        assert!(db.delete(b"domain:example.com").unwrap());
        assert!(db.get(b"domain:example.com").unwrap().is_none());

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_performance_1m_records() {
        let path = "/tmp/reddb_perf.db";
        let _ = std::fs::remove_file(path);

        let mut db = RedDB::open(path).unwrap();

        let start = Instant::now();
        for i in 0..1_000_000 {
            let key = format!("scan:{}:port:80", i);
            db.insert(key.as_bytes().to_vec(), b"open".to_vec()).unwrap();

            if i % 10000 == 0 {
                db.flush().unwrap();
            }
        }
        let elapsed = start.elapsed();

        println!("Inserted 1M records in {:?}", elapsed);
        println!("Rate: {:.0} records/sec", 1_000_000.0 / elapsed.as_secs_f64());

        // Test read performance
        let start = Instant::now();
        for i in 0..100_000 {
            let key = format!("scan:{}:port:80", i);
            let _ = db.get(key.as_bytes()).unwrap();
        }
        let elapsed = start.elapsed();
        println!("Read 100K records in {:?}", elapsed);
        println!("Rate: {:.0} reads/sec", 100_000.0 / elapsed.as_secs_f64());

        std::fs::remove_file(path).unwrap();
        let _ = std::fs::remove_file(format!("{}.wal", path));
    }
}
