// Write-Ahead Log for durability
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::Path;

/// Write-ahead log for crash recovery
pub struct WriteAheadLog {
    file: File,
}

impl WriteAheadLog {
    /// Open or create WAL file
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self { file })
    }

    /// Append entry to WAL
    pub fn append(&mut self, data: &[u8]) -> io::Result<()> {
        // Write length prefix
        self.file.write_all(&(data.len() as u32).to_le_bytes())?;
        // Write data
        self.file.write_all(data)?;
        Ok(())
    }

    /// Sync WAL to disk
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Clear WAL (after successful checkpoint)
    pub fn clear(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        Ok(())
    }
}
