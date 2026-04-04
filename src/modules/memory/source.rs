//! Data source abstraction for hex editing
//!
//! Provides a unified interface for accessing data from different sources:
//! - Process memory (via ptrace/proc)
//! - Memory-mapped files
//! - In-memory buffers

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Error types for data source operations
#[derive(Debug)]
pub enum SourceError {
    IoError(std::io::Error),
    ReadFailed,
    WriteFailed,
    FlushFailed,
    OutOfBounds,
    ReadOnly,
    AttachFailed(i32),
    PermissionDenied,
    ProcessNotFound(i32),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::ReadFailed => write!(f, "Read failed"),
            Self::WriteFailed => write!(f, "Write failed"),
            Self::FlushFailed => write!(f, "Flush failed"),
            Self::OutOfBounds => write!(f, "Access out of bounds"),
            Self::ReadOnly => write!(f, "Source is read-only"),
            Self::AttachFailed(pid) => write!(f, "Failed to attach to process {}", pid),
            Self::PermissionDenied => write!(f, "Permission denied"),
            Self::ProcessNotFound(pid) => write!(f, "Process {} not found", pid),
        }
    }
}

impl From<std::io::Error> for SourceError {
    fn from(err: std::io::Error) -> Self {
        SourceError::IoError(err)
    }
}

pub type SourceResult<T> = Result<T, SourceError>;

/// Trait for data sources (memory, file, buffer)
pub trait DataSource: Send {
    /// Read bytes at offset
    fn read(&mut self, offset: u64, len: usize) -> SourceResult<Vec<u8>>;

    /// Write bytes at offset
    fn write(&mut self, offset: u64, data: &[u8]) -> SourceResult<()>;

    /// Total size in bytes
    fn size(&self) -> u64;

    /// Flush pending writes
    fn flush(&mut self) -> SourceResult<()>;

    /// Can insert/delete bytes (files only, not memory)
    fn supports_resize(&self) -> bool;

    /// Is the source writable?
    fn is_writable(&self) -> bool;

    /// Source description for display
    fn description(&self) -> String;
}

/// In-memory buffer source
pub struct BufferSource {
    data: Vec<u8>,
    writable: bool,
    name: String,
}

impl BufferSource {
    /// Create a new buffer source
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            writable: true,
            name: "buffer".to_string(),
        }
    }

    /// Create a read-only buffer
    pub fn read_only(data: Vec<u8>) -> Self {
        Self {
            data,
            writable: false,
            name: "buffer (read-only)".to_string(),
        }
    }

    /// Create from file contents
    pub fn from_file(path: &Path) -> SourceResult<Self> {
        let data = std::fs::read(path)?;
        Ok(Self {
            data,
            writable: true,
            name: path.display().to_string(),
        })
    }

    /// Get reference to internal data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl DataSource for BufferSource {
    fn read(&mut self, offset: u64, len: usize) -> SourceResult<Vec<u8>> {
        let start = offset as usize;
        if start >= self.data.len() {
            return Ok(Vec::new());
        }

        let end = (start + len).min(self.data.len());
        Ok(self.data[start..end].to_vec())
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> SourceResult<()> {
        if !self.writable {
            return Err(SourceError::ReadOnly);
        }

        let start = offset as usize;
        let end = start + data.len();

        // Extend buffer if needed
        if end > self.data.len() {
            self.data.resize(end, 0);
        }

        self.data[start..end].copy_from_slice(data);
        Ok(())
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn flush(&mut self) -> SourceResult<()> {
        Ok(()) // Nothing to flush for memory buffer
    }

    fn supports_resize(&self) -> bool {
        self.writable
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn description(&self) -> String {
        self.name.clone()
    }
}

/// File-based source using standard I/O
pub struct FileSource {
    path: PathBuf,
    file: File,
    size: u64,
    writable: bool,
}

impl FileSource {
    /// Open a file for reading
    pub fn open(path: &Path) -> SourceResult<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();

        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            writable: false,
        })
    }

    /// Open a file for reading and writing
    pub fn open_rw(path: &Path) -> SourceResult<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let size = file.metadata()?.len();

        Ok(Self {
            path: path.to_path_buf(),
            file,
            size,
            writable: true,
        })
    }
}

impl DataSource for FileSource {
    fn read(&mut self, offset: u64, len: usize) -> SourceResult<Vec<u8>> {
        if offset >= self.size {
            return Ok(Vec::new());
        }

        self.file.seek(SeekFrom::Start(offset))?;
        let to_read = len.min((self.size - offset) as usize);
        let mut buffer = vec![0u8; to_read];
        let read = self.file.read(&mut buffer)?;
        buffer.truncate(read);
        Ok(buffer)
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> SourceResult<()> {
        if !self.writable {
            return Err(SourceError::ReadOnly);
        }

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;

        // Update size if we wrote past the end
        let new_end = offset + data.len() as u64;
        if new_end > self.size {
            self.size = new_end;
        }

        Ok(())
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn flush(&mut self) -> SourceResult<()> {
        self.file.flush()?;
        Ok(())
    }

    fn supports_resize(&self) -> bool {
        self.writable
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn description(&self) -> String {
        self.path.display().to_string()
    }
}

/// Process memory source
#[cfg(target_os = "linux")]
pub struct ProcessMemorySource {
    pid: i32,
    base_addr: u64,
    region_size: u64,
    mem_file: Option<File>,
    writable: bool,
}

#[cfg(target_os = "linux")]
impl ProcessMemorySource {
    /// Create a source for a process memory region
    pub fn new(pid: i32, base_addr: u64, region_size: u64) -> SourceResult<Self> {
        // Try to open /proc/pid/mem
        let mem_path = format!("/proc/{}/mem", pid);
        let mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mem_path)
            .ok();

        let writable = mem_file.as_ref().is_some();

        Ok(Self {
            pid,
            base_addr,
            region_size,
            mem_file,
            writable,
        })
    }

    /// Create using process_vm_readv/writev (more efficient for bulk operations)
    pub fn new_vm(pid: i32, base_addr: u64, region_size: u64) -> Self {
        Self {
            pid,
            base_addr,
            region_size,
            mem_file: None,
            writable: true, // process_vm_writev requires appropriate permissions
        }
    }

    fn read_via_proc(&mut self, offset: u64, len: usize) -> SourceResult<Vec<u8>> {
        let Some(ref mut file) = self.mem_file else {
            return self.read_via_vm(offset, len);
        };

        let addr = self.base_addr + offset;
        file.seek(SeekFrom::Start(addr))?;

        let mut buffer = vec![0u8; len];
        match file.read(&mut buffer) {
            Ok(n) => {
                buffer.truncate(n);
                Ok(buffer)
            }
            Err(e) => Err(SourceError::IoError(e)),
        }
    }

    fn read_via_vm(&self, offset: u64, len: usize) -> SourceResult<Vec<u8>> {
        let addr = self.base_addr + offset;
        let mut buffer = vec![0u8; len];

        let local_iov = libc::iovec {
            iov_base: buffer.as_mut_ptr() as *mut _,
            iov_len: len,
        };
        let remote_iov = libc::iovec {
            iov_base: addr as *mut _,
            iov_len: len,
        };

        let read = unsafe { libc::process_vm_readv(self.pid, &local_iov, 1, &remote_iov, 1, 0) };

        if read < 0 {
            return Err(SourceError::ReadFailed);
        }

        buffer.truncate(read as usize);
        Ok(buffer)
    }

    fn write_via_proc(&mut self, offset: u64, data: &[u8]) -> SourceResult<()> {
        let Some(ref mut file) = self.mem_file else {
            return self.write_via_vm(offset, data);
        };

        let addr = self.base_addr + offset;
        file.seek(SeekFrom::Start(addr))?;
        file.write_all(data)?;
        Ok(())
    }

    fn write_via_vm(&self, offset: u64, data: &[u8]) -> SourceResult<()> {
        let addr = self.base_addr + offset;

        let local_iov = libc::iovec {
            iov_base: data.as_ptr() as *mut _,
            iov_len: data.len(),
        };
        let remote_iov = libc::iovec {
            iov_base: addr as *mut _,
            iov_len: data.len(),
        };

        let written =
            unsafe { libc::process_vm_writev(self.pid, &local_iov, 1, &remote_iov, 1, 0) };

        if written < 0 || written as usize != data.len() {
            return Err(SourceError::WriteFailed);
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl DataSource for ProcessMemorySource {
    fn read(&mut self, offset: u64, len: usize) -> SourceResult<Vec<u8>> {
        if offset >= self.region_size {
            return Err(SourceError::OutOfBounds);
        }

        let actual_len = len.min((self.region_size - offset) as usize);
        self.read_via_proc(offset, actual_len)
    }

    fn write(&mut self, offset: u64, data: &[u8]) -> SourceResult<()> {
        if !self.writable {
            return Err(SourceError::ReadOnly);
        }

        if offset + data.len() as u64 > self.region_size {
            return Err(SourceError::OutOfBounds);
        }

        self.write_via_proc(offset, data)
    }

    fn size(&self) -> u64 {
        self.region_size
    }

    fn flush(&mut self) -> SourceResult<()> {
        Ok(()) // Memory writes are immediate
    }

    fn supports_resize(&self) -> bool {
        false // Can't resize process memory
    }

    fn is_writable(&self) -> bool {
        self.writable
    }

    fn description(&self) -> String {
        format!(
            "pid:{} @ 0x{:x} ({} bytes)",
            self.pid, self.base_addr, self.region_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_source() {
        let data = vec![0x41, 0x42, 0x43, 0x44];
        let mut source = BufferSource::new(data);

        assert_eq!(source.size(), 4);
        assert!(source.is_writable());

        let read = source.read(0, 4).unwrap();
        assert_eq!(read, vec![0x41, 0x42, 0x43, 0x44]);

        let read = source.read(2, 2).unwrap();
        assert_eq!(read, vec![0x43, 0x44]);

        source.write(1, &[0xFF]).unwrap();
        let read = source.read(0, 4).unwrap();
        assert_eq!(read, vec![0x41, 0xFF, 0x43, 0x44]);
    }

    #[test]
    fn test_buffer_extend() {
        let data = vec![0x41, 0x42];
        let mut source = BufferSource::new(data);

        source.write(4, &[0x43, 0x44]).unwrap();
        assert_eq!(source.size(), 6);

        let read = source.read(0, 6).unwrap();
        assert_eq!(read, vec![0x41, 0x42, 0x00, 0x00, 0x43, 0x44]);
    }
}
