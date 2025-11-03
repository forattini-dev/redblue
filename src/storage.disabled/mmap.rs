// Memory-mapped file I/O for maximum performance
// ZERO external dependencies - uses raw syscalls on Linux
// For portability, falls back to regular file I/O on non-Linux

use std::fs::File;
use std::io;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

// Linux syscall numbers and constants
#[cfg(target_os = "linux")]
const SYS_MMAP: i64 = 9;
#[cfg(target_os = "linux")]
const SYS_MUNMAP: i64 = 11;
#[cfg(target_os = "linux")]
const PROT_READ: i32 = 1;
#[cfg(target_os = "linux")]
const MAP_SHARED: i32 = 1;
#[cfg(target_os = "linux")]
const MAP_FAILED: isize = -1;

// Macro for raw syscalls (ZERO dependencies!)
#[cfg(target_os = "linux")]
macro_rules! syscall {
    ($num:expr, $arg1:expr, $arg2:expr) => {{
        let mut ret: i64;
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") $num as i64,
                in("rdi") $arg1 as i64,
                in("rsi") $arg2 as i64,
                lateout("rax") ret,
                options(nostack)
            );
        }
        ret
    }};
    ($num:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, $arg6:expr) => {{
        let mut ret: i64;
        unsafe {
            std::arch::asm!(
                "syscall",
                in("rax") $num as i64,
                in("rdi") $arg1 as i64,
                in("rsi") $arg2 as i64,
                in("rdx") $arg3 as i32,
                in("r10") $arg4 as i32,
                in("r8") $arg5 as i32,
                in("r9") $arg6 as i64,
                lateout("rax") ret,
                options(nostack)
            );
        }
        ret
    }};
}

#[cfg(target_os = "linux")]
pub struct MmapFile {
    ptr: *mut u8,
    len: usize,
    _file: File,
}

#[cfg(target_os = "linux")]
impl MmapFile {
    /// Memory-map a file for reading using raw syscalls
    pub fn new(file: File, len: usize) -> io::Result<Self> {
        use std::ptr;

        let fd = file.as_raw_fd();

        // Direct mmap syscall (ZERO dependencies!)
        let ptr = syscall!(
            SYS_MMAP,
            ptr::null_mut::<u8>(),
            len,
            PROT_READ,
            MAP_SHARED,
            fd,
            0
        ) as isize;

        if ptr == MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            ptr: ptr as *mut u8,
            len,
            _file: file,
        })
    }

    /// Get slice view of mapped memory
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Read u32 at offset
    pub fn read_u32(&self, offset: usize) -> io::Result<u32> {
        if offset + 4 > self.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Offset out of bounds",
            ));
        }

        let bytes = unsafe {
            std::slice::from_raw_parts(self.ptr.add(offset), 4)
        };

        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read bytes at offset
    pub fn read_bytes(&self, offset: usize, len: usize) -> io::Result<&[u8]> {
        if offset + len > self.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Offset out of bounds",
            ));
        }

        Ok(unsafe { std::slice::from_raw_parts(self.ptr.add(offset), len) })
    }
}

#[cfg(target_os = "linux")]
impl Drop for MmapFile {
    fn drop(&mut self) {
        let _ = syscall!(SYS_MUNMAP, self.ptr, self.len);
    }
}

// Simpler fallback for non-Linux systems - just disable mmap
#[cfg(not(target_os = "linux"))]
pub struct MmapFile {
    _placeholder: (),
}

#[cfg(not(target_os = "linux"))]
impl MmapFile {
    pub fn new(_file: File, _len: usize) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mmap only supported on Linux (use regular file I/O)",
        ))
    }

    pub fn as_slice(&self) -> &[u8] {
        &[]
    }

    pub fn read_u32(&self, _offset: usize) -> io::Result<u32> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Not implemented"))
    }

    pub fn read_bytes(&self, _offset: usize, _len: usize) -> io::Result<&[u8]> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "Not implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_mmap_basic() {
        let path = "/tmp/mmap_test.dat";

        // Create test file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();

        file.write_all(b"Hello, mmap!").unwrap();
        drop(file);

        // Open for mmap
        let file = OpenOptions::new().read(true).open(path).unwrap();
        let len = file.metadata().unwrap().len() as usize;

        let mmap = MmapFile::new(file, len).unwrap();
        let data = mmap.as_slice();

        assert_eq!(data, b"Hello, mmap!");

        std::fs::remove_file(path).unwrap();
    }
}
