//! Process memory access via ptrace and /proc filesystem

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

/// Represents an attached process for memory inspection
pub struct ProcessMemory {
    pid: i32,
    mem_file: Option<File>,
    attached: bool,
}

impl ProcessMemory {
    /// Attach to a process by PID using ptrace
    pub fn attach(pid: i32) -> Result<Self, String> {
        // First, try to attach via ptrace
        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_ATTACH,
                pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };

        if result == -1 {
            let errno = std::io::Error::last_os_error();
            return Err(format!("Failed to attach to process {}: {}", pid, errno));
        }

        // Wait for the process to stop
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }

        // Open /proc/pid/mem for faster bulk reads
        let mem_path = format!("/proc/{}/mem", pid);
        let mem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&mem_path)
            .ok();

        Ok(Self {
            pid,
            mem_file,
            attached: true,
        })
    }

    /// Create a read-only view without attaching (for processes we own)
    pub fn open_readonly(pid: i32) -> Result<Self, String> {
        let mem_path = format!("/proc/{}/mem", pid);
        let mem_file = OpenOptions::new()
            .read(true)
            .open(&mem_path)
            .map_err(|e| format!("Failed to open {}: {}", mem_path, e))?;

        Ok(Self {
            pid,
            mem_file: Some(mem_file),
            attached: false,
        })
    }

    /// Get the process ID
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Check if we're attached via ptrace
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Read bytes from a memory address
    pub fn read_bytes(&mut self, addr: usize, size: usize) -> Result<Vec<u8>, String> {
        if let Some(ref mut file) = self.mem_file {
            // Use /proc/pid/mem for fast reads
            file.seek(SeekFrom::Start(addr as u64))
                .map_err(|e| format!("Seek failed: {}", e))?;

            let mut buffer = vec![0u8; size];
            match file.read_exact(&mut buffer) {
                Ok(_) => Ok(buffer),
                Err(e) => Err(format!("Read failed at 0x{:x}: {}", addr, e)),
            }
        } else {
            // Fallback to ptrace PEEKDATA (slower, word by word)
            self.read_bytes_ptrace(addr, size)
        }
    }

    /// Read bytes using ptrace (slower but more reliable)
    fn read_bytes_ptrace(&self, addr: usize, size: usize) -> Result<Vec<u8>, String> {
        let word_size = std::mem::size_of::<libc::c_long>();
        let mut buffer = Vec::with_capacity(size);
        let mut current_addr = addr;

        while buffer.len() < size {
            let word = unsafe {
                // Clear errno before ptrace call
                *libc::__errno_location() = 0;

                libc::ptrace(
                    libc::PTRACE_PEEKDATA,
                    self.pid,
                    current_addr as *mut libc::c_void,
                    std::ptr::null_mut::<libc::c_void>(),
                )
            };

            // Check for error (ptrace returns -1 and sets errno)
            let errno = unsafe { *libc::__errno_location() };
            if word == -1 && errno != 0 {
                if buffer.is_empty() {
                    return Err(format!(
                        "PEEKDATA failed at 0x{:x}: {}",
                        current_addr,
                        std::io::Error::from_raw_os_error(errno)
                    ));
                }
                // Partial read, return what we got
                break;
            }

            let bytes = word.to_ne_bytes();
            let remaining = size - buffer.len();
            let to_copy = remaining.min(word_size);
            buffer.extend_from_slice(&bytes[..to_copy]);

            current_addr += word_size;
        }

        Ok(buffer)
    }

    /// Write bytes to a memory address
    pub fn write_bytes(&mut self, addr: usize, data: &[u8]) -> Result<(), String> {
        if let Some(ref mut file) = self.mem_file {
            file.seek(SeekFrom::Start(addr as u64))
                .map_err(|e| format!("Seek failed: {}", e))?;

            file.write_all(data)
                .map_err(|e| format!("Write failed at 0x{:x}: {}", addr, e))?;

            Ok(())
        } else {
            self.write_bytes_ptrace(addr, data)
        }
    }

    /// Write bytes using ptrace
    fn write_bytes_ptrace(&self, addr: usize, data: &[u8]) -> Result<(), String> {
        let word_size = std::mem::size_of::<libc::c_long>();
        let mut offset = 0;

        while offset < data.len() {
            let current_addr = addr + offset;

            // If we have a full word, write it directly
            if offset + word_size <= data.len() {
                let mut word_bytes = [0u8; 8];
                word_bytes[..word_size].copy_from_slice(&data[offset..offset + word_size]);
                let word = libc::c_long::from_ne_bytes(word_bytes);

                let result = unsafe {
                    libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        self.pid,
                        current_addr as *mut libc::c_void,
                        word as *mut libc::c_void,
                    )
                };

                if result == -1 {
                    let errno = std::io::Error::last_os_error();
                    return Err(format!(
                        "POKEDATA failed at 0x{:x}: {}",
                        current_addr, errno
                    ));
                }

                offset += word_size;
            } else {
                // Partial word: read-modify-write
                let existing = unsafe {
                    libc::ptrace(
                        libc::PTRACE_PEEKDATA,
                        self.pid,
                        current_addr as *mut libc::c_void,
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                };

                let mut word_bytes = existing.to_ne_bytes();
                let remaining = data.len() - offset;
                word_bytes[..remaining].copy_from_slice(&data[offset..]);
                let word = libc::c_long::from_ne_bytes(word_bytes);

                let result = unsafe {
                    libc::ptrace(
                        libc::PTRACE_POKEDATA,
                        self.pid,
                        current_addr as *mut libc::c_void,
                        word as *mut libc::c_void,
                    )
                };

                if result == -1 {
                    let errno = std::io::Error::last_os_error();
                    return Err(format!(
                        "POKEDATA failed at 0x{:x}: {}",
                        current_addr, errno
                    ));
                }

                break;
            }
        }

        Ok(())
    }

    /// Read a value of type T from memory
    pub fn read<T: Copy>(&mut self, addr: usize) -> Result<T, String> {
        let size = std::mem::size_of::<T>();
        let bytes = self.read_bytes(addr, size)?;

        if bytes.len() < size {
            return Err(format!(
                "Incomplete read: got {} bytes, expected {}",
                bytes.len(),
                size
            ));
        }

        // Safety: we've verified the size matches
        let value = unsafe { std::ptr::read(bytes.as_ptr() as *const T) };
        Ok(value)
    }

    /// Write a value of type T to memory
    pub fn write<T: Copy>(&mut self, addr: usize, value: T) -> Result<(), String> {
        let size = std::mem::size_of::<T>();
        let bytes = unsafe { std::slice::from_raw_parts(&value as *const T as *const u8, size) };
        self.write_bytes(addr, bytes)
    }

    /// Continue process execution (if attached)
    pub fn cont(&self) -> Result<(), String> {
        if !self.attached {
            return Ok(());
        }

        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_CONT,
                self.pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };

        if result == -1 {
            let errno = std::io::Error::last_os_error();
            return Err(format!("PTRACE_CONT failed: {}", errno));
        }

        Ok(())
    }

    /// Stop the process (send SIGSTOP)
    pub fn stop(&self) -> Result<(), String> {
        let result = unsafe { libc::kill(self.pid, libc::SIGSTOP) };

        if result == -1 {
            let errno = std::io::Error::last_os_error();
            return Err(format!("Failed to stop process: {}", errno));
        }

        // Wait for it to actually stop
        let mut status: libc::c_int = 0;
        unsafe {
            libc::waitpid(self.pid, &mut status, libc::WUNTRACED);
        }

        Ok(())
    }

    /// Detach from the process
    pub fn detach(&mut self) -> Result<(), String> {
        if !self.attached {
            return Ok(());
        }

        let result = unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };

        if result == -1 {
            let errno = std::io::Error::last_os_error();
            return Err(format!("PTRACE_DETACH failed: {}", errno));
        }

        self.attached = false;
        Ok(())
    }

    /// Get process name from /proc/pid/comm
    pub fn name(&self) -> Result<String, String> {
        let path = format!("/proc/{}/comm", self.pid);
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Failed to read process name: {}", e))
    }

    /// Get process command line from /proc/pid/cmdline
    pub fn cmdline(&self) -> Result<Vec<String>, String> {
        let path = format!("/proc/{}/cmdline", self.pid);
        let data = std::fs::read(&path).map_err(|e| format!("Failed to read cmdline: {}", e))?;

        Ok(data
            .split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).to_string())
            .collect())
    }
}

impl Drop for ProcessMemory {
    fn drop(&mut self) {
        if self.attached {
            let _ = self.detach();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_own_memory() {
        // We can read our own process memory
        let pid = std::process::id() as i32;
        let test_value: i32 = 0x12345678;
        let addr = &test_value as *const i32 as usize;

        // Note: Can't attach to self with ptrace, but can read via /proc
        if let Ok(mut proc) = ProcessMemory::open_readonly(pid) {
            if let Ok(read_value) = proc.read::<i32>(addr) {
                assert_eq!(read_value, test_value);
            }
        }
    }
}
