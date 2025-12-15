use redblue::accessors::file::FileAccessor;
use redblue::accessors::network::NetworkAccessor;
use redblue::accessors::process::ProcessAccessor;
use redblue::accessors::registry::RegistryAccessor;
use redblue::accessors::service::ServiceAccessor;
use redblue::accessors::{Accessor, AccessorResult};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[test]
fn test_file_accessor() {
    let accessor = FileAccessor::new();
    let mut args = HashMap::new();

    // Test list
    args.insert("path".to_string(), ".".to_string());
    let result = accessor.execute("list", &args);
    assert!(result.success);
    let json = result.data.unwrap();
    assert!(json.as_array().unwrap().len() > 0);

    // Test read/hash
    let test_file = "test_accessor.txt";
    let mut f = File::create(test_file).unwrap();
    f.write_all(b"hello world").unwrap();

    args.insert("path".to_string(), test_file.to_string());
    let result = accessor.execute("read", &args);
    assert!(result.success);
    assert_eq!(result.data.unwrap().as_str().unwrap(), "hello world");

    args.insert("algorithm".to_string(), "sha256".to_string());
    let result = accessor.execute("hash", &args);
    assert!(result.success);
    let hash = result.data.unwrap();
    assert_eq!(
        hash["hash"].as_str().unwrap(),
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    std::fs::remove_file(test_file).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn test_process_accessor_linux() {
    let accessor = ProcessAccessor::new();
    let args = HashMap::new();

    let result = accessor.execute("list", &args);
    assert!(result.success);
    let list = result.data.unwrap();
    let procs = list.as_array().unwrap();
    assert!(!procs.is_empty());

    // Ensure current process is in list (approximate check)
    let my_pid = std::process::id();
    let found = procs
        .iter()
        .any(|p| p["pid"].as_u64() == Some(my_pid as u64));
    assert!(found, "Current PID {} not found in process list", my_pid);

    let result = accessor.execute("tree", &args);
    assert!(result.success);
}

#[cfg(target_os = "linux")]
#[test]
fn test_network_accessor_linux() {
    let accessor = NetworkAccessor::new();
    let args = HashMap::new();

    let result = accessor.execute("connections", &args);
    assert!(result.success);
    let conns = result.data.unwrap();
    assert!(conns.as_array().is_some());

    let result = accessor.execute("interfaces", &args);
    assert!(result.success);
    let ifaces = result.data.unwrap();
    assert!(ifaces.as_array().unwrap().iter().any(|i| i["name"] == "lo"
        || i["name"] == "eth0"
        || i["name"].as_str().unwrap().starts_with("e")));
}

#[cfg(target_os = "linux")]
#[test]
fn test_service_accessor_linux() {
    let accessor = ServiceAccessor::new();
    let args = HashMap::new();

    let result = accessor.execute("list", &args);
    assert!(result.success);
    // Might be empty in containers/minimal envs, but should succeed
    let services = result.data.unwrap();
    assert!(services.as_array().is_some());
}

#[test]
fn test_registry_accessor() {
    let accessor = RegistryAccessor::new();
    let mut args = HashMap::new();
    args.insert("key".to_string(), "HKLM\\Software".to_string());

    let result = accessor.execute("read", &args);
    #[cfg(target_os = "windows")]
    assert!(result.success); // Assuming stub returns error or we implement it
    #[cfg(not(target_os = "windows"))]
    assert!(!result.success);
}
