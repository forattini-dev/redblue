include!(concat!(env!("OUT_DIR"), "/version_info.rs"));

pub fn current_version() -> &'static str {
  BUILD_VERSION
}
