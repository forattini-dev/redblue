use super::*;

#[test]
fn test_cloud_modern_count() {
  assert!(
    CLOUD_MODERN.len() >= 500,
    "Cloud modern should have at least 500 entries, got {}",
    CLOUD_MODERN.len()
  );
}

#[test]
fn test_pentest_focused_count() {
  assert!(
    PENTEST_FOCUSED.len() >= 400,
    "Pentest focused should have at least 400 entries, got {}",
    PENTEST_FOCUSED.len()
  );
}

#[test]
fn test_common_vhosts_count() {
  assert!(
    COMMON_VHOSTS.len() >= 500,
    "Common vhosts should have at least 500 entries, got {}",
    COMMON_VHOSTS.len()
  );
}

#[test]
fn test_all_unique() {
  let all = VHostWordlist::all();
  let unique: HashSet<_> = all.iter().collect();
  // Allow some duplicates across categories, but should be mostly unique
  assert!(
    unique.len() > all.len() / 2,
    "Too many duplicates in combined wordlist"
  );
}

#[test]
fn test_get_by_category() {
  assert!(!VHostWordlist::get(VHostCategory::CloudModern).is_empty());
  assert!(!VHostWordlist::get(VHostCategory::PentestFocused).is_empty());
  assert!(!VHostWordlist::get(VHostCategory::CommonVHosts).is_empty());
}

#[test]
fn test_counts() {
  assert!(VHostWordlist::count(VHostCategory::CloudModern) > 0);
  assert!(VHostWordlist::count(VHostCategory::PentestFocused) > 0);
  assert!(VHostWordlist::count(VHostCategory::CommonVHosts) > 0);
  assert!(VHostWordlist::total_count() > 0);
}
