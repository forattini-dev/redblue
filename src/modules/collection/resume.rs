use crate::modules::collection::persistence::SessionStore;
use std::collections::HashSet;

pub struct ResumeManager {
    store: SessionStore,
}

impl ResumeManager {
    pub fn new(path: &str) -> Self {
        Self {
            store: SessionStore::new(path),
        }
    }

    pub fn mark_processed(&self, url: &str) {
        // We use a simple key prefix "visited:"
        self.store.set(&format!("visited:{}", url), "true");
        let _ = self.store.save();
    }

    pub fn is_processed(&self, url: &str) -> bool {
        self.store.get(&format!("visited:{}", url)).is_some()
    }
    
    pub fn get_processed_urls(&self) -> HashSet<String> {
        // This would require iterating the store, but our simple store doesn't expose iter.
        // For a simple boolean check, `is_processed` is enough.
        HashSet::new()
    }
}
