use std::sync::Arc;

use crate::storage::engine::pager::PagerError;
use crate::storage::engine::{BTree, BTreeError, Pager, PagerConfig};

use super::config::UnifiedStoreConfig;
use super::core::UnifiedStore;
use super::errors::StoreError;

impl UnifiedStore {
  pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
    let path = path.as_ref();
    let pager_config = PagerConfig::default();
    let pager = Pager::open(path, pager_config).map_err(|e| {
      StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
      ))
    })?;

    let mut store = Self::with_config(UnifiedStoreConfig::default());
    store.pager = Some(Arc::new(pager));
    store.db_path = Some(path.to_path_buf());
    store
      .format_version
      .store(super::STORE_VERSION_V2, std::sync::atomic::Ordering::SeqCst);

    store.load_from_pages()?;

    Ok(store)
  }

  /// Load data from page-based storage
  ///
  /// Reads the B-tree indices and reconstructs collections from pages.
  fn load_from_pages(&self) -> Result<(), StoreError> {
    let pager = match &self.pager {
      Some(p) => p,
      None => return Ok(()),
    };

    let page_count = pager.page_count();
    if page_count <= 1 {
      return Ok(());
    }

    if let Ok(meta_page) = pager.read_page(1) {
      let data = meta_page.as_bytes();
      let content = &data[crate::storage::engine::HEADER_SIZE..];
      if content.len() >= 4 {
        let mut pos = 0;
        let mut format_version = super::STORE_VERSION_V1;

        if content.len() >= 8 && &content[0..4] == super::METADATA_MAGIC {
          format_version = u32::from_le_bytes([content[4], content[5], content[6], content[7]]);
          pos += 8;
        }

        self.set_format_version(format_version);

        let collection_count = u32::from_le_bytes([
          content[pos],
          content[pos + 1],
          content[pos + 2],
          content[pos + 3],
        ]) as usize;
        pos += 4;

        for _ in 0..collection_count {
          if pos + 4 > content.len() {
            break;
          }

          let name_len = u32::from_le_bytes([
            content[pos],
            content[pos + 1],
            content[pos + 2],
            content[pos + 3],
          ]) as usize;
          pos += 4;

          if pos + name_len + 4 > content.len() {
            break;
          }

          if let Ok(name) = String::from_utf8(content[pos..pos + name_len].to_vec()) {
            pos += name_len;

            let root_page = u32::from_le_bytes([
              content[pos],
              content[pos + 1],
              content[pos + 2],
              content[pos + 3],
            ]);
            pos += 4;

            let _ = self.create_collection(&name);

            if root_page > 0 {
              let btree = BTree::with_root(Arc::clone(pager), root_page);

              if let Ok(mut cursor) = btree.cursor_first() {
                let manager = self.get_collection(&name);
                while let Ok(Some((_, value))) = cursor.next() {
                  if let Ok(entity) = Self::deserialize_entity(&value, self.format_version()) {
                    if let Some(m) = &manager {
                      let id = entity.id;
                      let _ = m.insert(entity.clone());
                      self.register_entity_id(id);
                      if self.config.auto_index_refs {
                        self.index_cross_refs(&entity, &name);
                      }
                    }
                  }
                }
              }

              self.btree_indices.write().unwrap().insert(name, btree);
            }
          } else {
            pos += name_len + 4;
          }
        }

        if format_version >= super::STORE_VERSION_V2 && pos + 4 <= content.len() {
          let cross_ref_count = u32::from_le_bytes([
            content[pos],
            content[pos + 1],
            content[pos + 2],
            content[pos + 3],
          ]) as usize;
          pos += 4;

          for _ in 0..cross_ref_count {
            if pos + 17 > content.len() {
              break;
            }
            let source_id = u64::from_le_bytes([
              content[pos],
              content[pos + 1],
              content[pos + 2],
              content[pos + 3],
              content[pos + 4],
              content[pos + 5],
              content[pos + 6],
              content[pos + 7],
            ]);
            pos += 8;
            let target_id = u64::from_le_bytes([
              content[pos],
              content[pos + 1],
              content[pos + 2],
              content[pos + 3],
              content[pos + 4],
              content[pos + 5],
              content[pos + 6],
              content[pos + 7],
            ]);
            pos += 8;
            let ref_type = super::super::entity::RefType::from_byte(content[pos]);
            pos += 1;

            if pos + 4 > content.len() {
              break;
            }
            let name_len = u32::from_le_bytes([
              content[pos],
              content[pos + 1],
              content[pos + 2],
              content[pos + 3],
            ]) as usize;
            pos += 4;
            if pos + name_len > content.len() {
              break;
            }
            let target_collection =
              String::from_utf8_lossy(&content[pos..pos + name_len]).to_string();
            pos += name_len;

            let source_id = super::super::entity::EntityId::new(source_id);
            let target_id = super::super::entity::EntityId::new(target_id);

            self
              .cross_refs
              .write()
              .unwrap()
              .entry(source_id)
              .or_default()
              .push((target_id, ref_type, target_collection.clone()));

            if let Some((collection, mut entity)) = self.get_any(source_id) {
              let exists = entity.cross_refs.iter().any(|xref| {
                xref.target == target_id
                  && xref.ref_type == ref_type
                  && xref.target_collection == target_collection
              });
              if !exists {
                entity.cross_refs.push(super::super::entity::CrossRef::new(
                  source_id,
                  target_id,
                  target_collection.clone(),
                  ref_type,
                ));
                if let Some(manager) = self.get_collection(&collection) {
                  let _ = manager.update(entity);
                }
              }
            }
          }
        }
      }
    }

    Ok(())
  }

  pub fn persist(&self) -> Result<(), StoreError> {
    let pager = match &self.pager {
      Some(p) => p,
      None => {
        if let Some(path) = &self.db_path {
          return self
            .save_to_file(path)
            .map_err(|e| super::errors::StoreError::Serialization(e.to_string()));
        }
        return Err(super::errors::StoreError::Io(std::io::Error::new(
          std::io::ErrorKind::Other,
          "No pager or path configured for persistence",
        )));
      }
    };

    match pager.read_page(1) {
      Ok(_) => {}
      Err(PagerError::PageNotFound(_)) => {
        let meta_page = pager
          .allocate_page(crate::storage::engine::PageType::Header)
          .map_err(|e| {
            super::errors::StoreError::Io(std::io::Error::new(
              std::io::ErrorKind::Other,
              e.to_string(),
            ))
          })?;
        pager
          .write_page(meta_page.page_id(), meta_page)
          .map_err(|e| {
            super::errors::StoreError::Io(std::io::Error::new(
              std::io::ErrorKind::Other,
              e.to_string(),
            ))
          })?;
      }
      Err(e) => {
        return Err(super::errors::StoreError::Io(std::io::Error::new(
          std::io::ErrorKind::Other,
          e.to_string(),
        )));
      }
    }

    let collections = self.collections.read().unwrap();
    let mut btree_indices = self.btree_indices.write().unwrap();
    let mut collection_roots: Vec<(String, u32)> = Vec::new();

    for (name, manager) in collections.iter() {
      let btree = btree_indices
        .entry(name.clone())
        .or_insert_with(|| BTree::new(Arc::clone(pager)));

      for entity in manager.query_all(|_| true) {
        let key = entity.id.raw().to_le_bytes();
        let value = Self::serialize_entity(&entity, self.format_version());

        match btree.insert(&key, &value) {
          Ok(_) => {}
          Err(BTreeError::DuplicateKey) => {
            let _ = btree.delete(&key);
            let _ = btree.insert(&key, &value);
          }
          Err(e) => {
            return Err(super::errors::StoreError::Io(std::io::Error::new(
              std::io::ErrorKind::Other,
              format!("B-tree insert error: {}", e),
            )));
          }
        }
      }

      collection_roots.push((name.clone(), btree.root_page_id()));
    }

    let mut meta_data = Vec::with_capacity(4096);

    let format_version = super::STORE_VERSION_V2;
    self.set_format_version(format_version);

    meta_data.extend_from_slice(super::METADATA_MAGIC);
    meta_data.extend_from_slice(&format_version.to_le_bytes());
    meta_data.extend_from_slice(&(collection_roots.len() as u32).to_le_bytes());

    for (name, root_page) in &collection_roots {
      meta_data.extend_from_slice(&(name.len() as u32).to_le_bytes());
      meta_data.extend_from_slice(name.as_bytes());
      meta_data.extend_from_slice(&root_page.to_le_bytes());
    }

    let cross_refs = self.cross_refs.read().unwrap();
    let total_refs: usize = cross_refs.values().map(|v| v.len()).sum();
    meta_data.extend_from_slice(&(total_refs as u32).to_le_bytes());
    for (source_id, refs) in cross_refs.iter() {
      for (target_id, ref_type, collection) in refs {
        meta_data.extend_from_slice(&source_id.raw().to_le_bytes());
        meta_data.extend_from_slice(&target_id.raw().to_le_bytes());
        meta_data.push(ref_type.to_byte());
        meta_data.extend_from_slice(&(collection.len() as u32).to_le_bytes());
        meta_data.extend_from_slice(collection.as_bytes());
      }
    }

    let mut meta_page =
      crate::storage::engine::Page::new(crate::storage::engine::PageType::Header, 1);
    let page_data = meta_page.as_bytes_mut();
    let content_start = crate::storage::engine::HEADER_SIZE;
    let copy_len = meta_data.len().min(page_data.len() - content_start);
    page_data[content_start..content_start + copy_len].copy_from_slice(&meta_data[..copy_len]);

    pager.write_page(1, meta_page).map_err(|e| {
      super::errors::StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
      ))
    })?;

    pager.flush().map_err(|e| {
      super::errors::StoreError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
      ))
    })?;

    Ok(())
  }
}
