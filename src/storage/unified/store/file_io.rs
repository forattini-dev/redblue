use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use crate::storage::primitives::encoding::{read_varu32, read_varu64, write_varu32, write_varu64};
use crate::storage::schema::types::Value;

use super::super::entity::{
  CrossRef, EmbeddingSlot, EntityData, EntityId, EntityKind, RefType, UnifiedEntity,
};
use super::config::UnifiedStoreConfig;
use super::errors::StoreError;
use super::UnifiedStore;

/// Read and write UnifiedStore entities in binary format.
impl UnifiedStore {
  /// Load store from binary file
  ///
  /// Binary format:
  /// ```text
  /// [magic: 4 bytes "RDST"]
  /// [version: u32]
  /// [collection_count: varu32]
  /// [collections...]
  /// [cross_ref_count: varu32]
  /// [cross_refs...]
  /// ```
  pub fn load_from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    if buf.len() < 8 {
      return Err(
        format!(
          "INCOMPATIBLE_DB: file is too small to be an RDST store ({} bytes). \
         If this file was not produced by redblue, delete it or point --db at a real scan DB.",
          buf.len()
        )
        .into(),
      );
    }
    if &buf[0..4] != super::STORE_MAGIC {
      let found = String::from_utf8_lossy(&buf[0..4]).into_owned();
      return Err(
        format!(
          "INCOMPATIBLE_DB: magic bytes {:?} (hex {:02X?}) do not match expected RDST. \
         Legacy or foreign file — delete it or point --db at a real scan DB.",
          found,
          &buf[0..4]
        )
        .into(),
      );
    }
    let mut pos = 4;

    let version = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    pos += 4;
    if version != super::STORE_VERSION_V1 && version != super::STORE_VERSION_V2 {
      return Err(
        format!(
          "INCOMPATIBLE_DB: unsupported RDST version {} (supported: {}, {}). \
         Regenerate the DB with `rb ... --persist`.",
          version,
          super::STORE_VERSION_V1,
          super::STORE_VERSION_V2
        )
        .into(),
      );
    }

    let store = Self::with_config(UnifiedStoreConfig::default());
    store.set_format_version(version);

    let collection_count = read_varu32(&buf, &mut pos)
      .map_err(|e| format!("Failed to read collection count: {:?}", e))?;

    for _ in 0..collection_count {
      let name_len = read_varu32(&buf, &mut pos)
        .map_err(|e| format!("Failed to read name length: {:?}", e))? as usize;
      let name = String::from_utf8(buf[pos..pos + name_len].to_vec())
        .map_err(|e| format!("Invalid UTF-8 in collection name: {}", e))?;
      pos += name_len;

      let entity_count =
        read_varu32(&buf, &mut pos).map_err(|e| format!("Failed to read entity count: {:?}", e))?;

      for _ in 0..entity_count {
        let entity = Self::read_entity_binary(&buf, &mut pos, version)?;
        store.insert_auto(&name, entity)?;
      }
    }

    if pos < buf.len() {
      let cross_ref_count = read_varu32(&buf, &mut pos)
        .map_err(|e| format!("Failed to read cross-ref count: {:?}", e))?;

      for _ in 0..cross_ref_count {
        let source_id =
          read_varu64(&buf, &mut pos).map_err(|e| format!("Failed to read source_id: {:?}", e))?;
        let target_id =
          read_varu64(&buf, &mut pos).map_err(|e| format!("Failed to read target_id: {:?}", e))?;
        let ref_type_byte = buf[pos];
        pos += 1;
        let ref_type = RefType::from_byte(ref_type_byte);

        let coll_len = read_varu32(&buf, &mut pos)
          .map_err(|e| format!("Failed to read collection length: {:?}", e))?
          as usize;
        let collection = String::from_utf8(buf[pos..pos + coll_len].to_vec())
          .map_err(|e| format!("Invalid UTF-8 in collection: {}", e))?;
        pos += coll_len;

        let source_collection = store
          .get_any(EntityId::new(source_id))
          .map(|(name, _)| name)
          .unwrap_or_else(|| collection.clone());
        let _ = store.add_cross_ref(
          &source_collection,
          EntityId::new(source_id),
          &collection,
          EntityId::new(target_id),
          ref_type,
          1.0,
        );
      }
    }

    Ok(store)
  }

  /// Save store to binary file
  pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    let mut buf = Vec::new();

    buf.extend_from_slice(super::STORE_MAGIC);
    buf.extend_from_slice(&super::STORE_VERSION_V2.to_le_bytes());

    let collections = self.collections.read().unwrap();
    write_varu32(&mut buf, collections.len() as u32);

    for (name, manager) in collections.iter() {
      write_varu32(&mut buf, name.len() as u32);
      buf.extend_from_slice(name.as_bytes());

      let entities = manager.query_all(|_| true);
      write_varu32(&mut buf, entities.len() as u32);

      for entity in entities {
        Self::write_entity_binary(&mut buf, &entity, super::STORE_VERSION_V2);
      }
    }

    let cross_refs = self.cross_refs.read().unwrap();
    let total_refs: usize = cross_refs.values().map(|v| v.len()).sum();
    write_varu32(&mut buf, total_refs as u32);

    for (source_id, refs) in cross_refs.iter() {
      for (target_id, ref_type, collection) in refs {
        write_varu64(&mut buf, source_id.raw());
        write_varu64(&mut buf, target_id.raw());
        buf.push(ref_type.to_byte());
        write_varu32(&mut buf, collection.len() as u32);
        buf.extend_from_slice(collection.as_bytes());
      }
    }

    self.set_format_version(super::STORE_VERSION_V2);

    writer.write_all(&buf)?;
    writer.flush()?;

    Ok(())
  }

  /// Read entity from binary buffer
  fn read_entity_binary(
    buf: &[u8],
    pos: &mut usize,
    format_version: u32,
  ) -> Result<UnifiedEntity, Box<dyn std::error::Error>> {
    let id = read_varu64(buf, pos).map_err(|e| format!("Failed to read entity id: {:?}", e))?;
    let kind_type = buf[*pos];
    *pos += 1;

    let kind = match kind_type {
      0 => {
        let table_len = Self::read_varu32_safe(buf, pos)?;
        let table = String::from_utf8(buf[*pos..*pos + table_len].to_vec())?;
        *pos += table_len;
        let row_id = Self::read_varu64_safe(buf, pos)?;
        EntityKind::TableRow { table, row_id }
      }
      1 => {
        let label_len = Self::read_varu32_safe(buf, pos)?;
        let label = String::from_utf8(buf[*pos..*pos + label_len].to_vec())?;
        *pos += label_len;
        let node_type_len = Self::read_varu32_safe(buf, pos)?;
        let node_type = String::from_utf8(buf[*pos..*pos + node_type_len].to_vec())?;
        *pos += node_type_len;
        EntityKind::GraphNode { label, node_type }
      }
      2 => {
        let label_len = Self::read_varu32_safe(buf, pos)?;
        let label = String::from_utf8(buf[*pos..*pos + label_len].to_vec())?;
        *pos += label_len;
        let from_node_len = Self::read_varu32_safe(buf, pos)?;
        let from_node = String::from_utf8(buf[*pos..*pos + from_node_len].to_vec())?;
        *pos += from_node_len;
        let to_node_len = Self::read_varu32_safe(buf, pos)?;
        let to_node = String::from_utf8(buf[*pos..*pos + to_node_len].to_vec())?;
        *pos += to_node_len;
        let weight = u32::from_le_bytes([buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]]);
        *pos += 4;
        EntityKind::GraphEdge {
          label,
          from_node,
          to_node,
          weight,
        }
      }
      3 => {
        let collection_len = Self::read_varu32_safe(buf, pos)?;
        let collection = String::from_utf8(buf[*pos..*pos + collection_len].to_vec())?;
        *pos += collection_len;
        EntityKind::Vector { collection }
      }
      _ => return Err(format!("Unknown EntityKind type: {}", kind_type).into()),
    };

    let data_type = buf[*pos];
    *pos += 1;

    let data = match data_type {
      0 => {
        let col_count = Self::read_varu32_safe(buf, pos)?;
        let mut columns = Vec::with_capacity(col_count);
        for _ in 0..col_count {
          columns.push(Self::read_value_binary(buf, pos)?);
        }
        EntityData::Row(super::super::entity::RowData::new(columns))
      }
      1 => {
        let prop_count = Self::read_varu32_safe(buf, pos)?;
        let mut properties = HashMap::new();
        for _ in 0..prop_count {
          let key_len = Self::read_varu32_safe(buf, pos)?;
          let key = String::from_utf8(buf[*pos..*pos + key_len].to_vec())?;
          *pos += key_len;
          let value = Self::read_value_binary(buf, pos)?;
          properties.insert(key, value);
        }
        EntityData::Node(super::super::entity::NodeData::with_properties(properties))
      }
      2 => {
        let weight_bytes = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
        *pos += 4;
        let weight = f32::from_le_bytes(weight_bytes);
        let prop_count = Self::read_varu32_safe(buf, pos)?;
        let mut properties = HashMap::new();
        for _ in 0..prop_count {
          let key_len = Self::read_varu32_safe(buf, pos)?;
          let key = String::from_utf8(buf[*pos..*pos + key_len].to_vec())?;
          *pos += key_len;
          let value = Self::read_value_binary(buf, pos)?;
          properties.insert(key, value);
        }
        let mut edge = super::super::entity::EdgeData::new(weight);
        edge.properties = properties;
        EntityData::Edge(edge)
      }
      3 => {
        let dim = Self::read_varu32_safe(buf, pos)?;
        let mut dense = Vec::with_capacity(dim);
        for _ in 0..dim {
          let bytes = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
          *pos += 4;
          dense.push(f32::from_le_bytes(bytes));
        }
        EntityData::Vector(super::super::entity::VectorData::new(dense))
      }
      _ => return Err(format!("Unknown EntityData type: {}", data_type).into()),
    };

    let created_at = Self::read_varu64_safe(buf, pos)?;
    let updated_at = Self::read_varu64_safe(buf, pos)?;

    let embedding_count = Self::read_varu32_safe(buf, pos)?;
    let mut embeddings = Vec::with_capacity(embedding_count);
    for _ in 0..embedding_count {
      let name_len = Self::read_varu32_safe(buf, pos)?;
      let name = String::from_utf8(buf[*pos..*pos + name_len].to_vec())?;
      *pos += name_len;

      let dim = Self::read_varu32_safe(buf, pos)?;
      let mut vector = Vec::with_capacity(dim);
      for _ in 0..dim {
        let bytes = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
        *pos += 4;
        vector.push(f32::from_le_bytes(bytes));
      }

      let model_len = Self::read_varu32_safe(buf, pos)?;
      let model = String::from_utf8(buf[*pos..*pos + model_len].to_vec())?;
      *pos += model_len;

      embeddings.push(EmbeddingSlot::new(name, vector, model));
    }

    let cross_ref_count = Self::read_varu32_safe(buf, pos)?;
    let mut cross_refs = Vec::with_capacity(cross_ref_count);
    for _ in 0..cross_ref_count {
      let source = Self::read_varu64_safe(buf, pos)?;
      let target = Self::read_varu64_safe(buf, pos)?;
      let ref_type_byte = buf[*pos];
      *pos += 1;
      let (target_collection, weight, created_at) = if format_version >= super::STORE_VERSION_V2 {
        let coll_len = Self::read_varu32_safe(buf, pos)?;
        let collection = String::from_utf8(buf[*pos..*pos + coll_len].to_vec())?;
        *pos += coll_len;
        let weight_bytes = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
        *pos += 4;
        let weight = f32::from_le_bytes(weight_bytes);
        let created_at = Self::read_varu64_safe(buf, pos)?;
        (collection, weight, created_at)
      } else {
        (String::new(), 1.0, 0)
      };

      let mut cross_ref = CrossRef::new(
        EntityId::new(source),
        EntityId::new(target),
        target_collection,
        RefType::from_byte(ref_type_byte),
      );
      cross_ref.weight = weight;
      cross_ref.created_at = created_at;
      cross_refs.push(cross_ref);
    }

    let sequence_id = Self::read_varu64_safe(buf, pos)?;

    let entity = UnifiedEntity {
      id: EntityId::new(id),
      kind,
      created_at,
      updated_at,
      data,
      embeddings,
      cross_refs,
      sequence_id,
    };

    Ok(entity)
  }

  fn read_varu32_safe(buf: &[u8], pos: &mut usize) -> Result<usize, Box<dyn std::error::Error>> {
    read_varu32(buf, pos)
      .map(|v| v as usize)
      .map_err(|e| format!("Decode error: {:?}", e).into())
  }

  fn read_varu64_safe(buf: &[u8], pos: &mut usize) -> Result<u64, Box<dyn std::error::Error>> {
    read_varu64(buf, pos).map_err(|e| format!("Decode error: {:?}", e).into())
  }

  /// Read a Value from binary buffer
  fn read_value_binary(buf: &[u8], pos: &mut usize) -> Result<Value, Box<dyn std::error::Error>> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let type_byte = buf[*pos];
    *pos += 1;

    Ok(match type_byte {
      0 => Value::Null,
      1 => {
        let b = buf[*pos] != 0;
        *pos += 1;
        Value::Boolean(b)
      }
      2 => {
        let val = i64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::Integer(val)
      }
      3 => {
        let val = u64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::UnsignedInteger(val)
      }
      4 => {
        let val = f64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::Float(val)
      }
      5 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let s = String::from_utf8(buf[*pos..*pos + len].to_vec())?;
        *pos += len;
        Value::Text(s)
      }
      6 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let bytes = buf[*pos..*pos + len].to_vec();
        *pos += len;
        Value::Blob(bytes)
      }
      7 => {
        let val = i64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::Timestamp(val)
      }
      8 => {
        let val = i64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::Duration(val)
      }
      9 => {
        let version = buf[*pos];
        *pos += 1;
        if version == 4 {
          let octets = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
          *pos += 4;
          Value::IpAddr(IpAddr::V4(Ipv4Addr::from(octets)))
        } else {
          let mut octets = [0u8; 16];
          octets.copy_from_slice(&buf[*pos..*pos + 16]);
          *pos += 16;
          Value::IpAddr(IpAddr::V6(Ipv6Addr::from(octets)))
        }
      }
      10 => {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&buf[*pos..*pos + 6]);
        *pos += 6;
        Value::MacAddr(mac)
      }
      11 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let mut vector = Vec::with_capacity(len);
        for _ in 0..len {
          let bytes = [buf[*pos], buf[*pos + 1], buf[*pos + 2], buf[*pos + 3]];
          *pos += 4;
          vector.push(f32::from_le_bytes(bytes));
        }
        Value::Vector(vector)
      }
      12 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let bytes = buf[*pos..*pos + len].to_vec();
        *pos += len;
        Value::Json(bytes)
      }
      13 => {
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[*pos..*pos + 16]);
        *pos += 16;
        Value::Uuid(uuid)
      }
      14 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let s = String::from_utf8(buf[*pos..*pos + len].to_vec())?;
        *pos += len;
        Value::NodeRef(s)
      }
      15 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let s = String::from_utf8(buf[*pos..*pos + len].to_vec())?;
        *pos += len;
        Value::EdgeRef(s)
      }
      16 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let s = String::from_utf8(buf[*pos..*pos + len].to_vec())?;
        *pos += len;
        let id = u64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::VectorRef(s, id)
      }
      17 => {
        let len = Self::read_varu32_safe(buf, pos)?;
        let s = String::from_utf8(buf[*pos..*pos + len].to_vec())?;
        *pos += len;
        let id = u64::from_le_bytes([
          buf[*pos],
          buf[*pos + 1],
          buf[*pos + 2],
          buf[*pos + 3],
          buf[*pos + 4],
          buf[*pos + 5],
          buf[*pos + 6],
          buf[*pos + 7],
        ]);
        *pos += 8;
        Value::RowRef(s, id)
      }
      _ => return Err(format!("Unknown Value type: {}", type_byte).into()),
    })
  }

  /// Write a Value to binary buffer
  fn write_value_binary(buf: &mut Vec<u8>, value: &Value) {
    use std::net::IpAddr;

    match value {
      Value::Null => buf.push(0),
      Value::Boolean(b) => {
        buf.push(1);
        buf.push(if *b { 1 } else { 0 });
      }
      Value::Integer(i) => {
        buf.push(2);
        buf.extend_from_slice(&i.to_le_bytes());
      }
      Value::UnsignedInteger(u) => {
        buf.push(3);
        buf.extend_from_slice(&u.to_le_bytes());
      }
      Value::Float(f) => {
        buf.push(4);
        buf.extend_from_slice(&f.to_le_bytes());
      }
      Value::Text(s) => {
        buf.push(5);
        write_varu32(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
      }
      Value::Blob(bytes) => {
        buf.push(6);
        write_varu32(buf, bytes.len() as u32);
        buf.extend_from_slice(bytes);
      }
      Value::Timestamp(t) => {
        buf.push(7);
        buf.extend_from_slice(&t.to_le_bytes());
      }
      Value::Duration(d) => {
        buf.push(8);
        buf.extend_from_slice(&d.to_le_bytes());
      }
      Value::IpAddr(ip) => {
        buf.push(9);
        match ip {
          IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
          }
          IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
          }
        }
      }
      Value::MacAddr(mac) => {
        buf.push(10);
        buf.extend_from_slice(mac);
      }
      Value::Vector(vec) => {
        buf.push(11);
        write_varu32(buf, vec.len() as u32);
        for f in vec {
          buf.extend_from_slice(&f.to_le_bytes());
        }
      }
      Value::Json(bytes) => {
        buf.push(12);
        write_varu32(buf, bytes.len() as u32);
        buf.extend_from_slice(bytes);
      }
      Value::Uuid(uuid) => {
        buf.push(13);
        buf.extend_from_slice(uuid);
      }
      Value::NodeRef(s) => {
        buf.push(14);
        write_varu32(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
      }
      Value::EdgeRef(s) => {
        buf.push(15);
        write_varu32(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
      }
      Value::VectorRef(s, id) => {
        buf.push(16);
        write_varu32(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
        buf.extend_from_slice(&id.to_le_bytes());
      }
      Value::RowRef(s, id) => {
        buf.push(17);
        write_varu32(buf, s.len() as u32);
        buf.extend_from_slice(s.as_bytes());
        buf.extend_from_slice(&id.to_le_bytes());
      }
    }
  }

  /// Write entity to binary buffer
  fn write_entity_binary(buf: &mut Vec<u8>, entity: &UnifiedEntity, format_version: u32) {
    write_varu64(buf, entity.id.raw());

    match &entity.kind {
      EntityKind::TableRow { table, row_id } => {
        buf.push(0);
        write_varu32(buf, table.len() as u32);
        buf.extend_from_slice(table.as_bytes());
        write_varu64(buf, *row_id);
      }
      EntityKind::GraphNode { label, node_type } => {
        buf.push(1);
        write_varu32(buf, label.len() as u32);
        buf.extend_from_slice(label.as_bytes());
        write_varu32(buf, node_type.len() as u32);
        buf.extend_from_slice(node_type.as_bytes());
      }
      EntityKind::GraphEdge {
        label,
        from_node,
        to_node,
        weight,
      } => {
        buf.push(2);
        write_varu32(buf, label.len() as u32);
        buf.extend_from_slice(label.as_bytes());
        write_varu32(buf, from_node.len() as u32);
        buf.extend_from_slice(from_node.as_bytes());
        write_varu32(buf, to_node.len() as u32);
        buf.extend_from_slice(to_node.as_bytes());
        buf.extend_from_slice(&weight.to_le_bytes());
      }
      EntityKind::Vector { collection } => {
        buf.push(3);
        write_varu32(buf, collection.len() as u32);
        buf.extend_from_slice(collection.as_bytes());
      }
    }

    match &entity.data {
      EntityData::Row(row) => {
        buf.push(0);
        write_varu32(buf, row.columns.len() as u32);
        for col in &row.columns {
          Self::write_value_binary(buf, col);
        }
      }
      EntityData::Node(node) => {
        buf.push(1);
        write_varu32(buf, node.properties.len() as u32);
        for (key, value) in &node.properties {
          write_varu32(buf, key.len() as u32);
          buf.extend_from_slice(key.as_bytes());
          Self::write_value_binary(buf, value);
        }
      }
      EntityData::Edge(edge) => {
        buf.push(2);
        buf.extend_from_slice(&edge.weight.to_le_bytes());
        write_varu32(buf, edge.properties.len() as u32);
        for (key, value) in &edge.properties {
          write_varu32(buf, key.len() as u32);
          buf.extend_from_slice(key.as_bytes());
          Self::write_value_binary(buf, value);
        }
      }
      EntityData::Vector(vec) => {
        buf.push(3);
        write_varu32(buf, vec.dense.len() as u32);
        for f in &vec.dense {
          buf.extend_from_slice(&f.to_le_bytes());
        }
      }
    }

    write_varu64(buf, entity.created_at);
    write_varu64(buf, entity.updated_at);

    write_varu32(buf, entity.embeddings.len() as u32);
    for emb in &entity.embeddings {
      write_varu32(buf, emb.name.len() as u32);
      buf.extend_from_slice(emb.name.as_bytes());
      write_varu32(buf, emb.vector.len() as u32);
      for f in &emb.vector {
        buf.extend_from_slice(&f.to_le_bytes());
      }
      write_varu32(buf, emb.model.len() as u32);
      buf.extend_from_slice(emb.model.as_bytes());
    }

    write_varu32(buf, entity.cross_refs.len() as u32);
    for cross_ref in &entity.cross_refs {
      write_varu64(buf, cross_ref.source.raw());
      write_varu64(buf, cross_ref.target.raw());
      buf.push(cross_ref.ref_type.to_byte());
      if format_version >= super::STORE_VERSION_V2 {
        write_varu32(buf, cross_ref.target_collection.len() as u32);
        buf.extend_from_slice(cross_ref.target_collection.as_bytes());
        buf.extend_from_slice(&cross_ref.weight.to_le_bytes());
        write_varu64(buf, cross_ref.created_at);
      }
    }

    write_varu64(buf, entity.sequence_id);
  }

  /// Deserialize an entity from binary bytes
  pub(crate) fn deserialize_entity(
    data: &[u8],
    format_version: u32,
  ) -> Result<UnifiedEntity, StoreError> {
    let mut pos = 0;
    Self::read_entity_binary(data, &mut pos, format_version)
      .map_err(|e| StoreError::Serialization(e.to_string()))
  }

  /// Serialize an entity to binary bytes
  pub(crate) fn serialize_entity(entity: &UnifiedEntity, format_version: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    Self::write_entity_binary(&mut buf, entity, format_version);
    buf
  }
}
