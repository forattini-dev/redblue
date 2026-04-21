use super::*;

impl JsonEncode for PlaybookPhase {
  fn to_json_value(&self) -> Value {
    let s = match self {
      PlaybookPhase::Recon => "Recon",
      PlaybookPhase::InitialAccess => "InitialAccess",
      PlaybookPhase::Execution => "Execution",
      PlaybookPhase::Persistence => "Persistence",
      PlaybookPhase::PrivilegeEscalation => "PrivilegeEscalation",
      PlaybookPhase::DefenseEvasion => "DefenseEvasion",
      PlaybookPhase::CredentialAccess => "CredentialAccess",
      PlaybookPhase::Discovery => "Discovery",
      PlaybookPhase::LateralMovement => "LateralMovement",
      PlaybookPhase::Collection => "Collection",
      PlaybookPhase::C2 => "C2",
      PlaybookPhase::Exfiltration => "Exfiltration",
      PlaybookPhase::Impact => "Impact",
      PlaybookPhase::Cleanup => "Cleanup",
    };
    Value::String(s.to_string())
  }
}

impl JsonDecode for PlaybookPhase {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let s = String::from_json_value(value)?;
    let key = s
      .to_lowercase()
      .replace('&', "and")
      .replace(' ', "")
      .replace('-', "");
    match key.as_str() {
      "recon" | "reconnaissance" => Ok(PlaybookPhase::Recon),
      "initialaccess" => Ok(PlaybookPhase::InitialAccess),
      "execution" => Ok(PlaybookPhase::Execution),
      "persistence" => Ok(PlaybookPhase::Persistence),
      "privilegeescalation" => Ok(PlaybookPhase::PrivilegeEscalation),
      "defenseevasion" => Ok(PlaybookPhase::DefenseEvasion),
      "credentialaccess" => Ok(PlaybookPhase::CredentialAccess),
      "discovery" => Ok(PlaybookPhase::Discovery),
      "lateralmovement" => Ok(PlaybookPhase::LateralMovement),
      "collection" => Ok(PlaybookPhase::Collection),
      "c2" | "commandandcontrol" | "commandcontrol" => Ok(PlaybookPhase::C2),
      "exfiltration" => Ok(PlaybookPhase::Exfiltration),
      "impact" => Ok(PlaybookPhase::Impact),
      "cleanup" => Ok(PlaybookPhase::Cleanup),
      _ => Err("invalid playbook phase".to_string()),
    }
  }
}

impl JsonEncode for TargetType {
  fn to_json_value(&self) -> Value {
    let s = match self {
      TargetType::Host => "Host",
      TargetType::WebApp => "WebApp",
      TargetType::Network => "Network",
      TargetType::Domain => "Domain",
      TargetType::Cloud => "Cloud",
      TargetType::Internal => "Internal",
      TargetType::Container => "Container",
      TargetType::Api => "Api",
    };
    Value::String(s.to_string())
  }
}

impl JsonDecode for TargetType {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let s = String::from_json_value(value)?;
    let key = normalize_key(&s);
    match key.as_str() {
      "host" => Ok(TargetType::Host),
      "webapp" | "webapplication" => Ok(TargetType::WebApp),
      "network" => Ok(TargetType::Network),
      "domain" => Ok(TargetType::Domain),
      "cloud" => Ok(TargetType::Cloud),
      "internal" | "internalnetwork" => Ok(TargetType::Internal),
      "container" => Ok(TargetType::Container),
      "api" => Ok(TargetType::Api),
      _ => Err("invalid target type".to_string()),
    }
  }
}

impl JsonEncode for TargetOS {
  fn to_json_value(&self) -> Value {
    let s = match self {
      TargetOS::Any => "Any",
      TargetOS::Linux => "Linux",
      TargetOS::Windows => "Windows",
      TargetOS::MacOS => "MacOS",
      TargetOS::FreeBSD => "FreeBSD",
      TargetOS::Android => "Android",
      TargetOS::IOS => "IOS",
    };
    Value::String(s.to_string())
  }
}

impl JsonDecode for TargetOS {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let s = String::from_json_value(value)?;
    let key = normalize_key(&s);
    match key.as_str() {
      "any" => Ok(TargetOS::Any),
      "linux" => Ok(TargetOS::Linux),
      "windows" => Ok(TargetOS::Windows),
      "macos" | "mac" => Ok(TargetOS::MacOS),
      "freebsd" => Ok(TargetOS::FreeBSD),
      "android" => Ok(TargetOS::Android),
      "ios" => Ok(TargetOS::IOS),
      _ => Err("invalid target os".to_string()),
    }
  }
}

impl JsonEncode for RiskLevel {
  fn to_json_value(&self) -> Value {
    let s = match self {
      RiskLevel::Passive => "Passive",
      RiskLevel::Low => "Low",
      RiskLevel::Medium => "Medium",
      RiskLevel::High => "High",
      RiskLevel::Critical => "Critical",
    };
    Value::String(s.to_string())
  }
}

impl JsonDecode for RiskLevel {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let s = String::from_json_value(value)?;
    match s.to_lowercase().as_str() {
      "passive" => Ok(RiskLevel::Passive),
      "low" => Ok(RiskLevel::Low),
      "medium" => Ok(RiskLevel::Medium),
      "high" => Ok(RiskLevel::High),
      "critical" => Ok(RiskLevel::Critical),
      _ => Err("invalid risk level".to_string()),
    }
  }
}

impl JsonEncode for EvidenceType {
  fn to_json_value(&self) -> Value {
    let s = match self {
      EvidenceType::Credentials => "Credentials",
      EvidenceType::Vulnerability => "Vulnerability",
      EvidenceType::Screenshot => "Screenshot",
      EvidenceType::NetworkCapture => "NetworkCapture",
      EvidenceType::FileArtifact => "FileArtifact",
      EvidenceType::CommandOutput => "CommandOutput",
      EvidenceType::SystemInfo => "SystemInfo",
      EvidenceType::NetworkMap => "NetworkMap",
      EvidenceType::SessionData => "SessionData",
    };
    Value::String(s.to_string())
  }
}

impl JsonDecode for EvidenceType {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let s = String::from_json_value(value)?;
    let key = normalize_key(&s);
    match key.as_str() {
      "credentials" => Ok(EvidenceType::Credentials),
      "vulnerability" => Ok(EvidenceType::Vulnerability),
      "screenshot" => Ok(EvidenceType::Screenshot),
      "networkcapture" => Ok(EvidenceType::NetworkCapture),
      "fileartifact" => Ok(EvidenceType::FileArtifact),
      "commandoutput" => Ok(EvidenceType::CommandOutput),
      "systeminfo" => Ok(EvidenceType::SystemInfo),
      "networkmap" => Ok(EvidenceType::NetworkMap),
      "sessiondata" => Ok(EvidenceType::SessionData),
      _ => Err("invalid evidence type".to_string()),
    }
  }
}

impl JsonEncode for StepFailureAction {
  fn to_json_value(&self) -> Value {
    match self {
      StepFailureAction::Continue => Value::String("Continue".to_string()),
      StepFailureAction::Abort => Value::String("Abort".to_string()),
      StepFailureAction::SkipDependents => Value::String("SkipDependents".to_string()),
      StepFailureAction::AskUser => Value::String("AskUser".to_string()),
      StepFailureAction::Retry { max_attempts } => {
        let mut inner = Map::new();
        inner.insert("max_attempts".to_string(), max_attempts.to_json_value());
        tagged_value("Retry", Value::Object(inner))
      }
    }
  }
}

impl JsonDecode for StepFailureAction {
  fn from_json_value(value: Value) -> Result<Self, String> {
    match value {
      Value::String(s) => {
        let key = normalize_key(&s);
        match key.as_str() {
          "continue" => Ok(StepFailureAction::Continue),
          "abort" => Ok(StepFailureAction::Abort),
          "skipdependents" => Ok(StepFailureAction::SkipDependents),
          "askuser" => Ok(StepFailureAction::AskUser),
          _ => Err("invalid step failure action".to_string()),
        }
      }
      Value::Object(map) if map.len() == 1 => {
        let (key, value) = map.into_iter().next().unwrap();
        match key.as_str() {
          "Retry" | "retry" => match value {
            Value::Object(inner) => Ok(StepFailureAction::Retry {
              max_attempts: u8::from_json_value(map_get_value(&inner, "max_attempts"))?,
            }),
            other => Ok(StepFailureAction::Retry {
              max_attempts: u8::from_json_value(other)?,
            }),
          },
          _ => Err("invalid step failure action".to_string()),
        }
      }
      _ => Err("invalid step failure action".to_string()),
    }
  }
}

impl JsonEncode for StepCondition {
  fn to_json_value(&self) -> Value {
    match self {
      StepCondition::Always => Value::String("Always".to_string()),
      StepCondition::OnSuccess(step) => tagged_value("OnSuccess", step.to_json_value()),
      StepCondition::OnFailure(step) => tagged_value("OnFailure", step.to_json_value()),
      StepCondition::OnEvidence(evidence) => tagged_value("OnEvidence", evidence.to_json_value()),
      StepCondition::Custom(expr) => tagged_value("Custom", expr.to_json_value()),
      StepCondition::OnPreviousAction(action) => {
        tagged_value("OnPreviousAction", action.to_json_value())
      }
      StepCondition::IfNotScanned => Value::String("IfNotScanned".to_string()),
      StepCondition::IfHasVulnerabilities => Value::String("IfHasVulnerabilities".to_string()),
    }
  }
}

impl JsonDecode for StepCondition {
  fn from_json_value(value: Value) -> Result<Self, String> {
    match value {
      Value::String(s) => {
        let key = normalize_key(&s);
        match key.as_str() {
          "always" => Ok(StepCondition::Always),
          "ifnotscanned" => Ok(StepCondition::IfNotScanned),
          "ifhasvulnerabilities" => Ok(StepCondition::IfHasVulnerabilities),
          _ => Err("invalid step condition".to_string()),
        }
      }
      Value::Object(map) if map.len() == 1 => {
        let (key, value) = map.into_iter().next().unwrap();
        match key.as_str() {
          "OnSuccess" | "onsuccess" => Ok(StepCondition::OnSuccess(u8::from_json_value(value)?)),
          "OnFailure" | "onfailure" => Ok(StepCondition::OnFailure(u8::from_json_value(value)?)),
          "OnEvidence" | "onevidence" => Ok(StepCondition::OnEvidence(
            EvidenceType::from_json_value(value)?,
          )),
          "Custom" | "custom" => Ok(StepCondition::Custom(String::from_json_value(value)?)),
          "OnPreviousAction" | "onpreviousaction" => Ok(StepCondition::OnPreviousAction(
            String::from_json_value(value)?,
          )),
          _ => Err("invalid step condition".to_string()),
        }
      }
      _ => Err("invalid step condition".to_string()),
    }
  }
}

impl JsonEncode for PlaybookMetadata {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("id".to_string(), self.id.to_json_value());
    map.insert("name".to_string(), self.name.to_json_value());
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("objective".to_string(), self.objective.to_json_value());
    map.insert("author".to_string(), self.author.to_json_value());
    map.insert("version".to_string(), self.version.to_json_value());
    map.insert(
      "target_types".to_string(),
      self.target_types.to_json_value(),
    );
    map.insert("target_os".to_string(), self.target_os.to_json_value());
    map.insert("risk_level".to_string(), self.risk_level.to_json_value());
    map.insert(
      "estimated_duration".to_string(),
      self.estimated_duration.to_json_value(),
    );
    map.insert("tags".to_string(), self.tags.to_json_value());
    map.insert(
      "mitre_techniques".to_string(),
      self.mitre_techniques.to_json_value(),
    );
    Value::Object(map)
  }
}

impl JsonDecode for PlaybookMetadata {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    let mut meta = PlaybookMetadata::default();

    if let Ok(id) = String::from_json_value(map_get_value(&map, "id")) {
      meta.id = id;
    }
    if let Ok(name) = String::from_json_value(map_get_value(&map, "name")) {
      meta.name = name;
    }
    if map.contains_key("description") {
      meta.description = String::from_json_value(map_get_value(&map, "description"))?;
    }
    if map.contains_key("objective") {
      meta.objective = String::from_json_value(map_get_value(&map, "objective"))?;
    }
    if map.contains_key("author") {
      meta.author = String::from_json_value(map_get_value(&map, "author"))?;
    }
    if map.contains_key("version") {
      meta.version = String::from_json_value(map_get_value(&map, "version"))?;
    }
    if map.contains_key("target_types") {
      meta.target_types = Vec::<TargetType>::from_json_value(map_get_value(&map, "target_types"))?;
    }
    if map.contains_key("target_os") {
      meta.target_os = Vec::<TargetOS>::from_json_value(map_get_value(&map, "target_os"))?;
    }
    if map.contains_key("risk_level") {
      meta.risk_level = RiskLevel::from_json_value(map_get_value(&map, "risk_level"))?;
    }
    if map.contains_key("estimated_duration") {
      meta.estimated_duration = String::from_json_value(map_get_value(&map, "estimated_duration"))?;
    }
    if map.contains_key("tags") {
      meta.tags = Vec::<String>::from_json_value(map_get_value(&map, "tags"))?;
    }
    if map.contains_key("mitre_techniques") {
      meta.mitre_techniques =
        Vec::<String>::from_json_value(map_get_value(&map, "mitre_techniques"))?;
    }

    if meta.id.is_empty() || meta.name.is_empty() {
      return Err("playbook metadata missing id or name".to_string());
    }
    Ok(meta)
  }
}

impl JsonEncode for PreCondition {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("check".to_string(), self.check.to_json_value());
    map.insert("required".to_string(), self.required.to_json_value());
    map.insert("notes".to_string(), self.notes.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for PreCondition {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      description: String::from_json_value(map_get_value(&map, "description"))?,
      check: Option::<String>::from_json_value(map_get_value(&map, "check"))?,
      required: map_get_bool(&map, "required", true)?,
      notes: Option::<String>::from_json_value(map_get_value(&map, "notes"))?,
    })
  }
}

impl JsonEncode for PlaybookStep {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("number".to_string(), self.number.to_json_value());
    map.insert("phase".to_string(), self.phase.to_json_value());
    map.insert("name".to_string(), self.name.to_json_value());
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("scripts".to_string(), self.scripts.to_json_value());
    map.insert("commands".to_string(), self.commands.to_json_value());
    map.insert(
      "manual_instructions".to_string(),
      self.manual_instructions.to_json_value(),
    );
    map.insert(
      "success_criteria".to_string(),
      self.success_criteria.to_json_value(),
    );
    map.insert("on_failure".to_string(), self.on_failure.to_json_value());
    map.insert("depends_on".to_string(), self.depends_on.to_json_value());
    map.insert("optional".to_string(), self.optional.to_json_value());
    map.insert("timeout".to_string(), duration_to_value(self.timeout));
    map.insert(
      "mitre_technique".to_string(),
      self.mitre_technique.to_json_value(),
    );
    map.insert(
      "mitre_subtechnique".to_string(),
      self.mitre_subtechnique.to_json_value(),
    );
    map.insert(
      "parallel_group".to_string(),
      self.parallel_group.to_json_value(),
    );
    map.insert("condition".to_string(), self.condition.to_json_value());
    map.insert(
      "evidence_type".to_string(),
      self.evidence_type.to_json_value(),
    );
    Value::Object(map)
  }
}

impl JsonDecode for PlaybookStep {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    let number = u8::from_json_value(map_get_value(&map, "number"))?;
    let phase = PlaybookPhase::from_json_value(map_get_value(&map, "phase"))?;
    let name = String::from_json_value(map_get_value(&map, "name"))?;
    let mut step = PlaybookStep::new(number, phase, &name);

    if map.contains_key("description") {
      step.description = String::from_json_value(map_get_value(&map, "description"))?;
    }
    if map.contains_key("scripts") {
      step.scripts = Vec::<String>::from_json_value(map_get_array(&map, "scripts"))?;
    }
    if map.contains_key("commands") {
      step.commands = Vec::<String>::from_json_value(map_get_array(&map, "commands"))?;
    }
    if map.contains_key("manual_instructions") {
      step.manual_instructions =
        Option::<String>::from_json_value(map_get_value(&map, "manual_instructions"))?;
    }
    if map.contains_key("success_criteria") {
      step.success_criteria =
        Vec::<String>::from_json_value(map_get_array(&map, "success_criteria"))?;
    }
    if map.contains_key("on_failure") {
      step.on_failure = StepFailureAction::from_json_value(map_get_value(&map, "on_failure"))?;
    }
    if map.contains_key("depends_on") {
      step.depends_on = Vec::<u8>::from_json_value(map_get_array(&map, "depends_on"))?;
    }
    step.optional = map_get_bool(&map, "optional", step.optional)?;
    step.timeout = duration_from_value(map_get_value(&map, "timeout"), step.timeout)?;
    if map.contains_key("mitre_technique") {
      step.mitre_technique =
        Option::<String>::from_json_value(map_get_value(&map, "mitre_technique"))?;
    }
    if map.contains_key("mitre_subtechnique") {
      step.mitre_subtechnique =
        Option::<String>::from_json_value(map_get_value(&map, "mitre_subtechnique"))?;
    }
    if map.contains_key("parallel_group") {
      step.parallel_group = Option::<u8>::from_json_value(map_get_value(&map, "parallel_group"))?;
    }
    if map.contains_key("condition") {
      step.condition = StepCondition::from_json_value(map_get_value(&map, "condition"))?;
    }
    if map.contains_key("evidence_type") {
      step.evidence_type =
        Option::<EvidenceType>::from_json_value(map_get_value(&map, "evidence_type"))?;
    }

    Ok(step)
  }
}

impl JsonEncode for ExpectedEvidence {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("location".to_string(), self.location.to_json_value());
    map.insert("indicators".to_string(), self.indicators.to_json_value());
    map.insert("severity".to_string(), self.severity.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for ExpectedEvidence {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    let description = String::from_json_value(map_get_value(&map, "description"))?;
    let mut evidence = ExpectedEvidence::new(&description);
    if map.contains_key("location") {
      evidence.location = String::from_json_value(map_get_value(&map, "location"))?;
    }
    if map.contains_key("indicators") {
      evidence.indicators = Vec::<String>::from_json_value(map_get_array(&map, "indicators"))?;
    }
    if map.contains_key("severity") {
      evidence.severity = FindingSeverity::from_json_value(map_get_value(&map, "severity"))?;
    }
    Ok(evidence)
  }
}

impl JsonEncode for FailedControl {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("name".to_string(), self.name.to_json_value());
    map.insert("reason".to_string(), self.reason.to_json_value());
    map.insert("remediation".to_string(), self.remediation.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for FailedControl {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      name: String::from_json_value(map_get_value(&map, "name"))?,
      reason: String::from_json_value(map_get_value(&map, "reason"))?,
      remediation: String::from_json_value(map_get_value(&map, "remediation")).unwrap_or_default(),
    })
  }
}

impl JsonEncode for PlaybookVariation {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("name".to_string(), self.name.to_json_value());
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("use_when".to_string(), self.use_when.to_json_value());
    map.insert("command".to_string(), self.command.to_json_value());
    map.insert(
      "different_steps".to_string(),
      self.different_steps.to_json_value(),
    );
    map.insert("notes".to_string(), self.notes.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for PlaybookVariation {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    let name = String::from_json_value(map_get_value(&map, "name"))?;
    let mut variation = PlaybookVariation::new(&name, "");
    if map.contains_key("description") {
      variation.description = String::from_json_value(map_get_value(&map, "description"))?;
    }
    if map.contains_key("use_when") {
      variation.use_when = String::from_json_value(map_get_value(&map, "use_when"))?;
    }
    if map.contains_key("command") {
      variation.command = Option::<String>::from_json_value(map_get_value(&map, "command"))?;
    }
    if map.contains_key("different_steps") {
      variation.different_steps =
        Vec::<PlaybookStep>::from_json_value(map_get_array(&map, "different_steps"))?;
    }
    if map.contains_key("notes") {
      variation.notes = Option::<String>::from_json_value(map_get_value(&map, "notes"))?;
    }
    Ok(variation)
  }
}

impl JsonEncode for Playbook {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("metadata".to_string(), self.metadata.to_json_value());
    map.insert(
      "preconditions".to_string(),
      self.preconditions.to_json_value(),
    );
    map.insert("steps".to_string(), self.steps.to_json_value());
    map.insert("evidence".to_string(), self.evidence.to_json_value());
    map.insert(
      "failed_controls".to_string(),
      self.failed_controls.to_json_value(),
    );
    map.insert("variations".to_string(), self.variations.to_json_value());
    map.insert("kill_chain".to_string(), self.kill_chain.to_json_value());
    map.insert("on_success".to_string(), self.on_success.to_json_value());
    map.insert("on_failure".to_string(), self.on_failure.to_json_value());
    map.insert("assertions".to_string(), self.assertions.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for Playbook {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    let metadata = PlaybookMetadata::from_json_value(map_get_value(&map, "metadata"))?;
    Ok(Self {
      metadata,
      preconditions: Vec::<PreCondition>::from_json_value(map_get_array(&map, "preconditions"))
        .unwrap_or_default(),
      steps: Vec::<PlaybookStep>::from_json_value(map_get_array(&map, "steps")).unwrap_or_default(),
      evidence: Vec::<ExpectedEvidence>::from_json_value(map_get_array(&map, "evidence"))
        .unwrap_or_default(),
      failed_controls: Vec::<FailedControl>::from_json_value(map_get_array(
        &map,
        "failed_controls",
      ))
      .unwrap_or_default(),
      variations: Vec::<PlaybookVariation>::from_json_value(map_get_array(&map, "variations"))
        .unwrap_or_default(),
      kill_chain: Vec::<KillChainPhase>::from_json_value(map_get_array(&map, "kill_chain"))
        .unwrap_or_default(),
      on_success: Option::<String>::from_json_value(map_get_value(&map, "on_success"))?,
      on_failure: Option::<String>::from_json_value(map_get_value(&map, "on_failure"))?,
      assertions: Vec::<Assertion>::from_json_value(map_get_array(&map, "assertions"))
        .unwrap_or_default(),
    })
  }
}

impl JsonEncode for KillChainPhase {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("name".to_string(), self.name.to_json_value());
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert(
      "step_numbers".to_string(),
      self.step_numbers.to_json_value(),
    );
    Value::Object(map)
  }
}

impl JsonDecode for KillChainPhase {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      name: String::from_json_value(map_get_value(&map, "name"))?,
      description: String::from_json_value(map_get_value(&map, "description"))?,
      step_numbers: Vec::<u8>::from_json_value(map_get_array(&map, "step_numbers"))
        .unwrap_or_default(),
    })
  }
}

impl JsonEncode for PlaybookContext {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("target".to_string(), self.target.to_json_value());
    map.insert(
      "additional_targets".to_string(),
      self.additional_targets.to_json_value(),
    );
    map.insert("session_id".to_string(), self.session_id.to_json_value());
    map.insert("args".to_string(), self.args.to_json_value());
    map.insert(
      "gathered_data".to_string(),
      self.gathered_data.to_json_value(),
    );
    map.insert(
      "allow_intrusive".to_string(),
      self.allow_intrusive.to_json_value(),
    );
    map.insert(
      "step_timeout".to_string(),
      duration_to_value(self.step_timeout),
    );
    map.insert(
      "total_timeout".to_string(),
      duration_to_value(self.total_timeout),
    );
    map.insert("verbosity".to_string(), self.verbosity.to_json_value());
    map.insert("dry_run".to_string(), self.dry_run.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for PlaybookContext {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    let target = String::from_json_value(map_get_value(&map, "target"))?;
    let session_id = match map.get("session_id") {
      Some(value) => String::from_json_value(value.clone())?,
      None => Uuid::new_v4().to_string(),
    };
    Ok(Self {
      target,
      additional_targets: Vec::<String>::from_json_value(map_get_array(&map, "additional_targets"))
        .unwrap_or_default(),
      session_id,
      args: HashMap::<String, String>::from_json_value(map_get_value(&map, "args"))
        .unwrap_or_default(),
      gathered_data: HashMap::<String, String>::from_json_value(map_get_value(
        &map,
        "gathered_data",
      ))
      .unwrap_or_default(),
      allow_intrusive: map_get_bool(&map, "allow_intrusive", false)?,
      step_timeout: duration_from_value(
        map_get_value(&map, "step_timeout"),
        Duration::from_secs(300),
      )?,
      total_timeout: duration_from_value(
        map_get_value(&map, "total_timeout"),
        Duration::from_secs(3600),
      )?,
      verbosity: u8::from_json_value(map_get_value(&map, "verbosity")).unwrap_or(1),
      dry_run: map_get_bool(&map, "dry_run", false)?,
    })
  }
}

impl JsonEncode for StepExecutionResult {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("step_number".to_string(), self.step_number.to_json_value());
    map.insert("step_name".to_string(), self.step_name.to_json_value());
    map.insert("success".to_string(), self.success.to_json_value());
    map.insert("status".to_string(), self.status.to_json_value());
    map.insert("output".to_string(), self.output.to_json_value());
    map.insert("findings".to_string(), self.findings.to_json_value());
    map.insert(
      "extracted_data".to_string(),
      self.extracted_data.to_json_value(),
    );
    map.insert("duration".to_string(), duration_to_value(self.duration));
    map.insert("skipped".to_string(), self.skipped.to_json_value());
    map.insert("error".to_string(), self.error.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for StepExecutionResult {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      step_number: u8::from_json_value(map_get_value(&map, "step_number"))?,
      step_name: String::from_json_value(map_get_value(&map, "step_name"))?,
      success: map_get_bool(&map, "success", false)?,
      status: String::from_json_value(map_get_value(&map, "status"))
        .unwrap_or_else(|_| "Not executed".to_string()),
      output: Vec::<String>::from_json_value(map_get_array(&map, "output")).unwrap_or_default(),
      findings: Vec::<Finding>::from_json_value(map_get_array(&map, "findings"))
        .unwrap_or_default(),
      extracted_data: HashMap::<String, String>::from_json_value(map_get_value(
        &map,
        "extracted_data",
      ))
      .unwrap_or_default(),
      duration: duration_from_value(map_get_value(&map, "duration"), Duration::ZERO)?,
      skipped: map_get_bool(&map, "skipped", false)?,
      error: Option::<String>::from_json_value(map_get_value(&map, "error"))?,
    })
  }
}

impl JsonEncode for PlaybookExecutionResult {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("playbook_id".to_string(), self.playbook_id.to_json_value());
    map.insert(
      "playbook_name".to_string(),
      self.playbook_name.to_json_value(),
    );
    map.insert("target".to_string(), self.target.to_json_value());
    map.insert("success".to_string(), self.success.to_json_value());
    map.insert(
      "step_results".to_string(),
      self.step_results.to_json_value(),
    );
    map.insert(
      "all_findings".to_string(),
      self.all_findings.to_json_value(),
    );
    map.insert("duration".to_string(), duration_to_value(self.duration));
    map.insert("summary".to_string(), self.summary.to_json_value());
    map.insert(
      "steps_completed".to_string(),
      self.steps_completed.to_json_value(),
    );
    map.insert(
      "steps_skipped".to_string(),
      self.steps_skipped.to_json_value(),
    );
    map.insert(
      "steps_failed".to_string(),
      self.steps_failed.to_json_value(),
    );
    map.insert(
      "next_playbook".to_string(),
      self.next_playbook.to_json_value(),
    );
    map.insert(
      "assertion_results".to_string(),
      self.assertion_results.to_json_value(),
    );
    Value::Object(map)
  }
}

impl JsonDecode for PlaybookExecutionResult {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      playbook_id: String::from_json_value(map_get_value(&map, "playbook_id"))?,
      playbook_name: String::from_json_value(map_get_value(&map, "playbook_name"))?,
      target: String::from_json_value(map_get_value(&map, "target"))?,
      success: map_get_bool(&map, "success", false)?,
      step_results: Vec::<StepExecutionResult>::from_json_value(map_get_array(
        &map,
        "step_results",
      ))
      .unwrap_or_default(),
      all_findings: Vec::<Finding>::from_json_value(map_get_array(&map, "all_findings"))
        .unwrap_or_default(),
      duration: duration_from_value(map_get_value(&map, "duration"), Duration::ZERO)?,
      summary: String::from_json_value(map_get_value(&map, "summary")).unwrap_or_default(),
      steps_completed: usize::from_json_value(map_get_value(&map, "steps_completed")).unwrap_or(0),
      steps_skipped: usize::from_json_value(map_get_value(&map, "steps_skipped")).unwrap_or(0),
      steps_failed: usize::from_json_value(map_get_value(&map, "steps_failed")).unwrap_or(0),
      next_playbook: Option::<String>::from_json_value(map_get_value(&map, "next_playbook"))?,
      assertion_results: Vec::<AssertionResult>::from_json_value(map_get_array(
        &map,
        "assertion_results",
      ))
      .unwrap_or_default(),
    })
  }
}

impl JsonEncode for ChainCondition {
  fn to_json_value(&self) -> Value {
    match self {
      ChainCondition::Always => Value::String("Always".to_string()),
      ChainCondition::OnSuccess => Value::String("OnSuccess".to_string()),
      ChainCondition::OnFailure => Value::String("OnFailure".to_string()),
      ChainCondition::OnEvidence(evidence) => tagged_value("OnEvidence", evidence.to_json_value()),
      ChainCondition::OnSeverity(severity) => tagged_value("OnSeverity", severity.to_json_value()),
    }
  }
}

impl JsonDecode for ChainCondition {
  fn from_json_value(value: Value) -> Result<Self, String> {
    match value {
      Value::String(s) => {
        let key = normalize_key(&s);
        match key.as_str() {
          "always" => Ok(ChainCondition::Always),
          "onsuccess" => Ok(ChainCondition::OnSuccess),
          "onfailure" => Ok(ChainCondition::OnFailure),
          _ => Err("invalid chain condition".to_string()),
        }
      }
      Value::Object(map) if map.len() == 1 => {
        let (key, value) = map.into_iter().next().unwrap();
        match key.as_str() {
          "OnEvidence" | "onevidence" => Ok(ChainCondition::OnEvidence(
            EvidenceType::from_json_value(value)?,
          )),
          "OnSeverity" | "onseverity" => Ok(ChainCondition::OnSeverity(
            FindingSeverity::from_json_value(value)?,
          )),
          _ => Err("invalid chain condition".to_string()),
        }
      }
      _ => Err("invalid chain condition".to_string()),
    }
  }
}

impl JsonEncode for ChainedPlaybook {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("playbook_id".to_string(), self.playbook_id.to_json_value());
    map.insert("condition".to_string(), self.condition.to_json_value());
    map.insert(
      "output_mapping".to_string(),
      self.output_mapping.to_json_value(),
    );
    map.insert(
      "continue_on_failure".to_string(),
      self.continue_on_failure.to_json_value(),
    );
    Value::Object(map)
  }
}

impl JsonDecode for ChainedPlaybook {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      playbook_id: String::from_json_value(map_get_value(&map, "playbook_id"))?,
      condition: ChainCondition::from_json_value(map_get_value(&map, "condition"))
        .unwrap_or_default(),
      output_mapping: HashMap::<String, String>::from_json_value(map_get_value(
        &map,
        "output_mapping",
      ))
      .unwrap_or_default(),
      continue_on_failure: map_get_bool(&map, "continue_on_failure", false)?,
    })
  }
}

impl JsonEncode for PlaybookChain {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("id".to_string(), self.id.to_json_value());
    map.insert("name".to_string(), self.name.to_json_value());
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("playbooks".to_string(), self.playbooks.to_json_value());
    map.insert("tags".to_string(), self.tags.to_json_value());
    map.insert("risk_level".to_string(), self.risk_level.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for PlaybookChain {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      id: String::from_json_value(map_get_value(&map, "id"))?,
      name: String::from_json_value(map_get_value(&map, "name"))?,
      description: String::from_json_value(map_get_value(&map, "description")).unwrap_or_default(),
      playbooks: Vec::<ChainedPlaybook>::from_json_value(map_get_array(&map, "playbooks"))
        .unwrap_or_default(),
      tags: Vec::<String>::from_json_value(map_get_array(&map, "tags")).unwrap_or_default(),
      risk_level: RiskLevel::from_json_value(map_get_value(&map, "risk_level"))
        .unwrap_or(RiskLevel::Low),
    })
  }
}

impl JsonEncode for AssertionOperator {
  fn to_json_value(&self) -> Value {
    let s = match self {
      AssertionOperator::Equals => "Equals",
      AssertionOperator::NotEquals => "NotEquals",
      AssertionOperator::GreaterThan => "GreaterThan",
      AssertionOperator::LessThan => "LessThan",
      AssertionOperator::GreaterOrEqual => "GreaterOrEqual",
      AssertionOperator::LessOrEqual => "LessOrEqual",
      AssertionOperator::Contains => "Contains",
      AssertionOperator::NotContains => "NotContains",
      AssertionOperator::Matches => "Matches",
      AssertionOperator::IsTrue => "IsTrue",
      AssertionOperator::IsFalse => "IsFalse",
      AssertionOperator::Exists => "Exists",
      AssertionOperator::NotExists => "NotExists",
    };
    Value::String(s.to_string())
  }
}

impl JsonDecode for AssertionOperator {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let s = String::from_json_value(value)?;
    let key = s.to_lowercase();
    match key.as_str() {
      "equals" | "==" => Ok(AssertionOperator::Equals),
      "notequals" | "!=" => Ok(AssertionOperator::NotEquals),
      "greaterthan" | ">" => Ok(AssertionOperator::GreaterThan),
      "lessthan" | "<" => Ok(AssertionOperator::LessThan),
      "greaterorequal" | ">=" => Ok(AssertionOperator::GreaterOrEqual),
      "lessorequal" | "<=" => Ok(AssertionOperator::LessOrEqual),
      "contains" => Ok(AssertionOperator::Contains),
      "notcontains" => Ok(AssertionOperator::NotContains),
      "matches" => Ok(AssertionOperator::Matches),
      "istrue" => Ok(AssertionOperator::IsTrue),
      "isfalse" => Ok(AssertionOperator::IsFalse),
      "exists" => Ok(AssertionOperator::Exists),
      "notexists" => Ok(AssertionOperator::NotExists),
      _ => Err("invalid assertion operator".to_string()),
    }
  }
}

impl JsonEncode for Assertion {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("subject".to_string(), self.subject.to_json_value());
    map.insert("operator".to_string(), self.operator.to_json_value());
    map.insert("expected".to_string(), self.expected.to_json_value());
    map.insert("critical".to_string(), self.critical.to_json_value());
    map.insert(
      "failure_message".to_string(),
      self.failure_message.to_json_value(),
    );
    Value::Object(map)
  }
}

impl JsonDecode for Assertion {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      description: String::from_json_value(map_get_value(&map, "description"))?,
      subject: String::from_json_value(map_get_value(&map, "subject"))?,
      operator: AssertionOperator::from_json_value(map_get_value(&map, "operator"))
        .unwrap_or(AssertionOperator::Exists),
      expected: Option::<String>::from_json_value(map_get_value(&map, "expected"))?,
      critical: map_get_bool(&map, "critical", false)?,
      failure_message: Option::<String>::from_json_value(map_get_value(&map, "failure_message"))?,
    })
  }
}

impl JsonEncode for AssertionResult {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("description".to_string(), self.description.to_json_value());
    map.insert("passed".to_string(), self.passed.to_json_value());
    map.insert(
      "actual_value".to_string(),
      self.actual_value.to_json_value(),
    );
    map.insert(
      "expected_value".to_string(),
      self.expected_value.to_json_value(),
    );
    map.insert("message".to_string(), self.message.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for AssertionResult {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      description: String::from_json_value(map_get_value(&map, "description"))?,
      passed: map_get_bool(&map, "passed", false)?,
      actual_value: Option::<String>::from_json_value(map_get_value(&map, "actual_value"))?,
      expected_value: Option::<String>::from_json_value(map_get_value(&map, "expected_value"))?,
      message: Option::<String>::from_json_value(map_get_value(&map, "message"))?,
    })
  }
}

impl JsonEncode for ChainExecutionResult {
  fn to_json_value(&self) -> Value {
    let mut map = Map::new();
    map.insert("chain_id".to_string(), self.chain_id.to_json_value());
    map.insert("target".to_string(), self.target.to_json_value());
    map.insert("success".to_string(), self.success.to_json_value());
    map.insert(
      "playbook_results".to_string(),
      self.playbook_results.to_json_value(),
    );
    map.insert("duration".to_string(), duration_to_value(self.duration));
    map.insert(
      "all_findings".to_string(),
      self.all_findings.to_json_value(),
    );
    map.insert("summary".to_string(), self.summary.to_json_value());
    Value::Object(map)
  }
}

impl JsonDecode for ChainExecutionResult {
  fn from_json_value(value: Value) -> Result<Self, String> {
    let map = match value {
      Value::Object(map) => map,
      _ => return Err("expected object".to_string()),
    };
    Ok(Self {
      chain_id: String::from_json_value(map_get_value(&map, "chain_id"))?,
      target: String::from_json_value(map_get_value(&map, "target"))?,
      success: map_get_bool(&map, "success", false)?,
      playbook_results: Vec::<PlaybookExecutionResult>::from_json_value(map_get_array(
        &map,
        "playbook_results",
      ))
      .unwrap_or_default(),
      duration: duration_from_value(map_get_value(&map, "duration"), Duration::ZERO)?,
      all_findings: Vec::<Finding>::from_json_value(map_get_array(&map, "all_findings"))
        .unwrap_or_default(),
      summary: String::from_json_value(map_get_value(&map, "summary")).unwrap_or_default(),
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_playbook_creation() {
    let playbook = Playbook::new("test-playbook", "Test Playbook")
      .with_description("A test playbook")
      .with_objective("Test the playbook system")
      .for_target(TargetType::Host)
      .for_os(TargetOS::Linux)
      .with_risk(RiskLevel::Low)
      .add_precondition(PreCondition::new("Target must be reachable"))
      .add_step(
        PlaybookStep::new(1, PlaybookPhase::Recon, "Port Scan")
          .with_description("Scan for open ports")
          .with_command("rb network ports scan <target>")
          .with_success("Open ports identified"),
      )
      .add_evidence(
        ExpectedEvidence::new("Open SSH port")
          .at("Port 22")
          .with_indicator("SSH service banner"),
      )
      .add_failed_control(
        FailedControl::new("Perimeter Firewall", "SSH often allowed for admin access")
          .with_fix("Implement IP allowlisting for SSH access"),
      );

    assert_eq!(playbook.metadata.id, "test-playbook");
    assert_eq!(playbook.total_steps(), 1);
    assert!(playbook.is_safe());
  }

  #[test]
  fn test_risk_levels() {
    assert!(!RiskLevel::Passive.requires_consent());
    assert!(!RiskLevel::Low.requires_consent());
    assert!(!RiskLevel::Medium.requires_consent());
    assert!(RiskLevel::High.requires_consent());
    assert!(RiskLevel::Critical.requires_consent());
  }

  #[test]
  fn test_step_dependencies() {
    let step1 = PlaybookStep::new(1, PlaybookPhase::Recon, "Recon");
    let step2 = PlaybookStep::new(2, PlaybookPhase::InitialAccess, "Access").depends(1);

    assert!(step1.depends_on.is_empty());
    assert_eq!(step2.depends_on, vec![1]);
  }
}
