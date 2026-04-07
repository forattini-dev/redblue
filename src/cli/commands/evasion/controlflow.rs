//! Control flow obfuscation command

use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::evasion::control_flow;

use crate::cli::commands::{Command, Flag, Route};

pub struct EvasionControlflowCommand;

impl Command for EvasionControlflowCommand {
  fn domain(&self) -> &str {
    "evasion"
  }

  fn resource(&self) -> &str {
    "controlflow"
  }

  fn description(&self) -> &str {
    "Control flow obfuscation techniques"
  }

  fn routes(&self) -> Vec<Route> {
    vec![
      Route {
        verb: "demo",
        summary: "Demo control flow obfuscation techniques",
        usage: "rb evasion controlflow demo",
      },
      Route {
        verb: "predicates",
        summary: "Show opaque predicate examples",
        usage: "rb evasion controlflow predicates",
      },
      Route {
        verb: "substitute",
        summary: "Show instruction substitution examples",
        usage: "rb evasion controlflow substitute <value>",
      },
    ]
  }

  fn metadata(&self) -> crate::cli::schema::CommandMetadata {
    crate::cli::schema::CommandMetadata::new()
  }

  fn route_metadata(&self, verb: &str) -> crate::cli::schema::RouteMetadata {
    crate::cli::schema::RouteMetadata::new()
      .with_aliases(crate::cli::aliases::verb_aliases_for(verb))
      .with_machine_output(self.metadata().machine_output)
  }

  fn flags(&self) -> Vec<Flag> {
    vec![Flag::new("format", "Output format (text, json)")
      .with_short('f')
      .with_default("text")]
  }

  fn examples(&self) -> Vec<(&str, &str)> {
    vec![
      ("Demo techniques", "rb evasion controlflow demo"),
      ("Show predicates", "rb evasion controlflow predicates"),
      ("Substitute 42", "rb evasion controlflow substitute 42"),
    ]
  }

  fn execute(&self, ctx: &CliContext) -> Result<(), String> {
    let verb = ctx.verb.as_deref().unwrap_or("demo");

    match verb {
      "demo" => execute_controlflow_demo(),
      "predicates" => execute_controlflow_predicates(),
      "substitute" => execute_controlflow_substitute(ctx),
      _ => Err(format!("Unknown verb: {}", verb)),
    }
  }
}

fn execute_controlflow_demo() -> Result<(), String> {
  Output::header("Control Flow Obfuscation Demo");
  println!();

  // Demo opaque predicates
  Output::info("1. Opaque Predicates (always true/false, hard to analyze):");
  println!(
    "    always_true_math(42):   {}",
    control_flow::OpaquePredicates::always_true_math(42)
  );
  println!(
    "    always_true_ptr():      {}",
    control_flow::OpaquePredicates::always_true_ptr()
  );
  println!(
    "    always_true_float():    {}",
    control_flow::OpaquePredicates::always_true_float()
  );
  println!(
    "    always_false_math(42):  {}",
    control_flow::OpaquePredicates::always_false_math(42)
  );
  println!(
    "    always_false_const():   {}",
    control_flow::OpaquePredicates::always_false_const()
  );

  println!();

  // Demo dead code
  Output::info("2. Dead Code Insertion:");
  println!("    fake_crypto_code():  [complex but unused code]");
  println!("    fake_network_code(): [socket-like operations]");
  println!("    fake_file_code():    [file handling stubs]");
  control_flow::DeadCode::insert_all();
  println!("    All blocks contain dead code (never executed)");

  println!();

  // Demo instruction substitution
  Output::info("3. Instruction Substitution:");
  let a = 10u32;
  let b = 5u32;
  println!(
    "    add_substitute({}, {}): {}",
    a,
    b,
    control_flow::InstructionSubstitution::add_substitute(a, b)
  );
  println!(
    "    sub_substitute({}, {}): {}",
    a,
    b,
    control_flow::InstructionSubstitution::sub_substitute(a, b)
  );
  println!(
    "    xor_substitute({}, {}): {}",
    a,
    b,
    control_flow::InstructionSubstitution::xor_substitute(a, b)
  );

  Ok(())
}

fn execute_controlflow_predicates() -> Result<(), String> {
  Output::header("Opaque Predicates");
  println!();

  Output::info("These expressions always evaluate to the same value,");
  Output::info("but are hard for static analysis to determine:");
  println!();

  Output::info("Always True:");
  println!(
    "    always_true_math(seed):   {}",
    control_flow::OpaquePredicates::always_true_math(12345)
  );
  println!(
    "    always_true_ptr():        {}",
    control_flow::OpaquePredicates::always_true_ptr()
  );
  println!(
    "    always_true_time():       {}",
    control_flow::OpaquePredicates::always_true_time()
  );
  println!(
    "    always_true_float():      {}",
    control_flow::OpaquePredicates::always_true_float()
  );

  println!();

  Output::info("Always False:");
  println!(
    "    always_false_math(seed):  {}",
    control_flow::OpaquePredicates::always_false_math(12345)
  );
  println!(
    "    always_false_const():     {}",
    control_flow::OpaquePredicates::always_false_const()
  );

  println!();
  Output::info("Usage: Wrap real code in if(opaque_true(seed)) { ... }");
  Output::info("Static analysis may think the branch is conditional");

  Ok(())
}

fn execute_controlflow_substitute(ctx: &CliContext) -> Result<(), String> {
  let value: u32 = ctx
    .target
    .as_ref()
    .and_then(|s| s.parse().ok())
    .unwrap_or(42);

  Output::header("Instruction Substitution");
  println!();

  let other = 17u32;

  Output::item("Input", &format!("{}", value));
  Output::item("Other", &format!("{}", other));

  println!();
  Output::info("Addition alternatives:");
  println!(
    "    Normal:          {} + {} = {}",
    value,
    other,
    value.wrapping_add(other)
  );
  println!(
    "    add_substitute:  {} + {} = {}",
    value,
    other,
    control_flow::InstructionSubstitution::add_substitute(value, other)
  );

  println!();
  Output::info("Subtraction alternatives:");
  println!(
    "    Normal:          {} - {} = {}",
    value,
    other,
    value.wrapping_sub(other)
  );
  println!(
    "    sub_substitute:  {} - {} = {}",
    value,
    other,
    control_flow::InstructionSubstitution::sub_substitute(value, other)
  );

  println!();
  Output::info("XOR alternatives:");
  println!(
    "    Normal:          {} ^ {} = {}",
    value,
    other,
    value ^ other
  );
  println!(
    "    xor_substitute:  {} ^ {} = {}",
    value,
    other,
    control_flow::InstructionSubstitution::xor_substitute(value, other)
  );

  println!();
  Output::info("Multiplication alternative:");
  println!(
    "    Normal:          {} * {} = {}",
    value,
    other,
    value.wrapping_mul(other)
  );
  println!(
    "    mul_substitute:  {} * {} = {}",
    value,
    other,
    control_flow::InstructionSubstitution::mul_substitute(value, other)
  );

  Ok(())
}
