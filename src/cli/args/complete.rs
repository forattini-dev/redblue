/// Shell completion generation for the redblue CLI.
///
/// Generates static completion scripts for bash, zsh, and fish shells,
/// plus a dynamic `complete_partial` function for runtime tab-completion.

/// Supported shell targets for completion script generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
  Bash,
  Zsh,
  Fish,
}

/// Generate a full completion script for the given shell.
///
/// * `shell`        - Target shell.
/// * `domains`      - `(name, aliases)` for each domain.
/// * `global_flags` - `(long_name, optional_short)` for global flags.
pub fn generate_completion_script(
  shell: Shell,
  domains: &[(String, Vec<String>)],
  global_flags: &[(&str, Option<char>)],
) -> String {
  match shell {
    Shell::Bash => generate_bash(domains, global_flags),
    Shell::Zsh => generate_zsh(domains, global_flags),
    Shell::Fish => generate_fish(domains, global_flags),
  }
}

/// Complete partial input tokens at runtime.
///
/// * `tokens`  - Words typed so far.
/// * `domains` - `domain_name -> [(resource_name, [verb_names])]`.
///
/// Returns candidate completions for the next position.
pub fn complete_partial(
  tokens: &[&str],
  domains: &[(String, Vec<(String, Vec<String>)>)],
) -> Vec<String> {
  let domain_names: Vec<&str> = domains.iter().map(|(n, _)| n.as_str()).collect();

  match tokens.len() {
    // No input yet: return all domain names.
    0 => domain_names.iter().map(|s| s.to_string()).collect(),

    // Single partial token: filter matching domains.
    1 => {
      let prefix = tokens[0];
      domain_names
        .iter()
        .filter(|d| d.starts_with(prefix))
        .map(|d| d.to_string())
        .collect()
    }

    // Two tokens: domain given, complete the resource.
    2 => {
      let domain = tokens[0];
      let prefix = tokens[1];
      domains
        .iter()
        .find(|(name, _)| name == domain)
        .map(|(_, resources)| {
          resources
            .iter()
            .map(|(r, _)| r.as_str())
            .filter(|r| r.starts_with(prefix))
            .map(|r| r.to_string())
            .collect()
        })
        .unwrap_or_default()
    }

    // Three tokens: domain + resource given, complete the verb.
    3 => {
      let domain = tokens[0];
      let prefix = tokens[2];
      domains
        .iter()
        .find(|(name, _)| name == domain)
        .and_then(|(_, resources)| {
          resources
            .iter()
            .find(|(r, _)| r == tokens[1])
            .map(|(_, verbs)| {
              verbs
                .iter()
                .filter(|v| v.starts_with(prefix))
                .cloned()
                .collect()
            })
        })
        .unwrap_or_default()
    }

    // Four or more tokens: suggest flag names starting with --
    _ => {
      let last = *tokens.last().unwrap_or(&"");
      if last.starts_with("--") {
        let prefix = &last[2..];
        let flag_names = [
          "help", "json", "output", "verbose", "stealth", "no-color", "version",
        ];
        flag_names
          .iter()
          .filter(|f| f.starts_with(prefix))
          .map(|f| format!("--{}", f))
          .collect()
      } else if last.starts_with('-') && last.len() == 1 {
        vec![
          "-h".to_string(),
          "-j".to_string(),
          "-o".to_string(),
          "-v".to_string(),
          "-S".to_string(),
        ]
      } else {
        Vec::new()
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Bash completion
// ---------------------------------------------------------------------------

fn generate_bash(
  domains: &[(String, Vec<String>)],
  global_flags: &[(&str, Option<char>)],
) -> String {
  let all_domains: Vec<&str> = domains.iter().map(|(n, _)| n.as_str()).collect();
  let domain_word_list = all_domains.join(" ");

  let flag_word_list: String = global_flags
    .iter()
    .map(|(long, short)| {
      let mut parts = vec![format!("--{}", long)];
      if let Some(ch) = short {
        parts.push(format!("-{}", ch));
      }
      parts.join(" ")
    })
    .collect::<Vec<_>>()
    .join(" ");

  // Note: domain-level case arms are intentionally left out because the
  // real resource/verb data lives in the schema module and is dynamic.
  // The script handles the first completion level (domains) statically
  // and defers deeper levels to the binary via --complete if available.

  format!(
    r#"_rb_completions() {{
    local cur prev words cword
    _init_completion || return

    # Global flags at any position
    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "{flags}" -- "$cur"))
        return
    fi

    case $cword in
        1)
            COMPREPLY=($(compgen -W "{domains} help version" -- "$cur"))
            ;;
        *)
            # Delegate deeper completions to the binary when available
            if command -v rb &>/dev/null; then
                local completions
                completions=$(rb --complete "${{words[@]:1}}" 2>/dev/null)
                if [[ -n "$completions" ]]; then
                    COMPREPLY=($(compgen -W "$completions" -- "$cur"))
                fi
            fi
            ;;
    esac
}}
complete -F _rb_completions rb
"#,
    flags = flag_word_list,
    domains = domain_word_list,
  )
}

// ---------------------------------------------------------------------------
// Zsh completion
// ---------------------------------------------------------------------------

fn generate_zsh(
  domains: &[(String, Vec<String>)],
  global_flags: &[(&str, Option<char>)],
) -> String {
  let mut out = String::with_capacity(1024);

  out.push_str("#compdef rb\n\n");
  out.push_str("_rb() {\n");
  out.push_str("    local -a global_flags\n");
  out.push_str("    global_flags=(\n");
  for (long, short) in global_flags {
    match short {
      Some(ch) => {
        out.push_str(&format!(
          "        '(-{ch} --{long})'{{{short_dash},--{long}}}'[{long}]'\n",
          ch = ch,
          long = long,
          short_dash = format!("-{}", ch),
        ));
      }
      None => {
        out.push_str(&format!("        '--{long}[{long}]'\n", long = long));
      }
    }
  }
  out.push_str("    )\n\n");

  out.push_str("    _arguments -C \\\n");
  out.push_str("        $global_flags \\\n");
  out.push_str("        '1:domain:->domain' \\\n");
  out.push_str("        '*::arg:->args'\n\n");

  out.push_str("    case $state in\n");
  out.push_str("        domain)\n");
  out.push_str("            local -a domains\n");
  out.push_str("            domains=(\n");
  for (name, _) in domains {
    out.push_str(&format!("                '{}'\n", name));
  }
  out.push_str("                'help'\n");
  out.push_str("                'version'\n");
  out.push_str("            )\n");
  out.push_str("            _describe 'domain' domains\n");
  out.push_str("            ;;\n");

  out.push_str("        args)\n");
  out.push_str("            # Delegate to binary for deeper completions\n");
  out.push_str("            if (( $+commands[rb] )); then\n");
  out.push_str("                local completions\n");
  out.push_str(
    "                completions=(${(f)\"$(rb --complete ${words[2,-1]} 2>/dev/null)\"})\n",
  );
  out.push_str("                _describe 'subcommand' completions\n");
  out.push_str("            fi\n");
  out.push_str("            ;;\n");
  out.push_str("    esac\n");
  out.push_str("}\n\n");
  out.push_str("_rb\n");
  out
}

// ---------------------------------------------------------------------------
// Fish completion
// ---------------------------------------------------------------------------

fn generate_fish(
  domains: &[(String, Vec<String>)],
  global_flags: &[(&str, Option<char>)],
) -> String {
  let mut out = String::with_capacity(1024);

  out.push_str("# Fish completions for rb (redblue)\n\n");

  // Global flags
  for (long, short) in global_flags {
    match short {
      Some(ch) => {
        out.push_str(&format!(
          "complete -c rb -s {} -l {} -d '{}'\n",
          ch, long, long
        ));
      }
      None => {
        out.push_str(&format!("complete -c rb -l {} -d '{}'\n", long, long));
      }
    }
  }
  out.push('\n');

  // Domain completions: only when no subcommand has been given yet
  out.push_str("# Domain completions\n");
  for (name, _) in domains {
    out.push_str(&format!(
      "complete -c rb -n '__fish_use_subcommand' -a {} -d '{}'\n",
      name, name
    ));
  }
  out.push_str("complete -c rb -n '__fish_use_subcommand' -a help -d 'Show help'\n");
  out.push_str("complete -c rb -n '__fish_use_subcommand' -a version -d 'Show version'\n");
  out.push('\n');

  // Deeper completions via binary
  out.push_str("# Delegate deeper completions to the binary\n");
  out.push_str("complete -c rb -n 'not __fish_use_subcommand' -a '(rb --complete (commandline -cop) 2>/dev/null)'\n");

  out
}

#[cfg(test)]
mod tests {
  use super::*;

  fn sample_domains() -> Vec<(String, Vec<String>)> {
    vec![
      ("dns".to_string(), vec![]),
      (
        "network".to_string(),
        vec!["n".to_string(), "net".to_string()],
      ),
      ("web".to_string(), vec![]),
    ]
  }

  fn sample_global_flags() -> Vec<(&'static str, Option<char>)> {
    vec![
      ("help", Some('h')),
      ("json", Some('j')),
      ("output", Some('o')),
      ("verbose", Some('v')),
      ("no-color", None),
    ]
  }

  fn sample_domain_tree() -> Vec<(String, Vec<(String, Vec<String>)>)> {
    vec![
      (
        "dns".to_string(),
        vec![(
          "record".to_string(),
          vec!["lookup".to_string(), "list".to_string()],
        )],
      ),
      (
        "network".to_string(),
        vec![
          (
            "ports".to_string(),
            vec!["scan".to_string(), "range".to_string()],
          ),
          ("host".to_string(), vec!["ping".to_string()]),
        ],
      ),
      (
        "web".to_string(),
        vec![(
          "asset".to_string(),
          vec!["get".to_string(), "headers".to_string()],
        )],
      ),
    ]
  }

  // ----------------------------------------------------------------
  // complete_partial tests
  // ----------------------------------------------------------------

  #[test]
  fn test_complete_partial_domains() {
    let tree = sample_domain_tree();
    let result = complete_partial(&[], &tree);
    assert!(result.contains(&"dns".to_string()));
    assert!(result.contains(&"network".to_string()));
    assert!(result.contains(&"web".to_string()));
    assert_eq!(result.len(), 3);
  }

  #[test]
  fn test_complete_partial_domains_filter() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["d"], &tree);
    assert_eq!(result, vec!["dns".to_string()]);
  }

  #[test]
  fn test_complete_partial_resources() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["network", ""], &tree);
    assert!(result.contains(&"ports".to_string()));
    assert!(result.contains(&"host".to_string()));
  }

  #[test]
  fn test_complete_partial_resources_filter() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["network", "p"], &tree);
    assert_eq!(result, vec!["ports".to_string()]);
  }

  #[test]
  fn test_complete_partial_verbs() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["dns", "record", ""], &tree);
    assert!(result.contains(&"lookup".to_string()));
    assert!(result.contains(&"list".to_string()));
  }

  #[test]
  fn test_complete_partial_verbs_filter() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["dns", "record", "lo"], &tree);
    assert_eq!(result, vec!["lookup".to_string()]);
  }

  #[test]
  fn test_complete_partial_flags() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["dns", "record", "lookup", "--"], &tree);
    // All global flags start with empty prefix after --
    assert!(result.contains(&"--help".to_string()));
    assert!(result.contains(&"--json".to_string()));
    assert!(result.contains(&"--verbose".to_string()));
  }

  #[test]
  fn test_complete_partial_unknown_domain() {
    let tree = sample_domain_tree();
    let result = complete_partial(&["unknown", ""], &tree);
    assert!(result.is_empty());
  }

  // ----------------------------------------------------------------
  // Bash completion script tests
  // ----------------------------------------------------------------

  #[test]
  fn test_bash_completion_script() {
    let script = generate_completion_script(Shell::Bash, &sample_domains(), &sample_global_flags());
    assert!(script.contains("_rb_completions()"));
    assert!(script.contains("complete -F _rb_completions rb"));
    assert!(script.contains("dns"));
    assert!(script.contains("network"));
    assert!(script.contains("web"));
    assert!(script.contains("--help"));
    assert!(script.contains("-h"));
    assert!(script.contains("help version"));
  }

  // ----------------------------------------------------------------
  // Zsh completion script tests
  // ----------------------------------------------------------------

  #[test]
  fn test_zsh_completion_script() {
    let script = generate_completion_script(Shell::Zsh, &sample_domains(), &sample_global_flags());
    assert!(script.contains("#compdef rb"));
    assert!(script.contains("_rb()"));
    assert!(script.contains("_arguments"));
    assert!(script.contains("dns"));
    assert!(script.contains("network"));
    assert!(script.contains("web"));
    assert!(script.contains("--help"));
  }

  // ----------------------------------------------------------------
  // Fish completion script tests
  // ----------------------------------------------------------------

  #[test]
  fn test_fish_completion_script() {
    let script = generate_completion_script(Shell::Fish, &sample_domains(), &sample_global_flags());
    assert!(script.contains("complete -c rb"));
    assert!(script.contains("-s h -l help"));
    assert!(script.contains("__fish_use_subcommand"));
    assert!(script.contains("dns"));
    assert!(script.contains("network"));
  }
}
