use crate::cli::commands::{Command, Flag, Route};
use crate::cli::output::Output;
use crate::cli::CliContext;
use crate::modules::auth::http_auth::HttpAuthTester;
use crate::modules::auth::iterator::CredentialIterator;
use crate::wordlists::Loader;

pub struct AuthTestCommand;

impl Command for AuthTestCommand {
    fn domain(&self) -> &str {
        "auth"
    }
    fn resource(&self) -> &str {
        "test"
    }
    fn description(&self) -> &str {
        "Test credentials against target"
    }

    fn routes(&self) -> Vec<Route> {
        vec![Route {
            verb: "http",
            summary: "Test HTTP Basic/Digest/Form auth",
            usage: "rb auth test http <target> -u <users> -p <pass>",
        }]
    }

    fn flags(&self) -> Vec<Flag> {
        vec![
            Flag::new("userlist", "Usernames file").with_short('u'),
            Flag::new("passlist", "Passwords file").with_short('p'),
            Flag::new("type", "Auth type: basic, digest, form").with_default("basic"),
            Flag::new("delay", "Delay between attempts (ms)").with_default("0"),
        ]
    }

    fn examples(&self) -> Vec<(&str, &str)> {
        vec![(
            "Test Basic Auth",
            "rb auth test http http://target.com/admin -u users.txt -p pass.txt",
        )]
    }

    fn execute(&self, ctx: &CliContext) -> Result<(), String> {
        // Implementation of tasks 3.4.16 - 3.4.19
        let target = ctx.target.as_ref().ok_or("Missing target URL")?;
        let users_file = ctx.get_flag("userlist").ok_or("Missing --userlist")?;
        let pass_file = ctx.get_flag("passlist").ok_or("Missing --passlist")?;

        let users = Loader::load_lines(users_file).map_err(|e| e.to_string())?;

        let passwords = Loader::load_lines(pass_file).map_err(|e| e.to_string())?;

        let iter = CredentialIterator::new(users, passwords);
        let mut tester = HttpAuthTester::new();

        for (user, pass) in iter {
            if tester.test_basic(target, &user, &pass) {
                Output::success(&format!("Found credentials: {}:{}", user, pass));
                return Ok(()); // Stop on success for now
            }
        }

        Ok(())
    }
}
