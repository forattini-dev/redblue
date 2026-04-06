//! Development platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all development platforms
pub fn get_development_platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "GitHub",
      category: PlatformCategory::Development,
      url_pattern: "https://github.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "GitLab",
      category: PlatformCategory::Development,
      url_pattern: "https://gitlab.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bitbucket",
      category: PlatformCategory::Development,
      url_pattern: "https://bitbucket.org/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Stack Overflow",
      category: PlatformCategory::Development,
      url_pattern: "https://stackoverflow.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dev.to",
      category: PlatformCategory::Development,
      url_pattern: "https://dev.to/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hashnode",
      category: PlatformCategory::Development,
      url_pattern: "https://hashnode.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Medium",
      category: PlatformCategory::Development,
      url_pattern: "https://medium.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "HackerNews",
      category: PlatformCategory::Development,
      url_pattern: "https://news.ycombinator.com/user?id={username}",
      detection: DetectionMethod::ResponseNotContains {
        text: "No such user".to_string(),
      },
      ..Default::default()
    },
    Platform {
      name: "Kaggle",
      category: PlatformCategory::Development,
      url_pattern: "https://www.kaggle.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CodePen",
      category: PlatformCategory::Development,
      url_pattern: "https://codepen.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Replit",
      category: PlatformCategory::Development,
      url_pattern: "https://replit.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "npm",
      category: PlatformCategory::Development,
      url_pattern: "https://www.npmjs.com/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PyPI",
      category: PlatformCategory::Development,
      url_pattern: "https://pypi.org/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "RubyGems",
      category: PlatformCategory::Development,
      url_pattern: "https://rubygems.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Docker Hub",
      category: PlatformCategory::Development,
      url_pattern: "https://hub.docker.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "HackerOne",
      category: PlatformCategory::Development,
      url_pattern: "https://hackerone.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bugcrowd",
      category: PlatformCategory::Development,
      url_pattern: "https://bugcrowd.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "HackTheBox",
      category: PlatformCategory::Development,
      url_pattern: "https://app.hackthebox.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TryHackMe",
      category: PlatformCategory::Development,
      url_pattern: "https://tryhackme.com/p/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SourceForge",
      category: PlatformCategory::Development,
      url_pattern: "https://sourceforge.net/u/{username}/profile/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codeberg",
      category: PlatformCategory::Development,
      url_pattern: "https://codeberg.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gitee",
      category: PlatformCategory::Development,
      url_pattern: "https://gitee.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Launchpad",
      category: PlatformCategory::Development,
      url_pattern: "https://launchpad.net/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Glitch",
      category: PlatformCategory::Development,
      url_pattern: "https://glitch.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Observable",
      category: PlatformCategory::Development,
      url_pattern: "https://observablehq.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "JSFiddle",
      category: PlatformCategory::Development,
      url_pattern: "https://jsfiddle.net/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CodeSandbox",
      category: PlatformCategory::Development,
      url_pattern: "https://codesandbox.io/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "StackBlitz",
      category: PlatformCategory::Development,
      url_pattern: "https://stackblitz.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Exercism",
      category: PlatformCategory::Development,
      url_pattern: "https://exercism.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OpenStreetMap",
      category: PlatformCategory::Development,
      url_pattern: "https://www.openstreetmap.org/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OpenHub",
      category: PlatformCategory::Development,
      url_pattern: "https://www.openhub.net/accounts/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Crates.io",
      category: PlatformCategory::Development,
      url_pattern: "https://crates.io/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Packagist",
      category: PlatformCategory::Development,
      url_pattern: "https://packagist.org/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Intigriti",
      category: PlatformCategory::Development,
      url_pattern: "https://app.intigriti.com/researcher/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "YesWeHack",
      category: PlatformCategory::Development,
      url_pattern: "https://yeswehack.com/hunters/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Synack",
      category: PlatformCategory::Development,
      url_pattern: "https://www.synack.com/red-team/researchers/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Habr",
      category: PlatformCategory::Development,
      url_pattern: "https://habr.com/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Qiita",
      category: PlatformCategory::Development,
      url_pattern: "https://qiita.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zenn",
      category: PlatformCategory::Development,
      url_pattern: "https://zenn.dev/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Coderwall",
      category: PlatformCategory::Development,
      url_pattern: "https://coderwall.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Speakerdeck",
      category: PlatformCategory::Development,
      url_pattern: "https://speakerdeck.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SlideShare",
      category: PlatformCategory::Development,
      url_pattern: "https://www.slideshare.net/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "GitBook",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.gitbook.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Read the Docs",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.readthedocs.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vercel",
      category: PlatformCategory::Development,
      url_pattern: "https://vercel.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Netlify",
      category: PlatformCategory::Development,
      url_pattern: "https://app.netlify.com/teams/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Render",
      category: PlatformCategory::Development,
      url_pattern: "https://render.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Railway",
      category: PlatformCategory::Development,
      url_pattern: "https://railway.app/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fly.io",
      category: PlatformCategory::Development,
      url_pattern: "https://fly.io/apps/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Heroku",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.herokuapp.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "WakaTime",
      category: PlatformCategory::Development,
      url_pattern: "https://wakatime.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Daily.dev",
      category: PlatformCategory::Development,
      url_pattern: "https://app.daily.dev/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Showwcase",
      category: PlatformCategory::Development,
      url_pattern: "https://www.showwcase.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "V2EX",
      category: PlatformCategory::Development,
      url_pattern: "https://www.v2ex.com/member/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "IFTTT",
      category: PlatformCategory::Development,
      url_pattern: "https://ifttt.com/p/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zapier",
      category: PlatformCategory::Development,
      url_pattern: "https://zapier.com/shared/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Make (Integromat)",
      category: PlatformCategory::Development,
      url_pattern: "https://www.make.com/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Airtable Universe",
      category: PlatformCategory::Development,
      url_pattern: "https://www.airtable.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Coda",
      category: PlatformCategory::Development,
      url_pattern: "https://coda.io/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Root-Me",
      category: PlatformCategory::Development,
      url_pattern: "https://www.root-me.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PentesterLab",
      category: PlatformCategory::Development,
      url_pattern: "https://pentesterlab.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PortSwigger (Burp)",
      category: PlatformCategory::Development,
      url_pattern: "https://portswigger.net/web-security/hall-of-fame/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CTFtime",
      category: PlatformCategory::Development,
      url_pattern: "https://ctftime.org/team/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CyberDefenders",
      category: PlatformCategory::Development,
      url_pattern: "https://cyberdefenders.org/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "BlueTeamLabs",
      category: PlatformCategory::Development,
      url_pattern: "https://blueteamlabs.online/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OverTheWire",
      category: PlatformCategory::Development,
      url_pattern: "https://overthewire.org/wargames/bandit/scoreboard/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PicoCTF",
      category: PlatformCategory::Development,
      url_pattern: "https://play.picoctf.org/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "VulnHub",
      category: PlatformCategory::Development,
      url_pattern: "https://www.vulnhub.com/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Offensive Security",
      category: PlatformCategory::Development,
      url_pattern: "https://offensive-security.com/pwk/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TopCoder",
      category: PlatformCategory::Development,
      url_pattern: "https://www.topcoder.com/members/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "AtCoder",
      category: PlatformCategory::Development,
      url_pattern: "https://atcoder.jp/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SPOJ",
      category: PlatformCategory::Development,
      url_pattern: "https://www.spoj.com/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "UVa Online Judge",
      category: PlatformCategory::Development,
      url_pattern: "https://uhunt.onlinejudge.org/id/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "DMOJ",
      category: PlatformCategory::Development,
      url_pattern: "https://dmoj.ca/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kattis",
      category: PlatformCategory::Development,
      url_pattern: "https://open.kattis.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CSES",
      category: PlatformCategory::Development,
      url_pattern: "https://cses.fi/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Habr",
      category: PlatformCategory::Development,
      url_pattern: "https://habr.com/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gitea",
      category: PlatformCategory::Development,
      url_pattern: "https://gitea.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Sourcehut",
      category: PlatformCategory::Development,
      url_pattern: "https://sr.ht/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codeberg",
      category: PlatformCategory::Development,
      url_pattern: "https://codeberg.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "NotABug",
      category: PlatformCategory::Development,
      url_pattern: "https://notabug.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Launchpad",
      category: PlatformCategory::Development,
      url_pattern: "https://launchpad.net/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Savannah",
      category: PlatformCategory::Development,
      url_pattern: "https://savannah.gnu.org/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OSDN",
      category: PlatformCategory::Development,
      url_pattern: "https://osdn.net/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OpenHub",
      category: PlatformCategory::Development,
      url_pattern: "https://openhub.net/accounts/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Libraries.io",
      category: PlatformCategory::Development,
      url_pattern: "https://libraries.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codesandbox",
      category: PlatformCategory::Development,
      url_pattern: "https://codesandbox.io/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "StackBlitz",
      category: PlatformCategory::Development,
      url_pattern: "https://stackblitz.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Exercism",
      category: PlatformCategory::Development,
      url_pattern: "https://exercism.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Edabit",
      category: PlatformCategory::Development,
      url_pattern: "https://edabit.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codingame",
      category: PlatformCategory::Development,
      url_pattern: "https://www.codingame.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Advent of Code",
      category: PlatformCategory::Development,
      url_pattern: "https://adventofcode.com/settings",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ask Ubuntu",
      category: PlatformCategory::Development,
      url_pattern: "https://askubuntu.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Server Fault",
      category: PlatformCategory::Development,
      url_pattern: "https://serverfault.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Super User",
      category: PlatformCategory::Development,
      url_pattern: "https://superuser.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Information Security",
      category: PlatformCategory::Development,
      url_pattern: "https://security.stackexchange.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Code Review",
      category: PlatformCategory::Development,
      url_pattern: "https://codereview.stackexchange.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Code Golf",
      category: PlatformCategory::Development,
      url_pattern: "https://codegolf.stackexchange.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Unix & Linux",
      category: PlatformCategory::Development,
      url_pattern: "https://unix.stackexchange.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Database Administrators",
      category: PlatformCategory::Development,
      url_pattern: "https://dba.stackexchange.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hugging Face",
      category: PlatformCategory::Development,
      url_pattern: "https://huggingface.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kaggle",
      category: PlatformCategory::Development,
      url_pattern: "https://www.kaggle.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Weights & Biases",
      category: PlatformCategory::Development,
      url_pattern: "https://wandb.ai/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hashnode",
      category: PlatformCategory::Development,
      url_pattern: "https://hashnode.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "DEV.to",
      category: PlatformCategory::Development,
      url_pattern: "https://dev.to/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hacker News",
      category: PlatformCategory::Development,
      url_pattern: "https://news.ycombinator.com/user?id={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lobsters",
      category: PlatformCategory::Development,
      url_pattern: "https://lobste.rs/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Glitch",
      category: PlatformCategory::Development,
      url_pattern: "https://glitch.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Observable",
      category: PlatformCategory::Development,
      url_pattern: "https://observablehq.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Deno Land",
      category: PlatformCategory::Development,
      url_pattern: "https://deno.land/x?query=@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "JSFiddle",
      category: PlatformCategory::Development,
      url_pattern: "https://jsfiddle.net/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CodePen",
      category: PlatformCategory::Development,
      url_pattern: "https://codepen.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Crates.io",
      category: PlatformCategory::Development,
      url_pattern: "https://crates.io/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PyPI",
      category: PlatformCategory::Development,
      url_pattern: "https://pypi.org/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "RubyGems",
      category: PlatformCategory::Development,
      url_pattern: "https://rubygems.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Packagist",
      category: PlatformCategory::Development,
      url_pattern: "https://packagist.org/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hex.pm",
      category: PlatformCategory::Development,
      url_pattern: "https://hex.pm/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pub.dev",
      category: PlatformCategory::Development,
      url_pattern: "https://pub.dev/publishers/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Maven Central",
      category: PlatformCategory::Development,
      url_pattern: "https://search.maven.org/search?q=g:{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "NuGet",
      category: PlatformCategory::Development,
      url_pattern: "https://www.nuget.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CocoaPods",
      category: PlatformCategory::Development,
      url_pattern: "https://cocoapods.org/owners/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Go.dev",
      category: PlatformCategory::Development,
      url_pattern: "https://pkg.go.dev/search?q={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "XDA Developers",
      category: PlatformCategory::Development,
      url_pattern: "https://xdaforums.com/m/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ars Technica",
      category: PlatformCategory::Development,
      url_pattern: "https://arstechnica.com/civis/ucp.php?mode=viewprofile&u={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "AnandTech",
      category: PlatformCategory::Development,
      url_pattern: "https://forums.anandtech.com/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tom's Hardware",
      category: PlatformCategory::Development,
      url_pattern: "https://forums.tomshardware.com/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Linus Tech Tips",
      category: PlatformCategory::Development,
      url_pattern: "https://linustechtips.com/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Level1Techs",
      category: PlatformCategory::Development,
      url_pattern: "https://forum.level1techs.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Spiceworks",
      category: PlatformCategory::Development,
      url_pattern: "https://community.spiceworks.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Wilders Security",
      category: PlatformCategory::Development,
      url_pattern: "https://www.wilderssecurity.com/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "LeetCode",
      category: PlatformCategory::Development,
      url_pattern: "https://leetcode.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "HackerRank",
      category: PlatformCategory::Development,
      url_pattern: "https://www.hackerrank.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codewars",
      category: PlatformCategory::Development,
      url_pattern: "https://www.codewars.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Exercism",
      category: PlatformCategory::Development,
      url_pattern: "https://exercism.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codeforces",
      category: PlatformCategory::Development,
      url_pattern: "https://codeforces.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "AtCoder",
      category: PlatformCategory::Development,
      url_pattern: "https://atcoder.jp/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TopCoder",
      category: PlatformCategory::Development,
      url_pattern: "https://www.topcoder.com/members/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CodeChef",
      category: PlatformCategory::Development,
      url_pattern: "https://www.codechef.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SPOJ",
      category: PlatformCategory::Development,
      url_pattern: "https://www.spoj.com/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Glide",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.glideapp.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Softr",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.softr.app",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bubble",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.bubbleapps.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Webflow",
      category: PlatformCategory::Development,
      url_pattern: "https://{username}.webflow.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "GitLab",
      category: PlatformCategory::Development,
      url_pattern: "https://gitlab.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bitbucket",
      category: PlatformCategory::Development,
      url_pattern: "https://bitbucket.org/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SourceForge",
      category: PlatformCategory::Development,
      url_pattern: "https://sourceforge.net/u/{username}/profile/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Launchpad",
      category: PlatformCategory::Development,
      url_pattern: "https://launchpad.net/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gitea",
      category: PlatformCategory::Development,
      url_pattern: "https://gitea.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codeberg",
      category: PlatformCategory::Development,
      url_pattern: "https://codeberg.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "HackerOne",
      category: PlatformCategory::Development,
      url_pattern: "https://hackerone.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bugcrowd",
      category: PlatformCategory::Development,
      url_pattern: "https://bugcrowd.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Intigriti",
      category: PlatformCategory::Development,
      url_pattern: "https://www.intigriti.com/researcher/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "YesWeHack",
      category: PlatformCategory::Development,
      url_pattern: "https://yeswehack.com/hunters/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Synack",
      category: PlatformCategory::Development,
      url_pattern: "https://www.synack.com/researchers/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CTFtime",
      category: PlatformCategory::Development,
      url_pattern: "https://ctftime.org/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hack The Box",
      category: PlatformCategory::Development,
      url_pattern: "https://app.hackthebox.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TryHackMe",
      category: PlatformCategory::Development,
      url_pattern: "https://tryhackme.com/p/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PentesterLab",
      category: PlatformCategory::Development,
      url_pattern: "https://pentesterlab.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "RootMe",
      category: PlatformCategory::Development,
      url_pattern: "https://www.root-me.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OverTheWire",
      category: PlatformCategory::Development,
      url_pattern: "https://overthewire.org/wargames/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CyberDefenders",
      category: PlatformCategory::Development,
      url_pattern: "https://cyberdefenders.org/p/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hackaday",
      category: PlatformCategory::Development,
      url_pattern: "https://hackaday.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hackster.io",
      category: PlatformCategory::Development,
      url_pattern: "https://www.hackster.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Habr",
      category: PlatformCategory::Development,
      url_pattern: "https://habr.com/ru/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Peerlist",
      category: PlatformCategory::Development,
      url_pattern: "https://peerlist.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
