//! Education platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all education platforms
pub fn get_education_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "Duolingo",
            category: PlatformCategory::Education,
            url_pattern: "https://www.duolingo.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Khan Academy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.khanacademy.org/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Codecademy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.codecademy.com/profiles/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "LeetCode",
            category: PlatformCategory::Education,
            url_pattern: "https://leetcode.com/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Codeforces",
            category: PlatformCategory::Education,
            url_pattern: "https://codeforces.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "HackerRank",
            category: PlatformCategory::Education,
            url_pattern: "https://www.hackerrank.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Codewars",
            category: PlatformCategory::Education,
            url_pattern: "https://www.codewars.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Udemy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.udemy.com/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Coursera",
            category: PlatformCategory::Education,
            url_pattern: "https://www.coursera.org/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Skillshare",
            category: PlatformCategory::Education,
            url_pattern: "https://www.skillshare.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Pluralsight",
            category: PlatformCategory::Education,
            url_pattern: "https://app.pluralsight.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Frontend Mentor",
            category: PlatformCategory::Education,
            url_pattern: "https://www.frontendmentor.io/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "freeCodeCamp",
            category: PlatformCategory::Education,
            url_pattern: "https://www.freecodecamp.org/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "The Odin Project",
            category: PlatformCategory::Education,
            url_pattern: "https://www.theodinproject.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Scrimba",
            category: PlatformCategory::Education,
            url_pattern: "https://scrimba.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Treehouse",
            category: PlatformCategory::Education,
            url_pattern: "https://teamtreehouse.com/profiles/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Datacamp",
            category: PlatformCategory::Education,
            url_pattern: "https://www.datacamp.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MathOverflow",
            category: PlatformCategory::Education,
            url_pattern: "https://mathoverflow.net/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Physics Stack Exchange",
            category: PlatformCategory::Education,
            url_pattern: "https://physics.stackexchange.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Cross Validated",
            category: PlatformCategory::Education,
            url_pattern: "https://stats.stackexchange.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ResearchGate",
            category: PlatformCategory::Education,
            url_pattern: "https://www.researchgate.net/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Academia.edu",
            category: PlatformCategory::Education,
            url_pattern: "https://independent.academia.edu/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ORCID",
            category: PlatformCategory::Education,
            url_pattern: "https://orcid.org/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Google Scholar",
            category: PlatformCategory::Education,
            url_pattern: "https://scholar.google.com/citations?user={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Semantic Scholar",
            category: PlatformCategory::Education,
            url_pattern: "https://www.semanticscholar.org/author/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Publons",
            category: PlatformCategory::Education,
            url_pattern: "https://publons.com/researcher/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Mendeley",
            category: PlatformCategory::Education,
            url_pattern: "https://www.mendeley.com/profiles/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Zotero",
            category: PlatformCategory::Education,
            url_pattern: "https://www.zotero.org/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Duolingo",
            category: PlatformCategory::Education,
            url_pattern: "https://www.duolingo.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Busuu",
            category: PlatformCategory::Education,
            url_pattern: "https://www.busuu.com/en/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Memrise",
            category: PlatformCategory::Education,
            url_pattern: "https://www.memrise.com/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "LingQ",
            category: PlatformCategory::Education,
            url_pattern: "https://www.lingq.com/en/community/profile/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "italki",
            category: PlatformCategory::Education,
            url_pattern: "https://www.italki.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Tandem",
            category: PlatformCategory::Education,
            url_pattern: "https://www.tandem.net/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "HelloTalk",
            category: PlatformCategory::Education,
            url_pattern: "https://www.hellotalk.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Anki Web",
            category: PlatformCategory::Education,
            url_pattern: "https://ankiweb.net/shared/by/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Protocols.io",
            category: PlatformCategory::Education,
            url_pattern: "https://www.protocols.io/view/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Figshare",
            category: PlatformCategory::Education,
            url_pattern: "https://figshare.com/authors/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Zenodo",
            category: PlatformCategory::Education,
            url_pattern: "https://zenodo.org/search?q=owners:{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "OSF",
            category: PlatformCategory::Education,
            url_pattern: "https://osf.io/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "bioRxiv",
            category: PlatformCategory::Education,
            url_pattern: "https://www.biorxiv.org/search/author1:{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "arXiv",
            category: PlatformCategory::Education,
            url_pattern: "https://arxiv.org/search/?searchtype=author&query={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SSRN",
            category: PlatformCategory::Education,
            url_pattern: "https://papers.ssrn.com/sol3/cf_dev/AbsByAuth.cfm?per_id={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Codecademy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.codecademy.com/profiles/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "freeCodeCamp",
            category: PlatformCategory::Education,
            url_pattern: "https://www.freecodecamp.org/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "DataCamp",
            category: PlatformCategory::Education,
            url_pattern: "https://www.datacamp.com/portfolio/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Khan Academy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.khanacademy.org/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Udemy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.udemy.com/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Coursera",
            category: PlatformCategory::Education,
            url_pattern: "https://www.coursera.org/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Skillshare",
            category: PlatformCategory::Education,
            url_pattern: "https://www.skillshare.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Craftsy",
            category: PlatformCategory::Education,
            url_pattern: "https://www.craftsy.com/profile/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
    ]
}
