//! Business platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all business platforms
pub fn get_business_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "LinkedIn",
            category: PlatformCategory::Business,
            url_pattern: "https://www.linkedin.com/in/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "AngelList",
            category: PlatformCategory::Business,
            url_pattern: "https://angel.co/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Crunchbase",
            category: PlatformCategory::Business,
            url_pattern: "https://www.crunchbase.com/person/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "About.me",
            category: PlatformCategory::Business,
            url_pattern: "https://about.me/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Gravatar",
            category: PlatformCategory::Business,
            url_pattern: "https://gravatar.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Keybase",
            category: PlatformCategory::Business,
            url_pattern: "https://keybase.io/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ProductHunt",
            category: PlatformCategory::Business,
            url_pattern: "https://www.producthunt.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Patreon",
            category: PlatformCategory::Business,
            url_pattern: "https://www.patreon.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Ko-fi",
            category: PlatformCategory::Business,
            url_pattern: "https://ko-fi.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "BuyMeACoffee",
            category: PlatformCategory::Business,
            url_pattern: "https://www.buymeacoffee.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "XING",
            category: PlatformCategory::Business,
            url_pattern: "https://www.xing.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Hired",
            category: PlatformCategory::Business,
            url_pattern: "https://hired.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Glassdoor",
            category: PlatformCategory::Business,
            url_pattern: "https://www.glassdoor.com/member/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Freelancer",
            category: PlatformCategory::Business,
            url_pattern: "https://www.freelancer.com/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Upwork",
            category: PlatformCategory::Business,
            url_pattern: "https://www.upwork.com/freelancers/~{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Fiverr",
            category: PlatformCategory::Business,
            url_pattern: "https://www.fiverr.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Toptal",
            category: PlatformCategory::Business,
            url_pattern: "https://www.toptal.com/resume/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Contra",
            category: PlatformCategory::Business,
            url_pattern: "https://contra.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Polywork",
            category: PlatformCategory::Business,
            url_pattern: "https://www.polywork.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Read.cv",
            category: PlatformCategory::Business,
            url_pattern: "https://read.cv/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Peerlist",
            category: PlatformCategory::Business,
            url_pattern: "https://peerlist.io/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Indie Hackers",
            category: PlatformCategory::Business,
            url_pattern: "https://www.indiehackers.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ConvertKit",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.ck.page",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Wix",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.wixsite.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Squarespace",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.squarespace.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Weebly",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.weebly.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Webflow",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.webflow.io",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Carrd",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.carrd.co",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Wellfound",
            category: PlatformCategory::Business,
            url_pattern: "https://wellfound.com/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Hired",
            category: PlatformCategory::Business,
            url_pattern: "https://hired.com/talent/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Gun.io",
            category: PlatformCategory::Business,
            url_pattern: "https://gun.io/talent/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Turing",
            category: PlatformCategory::Business,
            url_pattern: "https://www.turing.com/developers/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Toptal",
            category: PlatformCategory::Business,
            url_pattern: "https://www.toptal.com/resume/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Torre",
            category: PlatformCategory::Business,
            url_pattern: "https://torre.co/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "RemoteOK",
            category: PlatformCategory::Business,
            url_pattern: "https://remoteok.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "We Work Remotely",
            category: PlatformCategory::Business,
            url_pattern: "https://weworkremotely.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Xing",
            category: PlatformCategory::Business,
            url_pattern: "https://www.xing.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Crunchbase",
            category: PlatformCategory::Business,
            url_pattern: "https://www.crunchbase.com/person/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "F6S",
            category: PlatformCategory::Business,
            url_pattern: "https://www.f6s.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ProductHunt",
            category: PlatformCategory::Business,
            url_pattern: "https://www.producthunt.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "BetaList",
            category: PlatformCategory::Business,
            url_pattern: "https://betalist.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Clarity.fm",
            category: PlatformCategory::Business,
            url_pattern: "https://clarity.fm/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MicroAcquire",
            category: PlatformCategory::Business,
            url_pattern: "https://acquire.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Fiverr",
            category: PlatformCategory::Business,
            url_pattern: "https://www.fiverr.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Upwork",
            category: PlatformCategory::Business,
            url_pattern: "https://www.upwork.com/freelancers/~{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Freelancer",
            category: PlatformCategory::Business,
            url_pattern: "https://www.freelancer.com/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "PeoplePerHour",
            category: PlatformCategory::Business,
            url_pattern: "https://www.peopleperhour.com/freelancer/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Guru",
            category: PlatformCategory::Business,
            url_pattern: "https://www.guru.com/freelancers/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Contra",
            category: PlatformCategory::Business,
            url_pattern: "https://contra.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Malt",
            category: PlatformCategory::Business,
            url_pattern: "https://www.malt.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Wix",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.wixsite.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Squarespace",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.squarespace.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Rover",
            category: PlatformCategory::Business,
            url_pattern: "https://www.rover.com/members/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Wag",
            category: PlatformCategory::Business,
            url_pattern: "https://wagwalking.com/dog-walker/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "CarGurus",
            category: PlatformCategory::Business,
            url_pattern: "https://www.cargurus.com/Cars/m-{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Turo",
            category: PlatformCategory::Business,
            url_pattern: "https://turo.com/drivers/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Notion",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.notion.site",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Slite",
            category: PlatformCategory::Business,
            url_pattern: "https://{username}.slite.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Coda",
            category: PlatformCategory::Business,
            url_pattern: "https://coda.io/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Airtable",
            category: PlatformCategory::Business,
            url_pattern: "https://airtable.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Miro",
            category: PlatformCategory::Business,
            url_pattern: "https://miro.com/app/board/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "G2",
            category: PlatformCategory::Business,
            url_pattern: "https://www.g2.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Capterra",
            category: PlatformCategory::Business,
            url_pattern: "https://www.capterra.com/reviewer/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Trustpilot",
            category: PlatformCategory::Business,
            url_pattern: "https://www.trustpilot.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Polywork",
            category: PlatformCategory::Business,
            url_pattern: "https://www.polywork.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Read.cv",
            category: PlatformCategory::Business,
            url_pattern: "https://read.cv/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Contra",
            category: PlatformCategory::Business,
            url_pattern: "https://contra.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
    ]
}
