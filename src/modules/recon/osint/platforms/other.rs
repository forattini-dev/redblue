//! Other platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all other platforms
pub fn get_other_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "XDA Developers",
            category: PlatformCategory::Other,
            url_pattern: "https://forum.xda-developers.com/m/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SlashDot",
            category: PlatformCategory::Other,
            url_pattern: "https://slashdot.org/~{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Disqus",
            category: PlatformCategory::Other,
            url_pattern: "https://disqus.com/by/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Lobsters",
            category: PlatformCategory::Other,
            url_pattern: "https://lobste.rs/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Lemmy (lemmy.world)",
            category: PlatformCategory::Other,
            url_pattern: "https://lemmy.world/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Kbin (kbin.social)",
            category: PlatformCategory::Other,
            url_pattern: "https://kbin.social/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Linktree",
            category: PlatformCategory::Other,
            url_pattern: "https://linktr.ee/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Carrd",
            category: PlatformCategory::Other,
            url_pattern: "https://{username}.carrd.co",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "bio.link",
            category: PlatformCategory::Other,
            url_pattern: "https://bio.link/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Beacons",
            category: PlatformCategory::Other,
            url_pattern: "https://beacons.ai/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Stan.store",
            category: PlatformCategory::Other,
            url_pattern: "https://stan.store/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Letterboxd",
            category: PlatformCategory::Other,
            url_pattern: "https://letterboxd.com/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Goodreads",
            category: PlatformCategory::Other,
            url_pattern: "https://www.goodreads.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MyAnimeList",
            category: PlatformCategory::Other,
            url_pattern: "https://myanimelist.net/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "AniList",
            category: PlatformCategory::Other,
            url_pattern: "https://anilist.co/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Rate Your Music",
            category: PlatformCategory::Other,
            url_pattern: "https://rateyourmusic.com/~{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Untappd",
            category: PlatformCategory::Other,
            url_pattern: "https://untappd.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Vivino",
            category: PlatformCategory::Other,
            url_pattern: "https://www.vivino.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Strava",
            category: PlatformCategory::Other,
            url_pattern: "https://www.strava.com/athletes/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Komoot",
            category: PlatformCategory::Other,
            url_pattern: "https://www.komoot.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "AllTrails",
            category: PlatformCategory::Other,
            url_pattern: "https://www.alltrails.com/members/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Geocaching",
            category: PlatformCategory::Other,
            url_pattern: "https://www.geocaching.com/p/default.aspx?u={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Garmin Connect",
            category: PlatformCategory::Other,
            url_pattern: "https://connect.garmin.com/modern/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Nike Run Club",
            category: PlatformCategory::Other,
            url_pattern: "https://www.nike.com/member/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Peloton",
            category: PlatformCategory::Other,
            url_pattern: "https://members.onepeloton.com/members/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MapMyRun",
            category: PlatformCategory::Other,
            url_pattern: "https://www.mapmyrun.com/profile/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Fitbit",
            category: PlatformCategory::Other,
            url_pattern: "https://www.fitbit.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Zwift",
            category: PlatformCategory::Other,
            url_pattern: "https://www.zwift.com/athlete/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "TrainingPeaks",
            category: PlatformCategory::Other,
            url_pattern: "https://www.trainingpeaks.com/athlete/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Ride with GPS",
            category: PlatformCategory::Other,
            url_pattern: "https://ridewithgps.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Yelp",
            category: PlatformCategory::Other,
            url_pattern: "https://www.yelp.com/user_details?userid={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "TripAdvisor",
            category: PlatformCategory::Other,
            url_pattern: "https://www.tripadvisor.com/Profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Trustpilot",
            category: PlatformCategory::Other,
            url_pattern: "https://www.trustpilot.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "G2 (Software Reviews)",
            category: PlatformCategory::Other,
            url_pattern: "https://www.g2.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Capterra",
            category: PlatformCategory::Other,
            url_pattern: "https://www.capterra.com/reviewer/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Polarsteps",
            category: PlatformCategory::Other,
            url_pattern: "https://www.polarsteps.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "FindPenguins",
            category: PlatformCategory::Other,
            url_pattern: "https://findpenguins.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "TravelBlog",
            category: PlatformCategory::Other,
            url_pattern: "https://www.travelblog.org/Bloggers/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "WorldNomads",
            category: PlatformCategory::Other,
            url_pattern: "https://journals.worldnomads.com/traveller/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Couchsurfing",
            category: PlatformCategory::Other,
            url_pattern: "https://www.couchsurfing.com/people/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "BeWelcome",
            category: PlatformCategory::Other,
            url_pattern: "https://www.bewelcome.org/members/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Trustroots",
            category: PlatformCategory::Other,
            url_pattern: "https://www.trustroots.org/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "AllRecipes",
            category: PlatformCategory::Other,
            url_pattern: "https://www.allrecipes.com/cook/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Food52",
            category: PlatformCategory::Other,
            url_pattern: "https://food52.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Cookpad",
            category: PlatformCategory::Other,
            url_pattern: "https://cookpad.com/us/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Tasty",
            category: PlatformCategory::Other,
            url_pattern: "https://tasty.co/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Yummly",
            category: PlatformCategory::Other,
            url_pattern: "https://www.yummly.com/profile/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Trakt",
            category: PlatformCategory::Other,
            url_pattern: "https://trakt.tv/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "TV Time",
            category: PlatformCategory::Other,
            url_pattern: "https://www.tvtime.com/user/{username}/profile",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SeriesGuide",
            category: PlatformCategory::Other,
            url_pattern: "https://seriesguide.cloud/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "IMDb",
            category: PlatformCategory::Other,
            url_pattern: "https://www.imdb.com/user/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Plex",
            category: PlatformCategory::Other,
            url_pattern: "https://plex.tv/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "JustWatch",
            category: PlatformCategory::Other,
            url_pattern: "https://www.justwatch.com/us/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Simkl",
            category: PlatformCategory::Other,
            url_pattern: "https://simkl.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SerieAdictos",
            category: PlatformCategory::Other,
            url_pattern: "https://www.serieadictos.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "BetaSeries",
            category: PlatformCategory::Other,
            url_pattern: "https://www.betaseries.com/membre/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Trackt",
            category: PlatformCategory::Other,
            url_pattern: "https://www.trackt.it/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Bookmate",
            category: PlatformCategory::Other,
            url_pattern: "https://bookmate.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
    ]
}
