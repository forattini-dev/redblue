use super::super::types::{DetectionMethod, Platform, PlatformCategory};

pub fn platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "Counter.social",
      category: PlatformCategory::Social,
      url_pattern: "https://counter.social/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Post.news",
      category: PlatformCategory::Social,
      url_pattern: "https://post.news/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Spoutible",
      category: PlatformCategory::Social,
      url_pattern: "https://spoutible.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cohost",
      category: PlatformCategory::Social,
      url_pattern: "https://cohost.org/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pillowfort",
      category: PlatformCategory::Social,
      url_pattern: "https://www.pillowfort.social/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dreamwidth",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.dreamwidth.org",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Imzy",
      category: PlatformCategory::Social,
      url_pattern: "https://www.imzy.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Diaspora",
      category: PlatformCategory::Social,
      url_pattern: "https://diaspora.social/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ResetEra",
      category: PlatformCategory::Social,
      url_pattern: "https://www.resetera.com/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "NeoGAF",
      category: PlatformCategory::Social,
      url_pattern: "https://www.neogaf.com/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SomethingAwful",
      category: PlatformCategory::Social,
      url_pattern:
        "https://forums.somethingawful.com/member.php?action=getinfo&username={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kiwi Farms",
      category: PlatformCategory::Social,
      url_pattern: "https://kiwifarms.net/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ovarit",
      category: PlatformCategory::Social,
      url_pattern: "https://ovarit.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Saidit",
      category: PlatformCategory::Social,
      url_pattern: "https://saidit.net/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ruqqus",
      category: PlatformCategory::Social,
      url_pattern: "https://ruqqus.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Voat",
      category: PlatformCategory::Social,
      url_pattern: "https://voat.co/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Scored",
      category: PlatformCategory::Social,
      url_pattern: "https://scored.co/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lemmy",
      category: PlatformCategory::Social,
      url_pattern: "https://lemmy.ml/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Beehaw",
      category: PlatformCategory::Social,
      url_pattern: "https://beehaw.org/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kbin",
      category: PlatformCategory::Social,
      url_pattern: "https://kbin.social/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Linktree",
      category: PlatformCategory::Social,
      url_pattern: "https://linktr.ee/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bio.link",
      category: PlatformCategory::Social,
      url_pattern: "https://bio.link/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Beacons",
      category: PlatformCategory::Social,
      url_pattern: "https://beacons.ai/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Campsite",
      category: PlatformCategory::Social,
      url_pattern: "https://campsite.bio/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Snipfeed",
      category: PlatformCategory::Social,
      url_pattern: "https://snipfeed.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Stan Store",
      category: PlatformCategory::Social,
      url_pattern: "https://stan.store/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Koji",
      category: PlatformCategory::Social,
      url_pattern: "https://koji.to/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lyntr",
      category: PlatformCategory::Social,
      url_pattern: "https://lyntr.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lnk.bio",
      category: PlatformCategory::Social,
      url_pattern: "https://lnk.bio/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Taplink",
      category: PlatformCategory::Social,
      url_pattern: "https://taplink.cc/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Solo.to",
      category: PlatformCategory::Social,
      url_pattern: "https://solo.to/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Milkshake",
      category: PlatformCategory::Social,
      url_pattern: "https://msha.ke/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MyAnimeList",
      category: PlatformCategory::Social,
      url_pattern: "https://myanimelist.net/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "AniList",
      category: PlatformCategory::Social,
      url_pattern: "https://anilist.co/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kitsu",
      category: PlatformCategory::Social,
      url_pattern: "https://kitsu.io/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Anime-Planet",
      category: PlatformCategory::Social,
      url_pattern: "https://www.anime-planet.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Shikimori",
      category: PlatformCategory::Social,
      url_pattern: "https://shikimori.one/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bangumi",
      category: PlatformCategory::Social,
      url_pattern: "https://bgm.tv/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MangaDex",
      category: PlatformCategory::Social,
      url_pattern: "https://mangadex.org/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MangaUpdates",
      category: PlatformCategory::Social,
      url_pattern: "https://www.mangaupdates.com/member/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cars.com",
      category: PlatformCategory::Social,
      url_pattern: "https://www.cars.com/dealers/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bring a Trailer",
      category: PlatformCategory::Social,
      url_pattern: "https://bringatrailer.com/member/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cars & Bids",
      category: PlatformCategory::Social,
      url_pattern: "https://carsandbids.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Carwow",
      category: PlatformCategory::Social,
      url_pattern: "https://www.carwow.co.uk/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ESPN Fantasy",
      category: PlatformCategory::Social,
      url_pattern: "https://fantasy.espn.com/team/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Sleeper",
      category: PlatformCategory::Social,
      url_pattern: "https://sleeper.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Yahoo Fantasy",
      category: PlatformCategory::Social,
      url_pattern: "https://profiles.sports.yahoo.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Typefully",
      category: PlatformCategory::Social,
      url_pattern: "https://typefully.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Telegraph",
      category: PlatformCategory::Social,
      url_pattern: "https://telegra.ph/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Amino",
      category: PlatformCategory::Social,
      url_pattern: "https://aminoapps.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Minds",
      category: PlatformCategory::Social,
      url_pattern: "https://www.minds.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gab",
      category: PlatformCategory::Social,
      url_pattern: "https://gab.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Parler",
      category: PlatformCategory::Social,
      url_pattern: "https://parler.com/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Truth Social",
      category: PlatformCategory::Social,
      url_pattern: "https://truthsocial.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gettr",
      category: PlatformCategory::Social,
      url_pattern: "https://gettr.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MeWe",
      category: PlatformCategory::Social,
      url_pattern: "https://mewe.com/i/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CloutHub",
      category: PlatformCategory::Social,
      url_pattern: "https://app.clouthub.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OnlyFans",
      category: PlatformCategory::Social,
      url_pattern: "https://onlyfans.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fansly",
      category: PlatformCategory::Social,
      url_pattern: "https://fansly.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "LoyalFans",
      category: PlatformCategory::Social,
      url_pattern: "https://www.loyalfans.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Discord",
      category: PlatformCategory::Social,
      url_pattern: "https://discord.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Guilded",
      category: PlatformCategory::Social,
      url_pattern: "https://www.guilded.gg/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TeamSpeak",
      category: PlatformCategory::Social,
      url_pattern: "https://www.myteamspeak.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Revolt",
      category: PlatformCategory::Social,
      url_pattern: "https://app.revolt.chat/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Matrix",
      category: PlatformCategory::Social,
      url_pattern: "https://matrix.to/#/@{username}:matrix.org",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pocket",
      category: PlatformCategory::Social,
      url_pattern: "https://getpocket.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Instapaper",
      category: PlatformCategory::Social,
      url_pattern: "https://www.instapaper.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Raindrop.io",
      category: PlatformCategory::Social,
      url_pattern: "https://raindrop.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Flipboard",
      category: PlatformCategory::Social,
      url_pattern: "https://flipboard.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Feedly",
      category: PlatformCategory::Social,
      url_pattern: "https://feedly.com/i/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Inoreader",
      category: PlatformCategory::Social,
      url_pattern: "https://www.inoreader.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Threads",
      category: PlatformCategory::Social,
      url_pattern: "https://www.threads.net/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bluesky",
      category: PlatformCategory::Social,
      url_pattern: "https://bsky.app/profile/{username}.bsky.social",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Nostr",
      category: PlatformCategory::Social,
      url_pattern: "https://nostr.band/npub{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pebble",
      category: PlatformCategory::Social,
      url_pattern: "https://pebble.is/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hive Social",
      category: PlatformCategory::Social,
      url_pattern: "https://www.hivesocial.app/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tribel",
      category: PlatformCategory::Social,
      url_pattern: "https://www.tribel.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Retalk",
      category: PlatformCategory::Social,
      url_pattern: "https://www.retalk.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ello",
      category: PlatformCategory::Social,
      url_pattern: "https://ello.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vero",
      category: PlatformCategory::Social,
      url_pattern: "https://vero.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
