//! Gaming platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all gaming platforms
pub fn get_gaming_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "Steam",
            category: PlatformCategory::Gaming,
            url_pattern: "https://steamcommunity.com/id/{username}",
            detection: DetectionMethod::ResponseNotContains { text: "The specified profile could not be found".to_string() },
            ..Default::default()
        },
        Platform {
            name: "Twitch",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.twitch.tv/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Discord",
            category: PlatformCategory::Gaming,
            url_pattern: "https://discord.com/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Xbox Gamertag",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.xboxgamertag.com/search/{username}",
            detection: DetectionMethod::ResponseContains { found: "Gamerscore".to_string(), not_found: None },
            ..Default::default()
        },
        Platform {
            name: "PlayStation Network",
            category: PlatformCategory::Gaming,
            url_pattern: "https://psnprofiles.com/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Chess.com",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.chess.com/member/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Lichess",
            category: PlatformCategory::Gaming,
            url_pattern: "https://lichess.org/@/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Roblox",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.roblox.com/users/profile?username={username}",
            detection: DetectionMethod::ResponseNotContains { text: "Page cannot be found".to_string() },
            ..Default::default()
        },
        Platform {
            name: "Minecraft (NameMC)",
            category: PlatformCategory::Gaming,
            url_pattern: "https://namemc.com/profile/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Epic Games",
            category: PlatformCategory::Gaming,
            url_pattern: "https://fortnitetracker.com/profile/all/{username}",
            detection: DetectionMethod::ResponseNotContains { text: "Player Not Found".to_string() },
            ..Default::default()
        },
        Platform {
            name: "Battle.net",
            category: PlatformCategory::Gaming,
            url_pattern: "https://worldofwarcraft.blizzard.com/en-us/character/us/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "GOG",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.gog.com/u/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Itch.io",
            category: PlatformCategory::Gaming,
            url_pattern: "https://{username}.itch.io",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Speedrun.com",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.speedrun.com/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "RetroAchievements",
            category: PlatformCategory::Gaming,
            url_pattern: "https://retroachievements.org/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "FACEIT",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.faceit.com/en/players/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "ESEA",
            category: PlatformCategory::Gaming,
            url_pattern: "https://play.esea.net/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Tracker.gg",
            category: PlatformCategory::Gaming,
            url_pattern: "https://tracker.gg/valorant/profile/riot/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Osu!",
            category: PlatformCategory::Gaming,
            url_pattern: "https://osu.ppy.sh/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Newgrounds",
            category: PlatformCategory::Gaming,
            url_pattern: "https://{username}.newgrounds.com",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Kongregate",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.kongregate.com/accounts/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "OP.GG (LoL)",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.op.gg/summoners/na/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "U.GG",
            category: PlatformCategory::Gaming,
            url_pattern: "https://u.gg/lol/profile/na1/{username}/overview",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Blitz.gg",
            category: PlatformCategory::Gaming,
            url_pattern: "https://blitz.gg/lol/profile/na1/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Mobalytics",
            category: PlatformCategory::Gaming,
            url_pattern: "https://app.mobalytics.gg/lol/profile/na/{username}/overview",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Dotabuff",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.dotabuff.com/players/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "OpenDota",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.opendota.com/players/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "HLTV",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.hltv.org/player/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Liquipedia",
            category: PlatformCategory::Gaming,
            url_pattern: "https://liquipedia.net/commons/Special:Search/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Apex Legends Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://apex.tracker.gg/apex/profile/origin/{username}/overview",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Rocket League Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://rocketleague.tracker.network/rocket-league/profile/epic/{username}/overview",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Overwatch Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://overwatch.blizzard.com/en-us/career/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "R6 Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://r6.tracker.network/profile/pc/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Smite Guru",
            category: PlatformCategory::Gaming,
            url_pattern: "https://smite.guru/profile/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Paladins Guru",
            category: PlatformCategory::Gaming,
            url_pattern: "https://paladins.guru/profile/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "PlayerAuctions",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.playerauctions.com/seller/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "G2G",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.g2g.com/seller/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Faceit",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.faceit.com/en/players/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "ESEA",
            category: PlatformCategory::Gaming,
            url_pattern: "https://play.esea.net/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "GameBanana",
            category: PlatformCategory::Gaming,
            url_pattern: "https://gamebanana.com/members/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Mod DB",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.moddb.com/members/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Indie DB",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.indiedb.com/members/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "NexusMods",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.nexusmods.com/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "CurseForge",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.curseforge.com/members/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Modrinth",
            category: PlatformCategory::Gaming,
            url_pattern: "https://modrinth.com/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Planet Minecraft",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.planetminecraft.com/member/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "NameMC",
            category: PlatformCategory::Gaming,
            url_pattern: "https://namemc.com/profile/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Valorant Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://tracker.gg/valorant/profile/riot/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Fortnite Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://fortnitetracker.com/profile/all/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "COD Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://cod.tracker.gg/warzone/profile/atvi/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Destiny Tracker",
            category: PlatformCategory::Gaming,
            url_pattern: "https://destinytracker.com/destiny-2/profile/bungie/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Raider.IO",
            category: PlatformCategory::Gaming,
            url_pattern: "https://raider.io/characters/us/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "WoWProgress",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.wowprogress.com/character/us/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "WarcraftLogs",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.warcraftlogs.com/character/us/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "FF Logs",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.fflogs.com/character/id/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "GG.deals",
            category: PlatformCategory::Gaming,
            url_pattern: "https://gg.deals/user/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "IsThereAnyDeal",
            category: PlatformCategory::Gaming,
            url_pattern: "https://isthereanydeal.com/profile/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "VRChat",
            category: PlatformCategory::Gaming,
            url_pattern: "https://vrchat.com/home/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Rec Room",
            category: PlatformCategory::Gaming,
            url_pattern: "https://rec.net/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Roblox",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.roblox.com/user.aspx?username={username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Decentraland",
            category: PlatformCategory::Gaming,
            url_pattern: "https://decentraland.org/profile/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Spatial",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.spatial.io/@{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Speedrun.com",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.speedrun.com/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Osu!",
            category: PlatformCategory::Gaming,
            url_pattern: "https://osu.ppy.sh/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Chess.com",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.chess.com/member/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Lichess",
            category: PlatformCategory::Gaming,
            url_pattern: "https://lichess.org/@/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Backloggd",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.backloggd.com/u/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Grouvee",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.grouvee.com/user/{username}/",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "HowLongToBeat",
            category: PlatformCategory::Gaming,
            url_pattern: "https://howlongtobeat.com/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "GGn",
            category: PlatformCategory::Gaming,
            url_pattern: "https://gazellegames.net/user.php?action=search&search={username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Battlefy",
            category: PlatformCategory::Gaming,
            url_pattern: "https://battlefy.com/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Start.gg",
            category: PlatformCategory::Gaming,
            url_pattern: "https://start.gg/user/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Challonge",
            category: PlatformCategory::Gaming,
            url_pattern: "https://challonge.com/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Toornament",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.toornament.com/en_US/users/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Leagueofgraphs",
            category: PlatformCategory::Gaming,
            url_pattern: "https://www.leagueofgraphs.com/summoner/na/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Porofessor",
            category: PlatformCategory::Gaming,
            url_pattern: "https://porofessor.gg/live/na/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
        Platform {
            name: "Tracker Network",
            category: PlatformCategory::Gaming,
            url_pattern: "https://tracker.gg/profile/{username}",
            detection: DetectionMethod::StatusCode { found: 200, not_found: 404 },
            ..Default::default()
        },
    ]
}
