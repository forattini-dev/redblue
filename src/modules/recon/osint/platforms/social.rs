//! Social platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all social platforms
pub fn get_social_platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "Twitter/X",
      category: PlatformCategory::Social,
      url_pattern: "https://twitter.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Instagram",
      category: PlatformCategory::Social,
      url_pattern: "https://www.instagram.com/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Facebook",
      category: PlatformCategory::Social,
      url_pattern: "https://www.facebook.com/{username}",
      detection: DetectionMethod::ResponseNotContains {
        text: "This content isn't available".to_string(),
      },
      ..Default::default()
    },
    Platform {
      name: "TikTok",
      category: PlatformCategory::Social,
      url_pattern: "https://www.tiktok.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Reddit",
      category: PlatformCategory::Social,
      url_pattern: "https://www.reddit.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pinterest",
      category: PlatformCategory::Social,
      url_pattern: "https://www.pinterest.com/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tumblr",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.tumblr.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mastodon (mastodon.social)",
      category: PlatformCategory::Social,
      url_pattern: "https://mastodon.social/@{username}",
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
      name: "Snapchat",
      category: PlatformCategory::Social,
      url_pattern: "https://www.snapchat.com/add/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "VK",
      category: PlatformCategory::Social,
      url_pattern: "https://vk.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Telegram",
      category: PlatformCategory::Social,
      url_pattern: "https://t.me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Clubhouse",
      category: PlatformCategory::Social,
      url_pattern: "https://www.clubhouse.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Imgur",
      category: PlatformCategory::Social,
      url_pattern: "https://imgur.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Giphy",
      category: PlatformCategory::Social,
      url_pattern: "https://giphy.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "9GAG",
      category: PlatformCategory::Social,
      url_pattern: "https://9gag.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mix (StumbleUpon)",
      category: PlatformCategory::Social,
      url_pattern: "https://mix.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Parler",
      category: PlatformCategory::Social,
      url_pattern: "https://parler.com/profile/{username}",
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
      name: "Weibo",
      category: PlatformCategory::Social,
      url_pattern: "https://weibo.com/n/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Douyin (TikTok China)",
      category: PlatformCategory::Social,
      url_pattern: "https://www.douyin.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zhihu",
      category: PlatformCategory::Social,
      url_pattern: "https://www.zhihu.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "LINE",
      category: PlatformCategory::Social,
      url_pattern: "https://line.me/R/ti/p/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "KakaoTalk",
      category: PlatformCategory::Social,
      url_pattern: "https://open.kakao.com/o/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Naver Blog",
      category: PlatformCategory::Social,
      url_pattern: "https://blog.naver.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Odnoklassniki (OK.ru)",
      category: PlatformCategory::Social,
      url_pattern: "https://ok.ru/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pikabu",
      category: PlatformCategory::Social,
      url_pattern: "https://pikabu.ru/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Yandex Zen",
      category: PlatformCategory::Social,
      url_pattern: "https://zen.yandex.ru/id/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ameblo",
      category: PlatformCategory::Social,
      url_pattern: "https://ameblo.jp/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "note.com",
      category: PlatformCategory::Social,
      url_pattern: "https://note.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hatena",
      category: PlatformCategory::Social,
      url_pattern: "https://profile.hatena.ne.jp/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ShareChat",
      category: PlatformCategory::Social,
      url_pattern: "https://sharechat.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Koo",
      category: PlatformCategory::Social,
      url_pattern: "https://www.kooapp.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Farcaster",
      category: PlatformCategory::Social,
      url_pattern: "https://warpcast.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hive",
      category: PlatformCategory::Social,
      url_pattern: "https://hive.blog/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Steemit",
      category: PlatformCategory::Social,
      url_pattern: "https://steemit.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tildes",
      category: PlatformCategory::Social,
      url_pattern: "https://tildes.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Squabbles",
      category: PlatformCategory::Social,
      url_pattern: "https://squabbles.io/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Askfm",
      category: PlatformCategory::Social,
      url_pattern: "https://ask.fm/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CuriousCat",
      category: PlatformCategory::Social,
      url_pattern: "https://curiouscat.live/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Retrospring",
      category: PlatformCategory::Social,
      url_pattern: "https://retrospring.net/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "NGL",
      category: PlatformCategory::Social,
      url_pattern: "https://ngl.link/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tellonym",
      category: PlatformCategory::Social,
      url_pattern: "https://tellonym.me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Substack",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.substack.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ghost",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.ghost.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Buttondown",
      category: PlatformCategory::Social,
      url_pattern: "https://buttondown.email/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Revue",
      category: PlatformCategory::Social,
      url_pattern: "https://www.getrevue.co/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Beehiiv",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.beehiiv.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Blogger",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.blogspot.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "WordPress.com",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.wordpress.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Foursquare",
      category: PlatformCategory::Social,
      url_pattern: "https://foursquare.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Swarm",
      category: PlatformCategory::Social,
      url_pattern: "https://swarmapp.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Weibo",
      category: PlatformCategory::Social,
      url_pattern: "https://weibo.com/n/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zhihu",
      category: PlatformCategory::Social,
      url_pattern: "https://www.zhihu.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Douban",
      category: PlatformCategory::Social,
      url_pattern: "https://www.douban.com/people/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Xiaohongshu",
      category: PlatformCategory::Social,
      url_pattern: "https://www.xiaohongshu.com/user/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Baidu Tieba",
      category: PlatformCategory::Social,
      url_pattern: "https://tieba.baidu.com/home/main?un={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Naver Blog",
      category: PlatformCategory::Social,
      url_pattern: "https://blog.naver.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Naver Cafe",
      category: PlatformCategory::Social,
      url_pattern: "https://cafe.naver.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kakao Story",
      category: PlatformCategory::Social,
      url_pattern: "https://story.kakao.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "VK",
      category: PlatformCategory::Social,
      url_pattern: "https://vk.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OK.ru",
      category: PlatformCategory::Social,
      url_pattern: "https://ok.ru/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pikabu",
      category: PlatformCategory::Social,
      url_pattern: "https://pikabu.ru/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mail.ru",
      category: PlatformCategory::Social,
      url_pattern: "https://my.mail.ru/mail/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Baaz",
      category: PlatformCategory::Social,
      url_pattern: "https://baaz.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Taringa",
      category: PlatformCategory::Social,
      url_pattern: "https://www.taringa.net/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ssjoy",
      category: PlatformCategory::Social,
      url_pattern: "https://www.ssjoy.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "About.me",
      category: PlatformCategory::Social,
      url_pattern: "https://about.me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gravatar",
      category: PlatformCategory::Social,
      url_pattern: "https://gravatar.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mastodon.social",
      category: PlatformCategory::Social,
      url_pattern: "https://mastodon.social/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fosstodon",
      category: PlatformCategory::Social,
      url_pattern: "https://fosstodon.org/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hachyderm",
      category: PlatformCategory::Social,
      url_pattern: "https://hachyderm.io/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Infosec.exchange",
      category: PlatformCategory::Social,
      url_pattern: "https://infosec.exchange/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Techhub.social",
      category: PlatformCategory::Social,
      url_pattern: "https://techhub.social/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mstdn.social",
      category: PlatformCategory::Social,
      url_pattern: "https://mstdn.social/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
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
    Platform {
      name: "Snapchat",
      category: PlatformCategory::Social,
      url_pattern: "https://www.snapchat.com/add/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "BeReal",
      category: PlatformCategory::Social,
      url_pattern: "https://bere.al/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lemon8",
      category: PlatformCategory::Social,
      url_pattern: "https://www.lemon8-app.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Clapper",
      category: PlatformCategory::Social,
      url_pattern: "https://clapperapp.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Likee",
      category: PlatformCategory::Social,
      url_pattern: "https://likee.video/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Triller",
      category: PlatformCategory::Social,
      url_pattern: "https://triller.co/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dubsmash",
      category: PlatformCategory::Social,
      url_pattern: "https://dubsmash.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zepeto",
      category: PlatformCategory::Social,
      url_pattern: "https://zepeto.me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Goodreads",
      category: PlatformCategory::Social,
      url_pattern: "https://www.goodreads.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Storygraph",
      category: PlatformCategory::Social,
      url_pattern: "https://app.thestorygraph.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "LibraryThing",
      category: PlatformCategory::Social,
      url_pattern: "https://www.librarything.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Literal",
      category: PlatformCategory::Social,
      url_pattern: "https://literal.club/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bookwyrm",
      category: PlatformCategory::Social,
      url_pattern: "https://bookwyrm.social/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hardcover",
      category: PlatformCategory::Social,
      url_pattern: "https://hardcover.app/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Letterboxd",
      category: PlatformCategory::Social,
      url_pattern: "https://letterboxd.com/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Serializd",
      category: PlatformCategory::Social,
      url_pattern: "https://www.serializd.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "FilmAffinity",
      category: PlatformCategory::Social,
      url_pattern: "https://www.filmaffinity.com/en/userratings.php?user_id={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TMDb",
      category: PlatformCategory::Social,
      url_pattern: "https://www.themoviedb.org/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mubi",
      category: PlatformCategory::Social,
      url_pattern: "https://mubi.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Criticker",
      category: PlatformCategory::Social,
      url_pattern: "https://www.criticker.com/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ICheckMovies",
      category: PlatformCategory::Social,
      url_pattern: "https://www.icheckmovies.com/profiles/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Recipe Key",
      category: PlatformCategory::Social,
      url_pattern: "https://recipekey.com/members/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Forkd",
      category: PlatformCategory::Social,
      url_pattern: "https://www.forkd.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "BigOven",
      category: PlatformCategory::Social,
      url_pattern: "https://www.bigoven.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Epicurious",
      category: PlatformCategory::Social,
      url_pattern: "https://www.epicurious.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Strava",
      category: PlatformCategory::Social,
      url_pattern: "https://www.strava.com/athletes/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MyFitnessPal",
      category: PlatformCategory::Social,
      url_pattern: "https://www.myfitnesspal.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cronometer",
      category: PlatformCategory::Social,
      url_pattern: "https://cronometer.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Freeletics",
      category: PlatformCategory::Social,
      url_pattern: "https://www.freeletics.com/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Hevy",
      category: PlatformCategory::Social,
      url_pattern: "https://hevy.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "JEFIT",
      category: PlatformCategory::Social,
      url_pattern: "https://www.jefit.com/members/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Strong",
      category: PlatformCategory::Social,
      url_pattern: "https://strong.app/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fitocracy",
      category: PlatformCategory::Social,
      url_pattern: "https://www.fitocracy.com/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mixi",
      category: PlatformCategory::Social,
      url_pattern: "https://mixi.jp/show_friend.pl?id={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "LINE",
      category: PlatformCategory::Social,
      url_pattern: "https://timeline.line.me/user/_d{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Kakaotalk",
      category: PlatformCategory::Social,
      url_pattern: "https://open.kakao.com/me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Weverse",
      category: PlatformCategory::Social,
      url_pattern: "https://weverse.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Universe",
      category: PlatformCategory::Social,
      url_pattern: "https://www.universe-official.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Marshmallow",
      category: PlatformCategory::Social,
      url_pattern: "https://marshmallow-qa.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Peing",
      category: PlatformCategory::Social,
      url_pattern: "https://peing.net/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lit.link",
      category: PlatformCategory::Social,
      url_pattern: "https://lit.link/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Profcard",
      category: PlatformCategory::Social,
      url_pattern: "https://profcard.info/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lens Protocol",
      category: PlatformCategory::Social,
      url_pattern: "https://hey.xyz/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Carrd",
      category: PlatformCategory::Social,
      url_pattern: "https://{username}.carrd.co",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Strava",
      category: PlatformCategory::Social,
      url_pattern: "https://www.strava.com/athletes/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Garmin Connect",
      category: PlatformCategory::Social,
      url_pattern: "https://connect.garmin.com/modern/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Nike Run Club",
      category: PlatformCategory::Social,
      url_pattern: "https://www.nike.com/member/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Map My Run",
      category: PlatformCategory::Social,
      url_pattern: "https://www.mapmyrun.com/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Komoot",
      category: PlatformCategory::Social,
      url_pattern: "https://www.komoot.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "AllTrails",
      category: PlatformCategory::Social,
      url_pattern: "https://www.alltrails.com/members/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Peloton",
      category: PlatformCategory::Social,
      url_pattern: "https://members.onepeloton.com/members/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zwift",
      category: PlatformCategory::Social,
      url_pattern: "https://www.zwift.com/athlete/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TripAdvisor",
      category: PlatformCategory::Social,
      url_pattern: "https://www.tripadvisor.com/Profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Couchsurfing",
      category: PlatformCategory::Social,
      url_pattern: "https://www.couchsurfing.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Polarsteps",
      category: PlatformCategory::Social,
      url_pattern: "https://www.polarsteps.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Travello",
      category: PlatformCategory::Social,
      url_pattern: "https://www.travelloapp.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rome2Rio",
      category: PlatformCategory::Social,
      url_pattern: "https://www.rome2rio.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Untappd",
      category: PlatformCategory::Social,
      url_pattern: "https://untappd.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vivino",
      category: PlatformCategory::Social,
      url_pattern: "https://www.vivino.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Yelp",
      category: PlatformCategory::Social,
      url_pattern: "https://www.yelp.com/user_details?userid={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Allrecipes",
      category: PlatformCategory::Social,
      url_pattern: "https://www.allrecipes.com/cook/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Food52",
      category: PlatformCategory::Social,
      url_pattern: "https://food52.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "BabyCenter",
      category: PlatformCategory::Social,
      url_pattern: "https://community.babycenter.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "What to Expect",
      category: PlatformCategory::Social,
      url_pattern: "https://community.whattoexpect.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mumsnet",
      category: PlatformCategory::Social,
      url_pattern: "https://www.mumsnet.com/Talk/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "BarkHappy",
      category: PlatformCategory::Social,
      url_pattern: "https://www.barkhappy.com/users/{username}",
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
      name: "Houzz",
      category: PlatformCategory::Social,
      url_pattern: "https://www.houzz.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ShareChat",
      category: PlatformCategory::Social,
      url_pattern: "https://sharechat.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "VK",
      category: PlatformCategory::Social,
      url_pattern: "https://vk.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OK.ru",
      category: PlatformCategory::Social,
      url_pattern: "https://ok.ru/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pikabu",
      category: PlatformCategory::Social,
      url_pattern: "https://pikabu.ru/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ancestry",
      category: PlatformCategory::Social,
      url_pattern: "https://www.ancestry.com/family-tree/person/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MyHeritage",
      category: PlatformCategory::Social,
      url_pattern: "https://www.myheritage.com/member-{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "FamilySearch",
      category: PlatformCategory::Social,
      url_pattern: "https://www.familysearch.org/tree/person/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Geni",
      category: PlatformCategory::Social,
      url_pattern: "https://www.geni.com/people/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bento",
      category: PlatformCategory::Social,
      url_pattern: "https://bento.me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
