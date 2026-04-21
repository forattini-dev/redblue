use super::super::types::{DetectionMethod, Platform, PlatformCategory};

pub fn platforms() -> Vec<Platform> {
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
  ]
}
