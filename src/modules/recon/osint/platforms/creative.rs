//! Creative platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all creative platforms
pub fn get_creative_platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "Behance",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.behance.net/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dribbble",
      category: PlatformCategory::Creative,
      url_pattern: "https://dribbble.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "DeviantArt",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.deviantart.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ArtStation",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.artstation.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Flickr",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.flickr.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "500px",
      category: PlatformCategory::Creative,
      url_pattern: "https://500px.com/p/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Figma",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.figma.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Unsplash",
      category: PlatformCategory::Creative,
      url_pattern: "https://unsplash.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pexels",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.pexels.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pixabay",
      category: PlatformCategory::Creative,
      url_pattern: "https://pixabay.com/users/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Shutterstock",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.shutterstock.com/g/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Artfol",
      category: PlatformCategory::Creative,
      url_pattern: "https://artfol.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pixiv",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.pixiv.net/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Sketchfab",
      category: PlatformCategory::Creative,
      url_pattern: "https://sketchfab.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Thingiverse",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.thingiverse.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Wattpad",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.wattpad.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Archive of Our Own (AO3)",
      category: PlatformCategory::Creative,
      url_pattern: "https://archiveofourown.org/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "FanFiction.net",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.fanfiction.net/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Webnovel",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.webnovel.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Canva",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.canva.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Notion",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.notion.site",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Miro",
      category: PlatformCategory::Creative,
      url_pattern: "https://miro.com/app/board/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cults3D",
      category: PlatformCategory::Creative,
      url_pattern: "https://cults3d.com/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MyMiniFactory",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.myminifactory.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Printables",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.printables.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ravelry",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.ravelry.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Instructables",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.instructables.com/member/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fotolog",
      category: PlatformCategory::Creative,
      url_pattern: "https://fotolog.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "VSCO",
      category: PlatformCategory::Creative,
      url_pattern: "https://vsco.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tenor",
      category: PlatformCategory::Creative,
      url_pattern: "https://tenor.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "EyeEm",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.eyeem.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Yupoo",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.yupoo.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ViewBug",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.viewbug.com/member/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "1x",
      category: PlatformCategory::Creative,
      url_pattern: "https://1x.com/member/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "YouPic",
      category: PlatformCategory::Creative,
      url_pattern: "https://youpic.com/photographer/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "GuruShots",
      category: PlatformCategory::Creative,
      url_pattern: "https://gurushots.com/{username}/photos",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Glass (Photo)",
      category: PlatformCategory::Creative,
      url_pattern: "https://glass.photo/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cargo",
      category: PlatformCategory::Creative,
      url_pattern: "https://cargo.site/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Format",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.format.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Portfoliobox",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.portfoliobox.net",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "StoryCraft",
      category: PlatformCategory::Creative,
      url_pattern: "https://storycraft.app/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Royal Road",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.royalroad.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tapas",
      category: PlatformCategory::Creative,
      url_pattern: "https://tapas.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Webtoon",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.webtoons.com/creator/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Comicfury",
      category: PlatformCategory::Creative,
      url_pattern: "https://comicfury.com/profile.php?username={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SmackJeeves",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.smackjeeves.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "99designs",
      category: PlatformCategory::Creative,
      url_pattern: "https://99designs.com/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Designspiration",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.designspiration.com/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Creativemarket",
      category: PlatformCategory::Creative,
      url_pattern: "https://creativemarket.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Envato",
      category: PlatformCategory::Creative,
      url_pattern: "https://themeforest.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "GraphicRiver",
      category: PlatformCategory::Creative,
      url_pattern: "https://graphicriver.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Videohive",
      category: PlatformCategory::Creative,
      url_pattern: "https://videohive.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Audiojungle",
      category: PlatformCategory::Creative,
      url_pattern: "https://audiojungle.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Codecanyon",
      category: PlatformCategory::Creative,
      url_pattern: "https://codecanyon.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "3DOcean",
      category: PlatformCategory::Creative,
      url_pattern: "https://3docean.net/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Pngtree",
      category: PlatformCategory::Creative,
      url_pattern: "https://pngtree.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Vecteezy",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.vecteezy.com/members/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Freepik",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.freepik.com/author/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Icons8",
      category: PlatformCategory::Creative,
      url_pattern: "https://icons8.com/creator/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Flaticon",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.flaticon.com/authors/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Thingiverse",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.thingiverse.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Printables",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.printables.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cults3D",
      category: PlatformCategory::Creative,
      url_pattern: "https://cults3d.com/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "MyMiniFactory",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.myminifactory.com/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cara",
      category: PlatformCategory::Creative,
      url_pattern: "https://cara.app/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Artfol",
      category: PlatformCategory::Creative,
      url_pattern: "https://artfol.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Toyhouse",
      category: PlatformCategory::Creative,
      url_pattern: "https://toyhou.se/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Inkblot",
      category: PlatformCategory::Creative,
      url_pattern: "https://inkblot.art/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Artistree",
      category: PlatformCategory::Creative,
      url_pattern: "https://artistree.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Artbreeder",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.artbreeder.com/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Newgrounds",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.newgrounds.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "FurAffinity",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.furaffinity.net/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Weasyl",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.weasyl.com/~{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SoFurry",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.sofurry.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "InkBunny",
      category: PlatformCategory::Creative,
      url_pattern: "https://inkbunny.net/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "e621",
      category: PlatformCategory::Creative,
      url_pattern: "https://e621.net/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Derpibooru",
      category: PlatformCategory::Creative,
      url_pattern: "https://derpibooru.org/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Danbooru",
      category: PlatformCategory::Creative,
      url_pattern: "https://danbooru.donmai.us/users?name={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rule34",
      category: PlatformCategory::Creative,
      url_pattern: "https://rule34.xxx/index.php?page=account&s=profile&uname={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Gelbooru",
      category: PlatformCategory::Creative,
      url_pattern: "https://gelbooru.com/index.php?page=account&s=profile&uname={username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Archive of Our Own",
      category: PlatformCategory::Creative,
      url_pattern: "https://archiveofourown.org/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "FanFiction.net",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.fanfiction.net/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Quotev",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.quotev.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Scribophile",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.scribophile.com/authors/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Penana",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.penana.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Inkitt",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.inkitt.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Reedsy",
      category: PlatformCategory::Creative,
      url_pattern: "https://reedsy.com/discovery/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "NovelUpdates",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.novelupdates.com/user/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ScribbleHub",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.scribblehub.com/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "500px",
      category: PlatformCategory::Creative,
      url_pattern: "https://500px.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Flickr",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.flickr.com/people/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SmugMug",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.smugmug.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PhotoBucket",
      category: PlatformCategory::Creative,
      url_pattern: "https://app.photobucket.com/u/{username}/a/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Imgur",
      category: PlatformCategory::Creative,
      url_pattern: "https://imgur.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Imgbb",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.imgbb.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PostImages",
      category: PlatformCategory::Creative,
      url_pattern: "https://postimg.cc/gallery/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Civitai",
      category: PlatformCategory::Creative,
      url_pattern: "https://civitai.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Tensor.Art",
      category: PlatformCategory::Creative,
      url_pattern: "https://tensor.art/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OpenArt",
      category: PlatformCategory::Creative,
      url_pattern: "https://openart.ai/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lexica",
      category: PlatformCategory::Creative,
      url_pattern: "https://lexica.art/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "PromptBase",
      category: PlatformCategory::Creative,
      url_pattern: "https://promptbase.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fanbox",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.fanbox.cc",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fantia",
      category: PlatformCategory::Creative,
      url_pattern: "https://fantia.jp/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Skeb",
      category: PlatformCategory::Creative,
      url_pattern: "https://skeb.jp/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Poipiku",
      category: PlatformCategory::Creative,
      url_pattern: "https://poipiku.com/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Privatter",
      category: PlatformCategory::Creative,
      url_pattern: "https://privatter.net/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Foundation",
      category: PlatformCategory::Creative,
      url_pattern: "https://foundation.app/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zora",
      category: PlatformCategory::Creative,
      url_pattern: "https://zora.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Figma Community",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.figma.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Framer",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.framer.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Sketch Cloud",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.sketch.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "InVision",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.invisionapp.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cargo Collective",
      category: PlatformCategory::Creative,
      url_pattern: "https://cargo.site/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Readymag",
      category: PlatformCategory::Creative,
      url_pattern: "https://readymag.com/u/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Format",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.format.com",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Fabrik",
      category: PlatformCategory::Creative,
      url_pattern: "https://{username}.fabrik.io",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Dunked",
      category: PlatformCategory::Creative,
      url_pattern: "https://dunked.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Crevado",
      category: PlatformCategory::Creative,
      url_pattern: "https://crevado.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Sketchfab",
      category: PlatformCategory::Creative,
      url_pattern: "https://sketchfab.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Turbosquid",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.turbosquid.com/Search/Artists/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CGTrader",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.cgtrader.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Blend Swap",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.blendswap.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Free3D",
      category: PlatformCategory::Creative,
      url_pattern: "https://free3d.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Clara.io",
      category: PlatformCategory::Creative,
      url_pattern: "https://clara.io/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Instructables",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.instructables.com/member/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Thingiverse",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.thingiverse.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Printables",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.printables.com/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Cults3D",
      category: PlatformCategory::Creative,
      url_pattern: "https://cults3d.com/en/users/{username}/creations",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Ravelry",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.ravelry.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "LoveKnitting",
      category: PlatformCategory::Creative,
      url_pattern: "https://www.loveknitting.com/profiles/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
