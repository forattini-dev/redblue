use super::super::types::{DetectionMethod, Platform, PlatformCategory};

pub fn platforms() -> Vec<Platform> {
  vec![
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
