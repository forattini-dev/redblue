//! Finance platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all finance platforms
pub fn get_finance_platforms() -> Vec<Platform> {
  vec![
    Platform {
      name: "CoinMarketCap",
      category: PlatformCategory::Finance,
      url_pattern: "https://coinmarketcap.com/community/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TradingView",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.tradingview.com/u/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Seeking Alpha",
      category: PlatformCategory::Finance,
      url_pattern: "https://seekingalpha.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Stocktwits",
      category: PlatformCategory::Finance,
      url_pattern: "https://stocktwits.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OpenSea",
      category: PlatformCategory::Finance,
      url_pattern: "https://opensea.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rarible",
      category: PlatformCategory::Finance,
      url_pattern: "https://rarible.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Foundation",
      category: PlatformCategory::Finance,
      url_pattern: "https://foundation.app/@{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Mirror.xyz",
      category: PlatformCategory::Finance,
      url_pattern: "https://mirror.xyz/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Lens Protocol",
      category: PlatformCategory::Finance,
      url_pattern: "https://lenster.xyz/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ENS Domains",
      category: PlatformCategory::Finance,
      url_pattern: "https://app.ens.domains/{username}.eth",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Unstoppable Domains",
      category: PlatformCategory::Finance,
      url_pattern: "https://ud.me/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Zora",
      category: PlatformCategory::Finance,
      url_pattern: "https://zora.co/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "SuperRare",
      category: PlatformCategory::Finance,
      url_pattern: "https://superrare.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "KnownOrigin",
      category: PlatformCategory::Finance,
      url_pattern: "https://knownorigin.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Async Art",
      category: PlatformCategory::Finance,
      url_pattern: "https://async.art/u/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Objkt",
      category: PlatformCategory::Finance,
      url_pattern: "https://objkt.com/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "TradingView",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.tradingview.com/u/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Seeking Alpha",
      category: PlatformCategory::Finance,
      url_pattern: "https://seekingalpha.com/user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Stocktwits",
      category: PlatformCategory::Finance,
      url_pattern: "https://stocktwits.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "eToro",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.etoro.com/people/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Investopedia",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.investopedia.com/contributors/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CoinMarketCap",
      category: PlatformCategory::Finance,
      url_pattern: "https://coinmarketcap.com/community/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CoinGecko",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.coingecko.com/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Binance",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.binance.com/en/feed/profile/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Bybit",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.bybit.com/en-US/copy-trade/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OKX",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.okx.com/trade-user/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "OpenSea",
      category: PlatformCategory::Finance,
      url_pattern: "https://opensea.io/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Rarible",
      category: PlatformCategory::Finance,
      url_pattern: "https://rarible.com/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "ENS Domains",
      category: PlatformCategory::Finance,
      url_pattern: "https://app.ens.domains/{username}.eth",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CoinMarketCap",
      category: PlatformCategory::Finance,
      url_pattern: "https://coinmarketcap.com/community/profile/{username}/",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "CoinGecko",
      category: PlatformCategory::Finance,
      url_pattern: "https://www.coingecko.com/en/users/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
    Platform {
      name: "Etherscan",
      category: PlatformCategory::Finance,
      url_pattern: "https://etherscan.io/address/{username}",
      detection: DetectionMethod::StatusCode {
        found: 200,
        not_found: 404,
      },
      ..Default::default()
    },
  ]
}
