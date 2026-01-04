//! Shopping platform definitions

use super::types::{DetectionMethod, Platform, PlatformCategory};

/// Get all shopping platforms
pub fn get_shopping_platforms() -> Vec<Platform> {
    vec![
        Platform {
            name: "Etsy",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.etsy.com/shop/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "eBay",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.ebay.com/usr/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Gumroad",
            category: PlatformCategory::Shopping,
            url_pattern: "https://gumroad.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Booth.pm",
            category: PlatformCategory::Shopping,
            url_pattern: "https://{username}.booth.pm",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Poshmark",
            category: PlatformCategory::Shopping,
            url_pattern: "https://poshmark.com/closet/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Depop",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.depop.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Mercari",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.mercari.com/u/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Vinted",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.vinted.com/member/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Grailed",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.grailed.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "StockX",
            category: PlatformCategory::Shopping,
            url_pattern: "https://stockx.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Reverb",
            category: PlatformCategory::Shopping,
            url_pattern: "https://reverb.com/shop/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Discogs Marketplace",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.discogs.com/seller/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Redbubble",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.redbubble.com/people/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Society6",
            category: PlatformCategory::Shopping,
            url_pattern: "https://society6.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Teepublic",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.teepublic.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Threadless",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.threadless.com/@{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Zazzle",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.zazzle.com/store/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Spreadshirt",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.spreadshirt.com/shop/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Etsy",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.etsy.com/shop/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "eBay",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.ebay.com/usr/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Shopify",
            category: PlatformCategory::Shopping,
            url_pattern: "https://{username}.myshopify.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Gumroad",
            category: PlatformCategory::Shopping,
            url_pattern: "https://{username}.gumroad.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Ko-fi",
            category: PlatformCategory::Shopping,
            url_pattern: "https://ko-fi.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Buy Me a Coffee",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.buymeacoffee.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Patreon",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.patreon.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "SubscribeStar",
            category: PlatformCategory::Shopping,
            url_pattern: "https://subscribestar.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Liberapay",
            category: PlatformCategory::Shopping,
            url_pattern: "https://liberapay.com/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "OpenCollective",
            category: PlatformCategory::Shopping,
            url_pattern: "https://opencollective.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "GitHub Sponsors",
            category: PlatformCategory::Shopping,
            url_pattern: "https://github.com/sponsors/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Tipeee",
            category: PlatformCategory::Shopping,
            url_pattern: "https://tipeee.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Throne",
            category: PlatformCategory::Shopping,
            url_pattern: "https://throne.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Streamlabs",
            category: PlatformCategory::Shopping,
            url_pattern: "https://streamlabs.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Fourthwall",
            category: PlatformCategory::Shopping,
            url_pattern: "https://{username}.fourthwall.com",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Lazada",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.lazada.com/shop/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Shopee",
            category: PlatformCategory::Shopping,
            url_pattern: "https://shopee.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Tokopedia",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.tokopedia.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Bukalapak",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.bukalapak.com/u/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Carousell",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.carousell.com/u/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Vinted",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.vinted.com/members/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Kleinanzeigen",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.kleinanzeigen.de/s-bestandsliste.html?userId={username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Leboncoin",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.leboncoin.fr/profil/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Wallapop",
            category: PlatformCategory::Shopping,
            url_pattern: "https://es.wallapop.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Subito",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.subito.it/vendite/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Marktplaats",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.marktplaats.nl/u/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "OLX",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.olx.com/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Poshmark",
            category: PlatformCategory::Shopping,
            url_pattern: "https://poshmark.com/closet/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Depop",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.depop.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Grailed",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.grailed.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "ThredUp",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.thredup.com/p/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Tradesy",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.tradesy.com/closet/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Mercari",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.mercari.com/u/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "StockX",
            category: PlatformCategory::Shopping,
            url_pattern: "https://stockx.com/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "GOAT",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.goat.com/users/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "MercadoLibre",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.mercadolibre.com.mx/perfil/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "OLX Brasil",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.olx.com.br/perfil/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Salla",
            category: PlatformCategory::Shopping,
            url_pattern: "https://{username}.salla.sa",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Opensooq",
            category: PlatformCategory::Shopping,
            url_pattern: "https://jo.opensooq.com/en/user/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Dubizzle",
            category: PlatformCategory::Shopping,
            url_pattern: "https://dubai.dubizzle.com/profile/{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Jumia",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.jumia.com.ng/sp-{username}/",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Konga",
            category: PlatformCategory::Shopping,
            url_pattern: "https://www.konga.com/seller/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
        Platform {
            name: "Jiji",
            category: PlatformCategory::Shopping,
            url_pattern: "https://jiji.ng/seller/{username}",
            detection: DetectionMethod::StatusCode {
                found: 200,
                not_found: 404,
            },
            ..Default::default()
        },
    ]
}
