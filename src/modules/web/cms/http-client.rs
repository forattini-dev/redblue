//! Shared HTTP client helpers for CMS scanning.

use super::HttpResponse as CmsHttpResponse;
use crate::protocols::http::{HttpClient, HttpRequest, HttpResponse as ProtoHttpResponse};
use std::time::Duration;

const DEFAULT_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

pub fn fetch_url(url: &str, user_agent: &str, timeout: Duration) -> Option<CmsHttpResponse> {
    let request = HttpRequest::get(url)
        .with_header("User-Agent", user_agent)
        .with_header("Accept", DEFAULT_ACCEPT);

    send_request(request, timeout, url)
}

pub fn post_url(
    url: &str,
    body: &str,
    user_agent: &str,
    timeout: Duration,
) -> Option<CmsHttpResponse> {
    let request = HttpRequest::post(url)
        .with_header("User-Agent", user_agent)
        .with_header("Accept", DEFAULT_ACCEPT)
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(body.as_bytes().to_vec());

    send_request(request, timeout, url)
}

fn send_request(request: HttpRequest, timeout: Duration, url: &str) -> Option<CmsHttpResponse> {
    let client = HttpClient::new().with_timeout(timeout);
    let response = client.send(&request).ok()?;
    Some(convert_response(response, url))
}

fn convert_response(response: ProtoHttpResponse, url: &str) -> CmsHttpResponse {
    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| (k, v))
        .collect::<Vec<(String, String)>>();

    CmsHttpResponse {
        status_code: response.status_code,
        headers,
        body: String::from_utf8_lossy(&response.body).to_string(),
        url: url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_convert_response() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "text/html".to_string());
        let response = ProtoHttpResponse {
            version: "HTTP/1.1".to_string(),
            status_code: 200,
            status_text: "OK".to_string(),
            headers,
            body: b"ok".to_vec(),
        };

        let converted = convert_response(response, "http://example.com");
        assert_eq!(converted.status_code, 200);
        assert_eq!(converted.body, "ok");
        assert_eq!(converted.url, "http://example.com");
        assert!(converted.get_header("Content-Type").is_some());
    }
}
