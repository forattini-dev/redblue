//! Embedded Files
//!
//! Default files embedded in the binary for serving without external dependencies.

/// Embedded files for the HTTP server
pub struct EmbeddedFiles;

impl EmbeddedFiles {
    /// Get the hook.js payload for browser exploitation
    pub fn hook_js() -> &'static str {
        include_str!("payloads/hook.js")
    }

    /// Get a minimal index.html
    pub fn index_html() -> &'static str {
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>redblue HTTP Server</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #0d1117;
            color: #c9d1d9;
        }
        h1 { color: #58a6ff; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .files { list-style: none; padding: 0; }
        .files li { padding: 8px 0; border-bottom: 1px solid #30363d; }
        .files li:last-child { border-bottom: none; }
        .dir { color: #7ee787; }
        .file { color: #c9d1d9; }
        code { background: #161b22; padding: 2px 6px; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>redblue HTTP Server</h1>
    <p>Serving files from the current directory.</p>
    <p>Available embedded files:</p>
    <ul class="files">
        <li><a href="/hook.js" class="file">hook.js</a> - Browser exploitation payload</li>
        <li><a href="/rb" class="file">rb</a> - Self-binary (for replication)</li>
    </ul>
</body>
</html>"#
    }

    /// Get a 404 page
    pub fn not_found_html() -> &'static str {
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>404 - Not Found</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #0d1117;
            color: #c9d1d9;
        }
        .container { text-align: center; }
        h1 { font-size: 72px; margin: 0; color: #f85149; }
        p { color: #8b949e; }
    </style>
</head>
<body>
    <div class="container">
        <h1>404</h1>
        <p>File not found</p>
    </div>
</body>
</html>"#
    }

    /// Get a directory listing template
    pub fn directory_listing_template() -> &'static str {
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Index of {{PATH}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1000px;
            margin: 50px auto;
            padding: 20px;
            background: #0d1117;
            color: #c9d1d9;
        }
        h1 { color: #58a6ff; word-break: break-all; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #30363d; }
        th { color: #8b949e; font-weight: 500; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .dir { color: #7ee787; }
        .file { color: #c9d1d9; }
        .size { color: #8b949e; font-family: monospace; }
        .date { color: #8b949e; }
        .parent { margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Index of {{PATH}}</h1>
    {{PARENT}}
    <table>
        <thead>
            <tr>
                <th>Name</th>
                <th>Size</th>
                <th>Modified</th>
            </tr>
        </thead>
        <tbody>
{{ENTRIES}}
        </tbody>
    </table>
</body>
</html>"#
    }

    /// Get list of embedded file paths
    pub fn list() -> Vec<(&'static str, &'static str)> {
        vec![
            ("/hook.js", "application/javascript"),
            ("/index.html", "text/html"),
        ]
    }

    /// Get embedded file by path
    pub fn get(path: &str) -> Option<(&'static str, &'static str)> {
        match path {
            "/hook.js" | "hook.js" => Some((Self::hook_js(), "application/javascript; charset=utf-8")),
            "/" | "/index.html" | "index.html" => Some((Self::index_html(), "text/html; charset=utf-8")),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_files() {
        assert!(EmbeddedFiles::hook_js().len() > 0);
        assert!(EmbeddedFiles::index_html().contains("<!DOCTYPE html>"));
        assert!(EmbeddedFiles::not_found_html().contains("404"));
    }

    #[test]
    fn test_get_embedded() {
        assert!(EmbeddedFiles::get("/hook.js").is_some());
        assert!(EmbeddedFiles::get("/").is_some());
        assert!(EmbeddedFiles::get("/nonexistent").is_none());
    }
}
