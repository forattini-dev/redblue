use super::*;

// -- helpers -----------------------------------------------------------

fn doc(html: &str) -> HtmlDocument {
  HtmlDocument::parse(html)
}

/// Collect all element tag names under root, depth-first.
fn all_tags(d: &HtmlDocument) -> Vec<String> {
  let mut tags = Vec::new();
  collect_tags(d, d.root, &mut tags);
  tags
}

fn collect_tags(d: &HtmlDocument, id: usize, out: &mut Vec<String>) {
  if let Some(node) = d.arena.get(id) {
    if node.node_type == NodeType::Element && node.tag_name != "[root]" {
      out.push(node.tag_name.clone());
    }
    for &kid in &node.children.clone() {
      collect_tags(d, kid, out);
    }
  }
}

// ======================================================================
// Basic parsing
// ======================================================================

#[test]
fn test_parse_simple_div() {
  let d = doc("<div>Hello</div>");
  let divs = d.get_elements_by_tag_name("div");
  assert_eq!(divs.len(), 1);
  assert_eq!(d.text(divs[0]), "Hello");
}

#[test]
fn test_parse_nested_elements() {
  let d = doc("<div><span><em>deep</em></span></div>");
  let tags = all_tags(&d);
  assert!(tags.contains(&"div".into()));
  assert!(tags.contains(&"span".into()));
  assert!(tags.contains(&"em".into()));

  let div = d.get_elements_by_tag_name("div")[0];
  assert_eq!(d.text(div), "deep");
}

#[test]
fn test_parse_attributes() {
  let d = doc(r#"<a href="https://example.com" class="link active">Go</a>"#);
  let a = d.get_elements_by_tag_name("a")[0];
  assert_eq!(d.get_attribute(a, "href"), Some("https://example.com"));
  assert_eq!(d.get_attribute(a, "class"), Some("link active"));
}

#[test]
fn test_parse_void_tags() {
  let d = doc("<div><br><hr><img src=\"x.png\"><input type=\"text\"></div>");
  let tags = all_tags(&d);
  assert!(tags.contains(&"br".into()));
  assert!(tags.contains(&"hr".into()));
  assert!(tags.contains(&"img".into()));
  assert!(tags.contains(&"input".into()));

  // Void tags must not eat following siblings
  let div = d.get_elements_by_tag_name("div")[0];
  assert_eq!(d.children(div).len(), 4);
}

#[test]
fn test_parse_self_closing() {
  let d = doc("<br/><br />");
  let brs = d.get_elements_by_tag_name("br");
  assert_eq!(brs.len(), 2);
  for &br in &brs {
    assert!(d.arena.get(br).unwrap().self_closing);
  }
}

#[test]
fn test_parse_comments() {
  let d = doc("<div><!-- this is a comment -->text</div>");
  let div = d.get_elements_by_tag_name("div")[0];
  let kids = d.children(div);
  let comments: Vec<usize> = kids
    .iter()
    .copied()
    .filter(|&k| d.node_type(k) == NodeType::Comment)
    .collect();
  assert_eq!(comments.len(), 1);
  assert_eq!(
    d.arena.get(comments[0]).unwrap().text_content,
    " this is a comment "
  );
}

#[test]
fn test_parse_text_nodes() {
  let d = doc("<p>Hello <b>world</b> !</p>");
  let p = d.get_elements_by_tag_name("p")[0];
  let text = d.text(p);
  assert!(text.contains("Hello"));
  assert!(text.contains("world"));
}

#[test]
fn test_parse_script_raw_content() {
  let d = doc(r#"<script>if (a < b && c > d) { alert("hi"); }</script>"#);
  let scripts = d.get_elements_by_tag_name("script");
  assert_eq!(scripts.len(), 1);
  let content = &d.arena.get(scripts[0]).unwrap().text_content;
  assert!(content.contains("a < b"));
  assert!(content.contains("c > d"));
}

#[test]
fn test_parse_style_raw_content() {
  let d = doc("<style>body { color: red; } .a > .b { margin: 0; }</style>");
  let styles = d.get_elements_by_tag_name("style");
  assert_eq!(styles.len(), 1);
  let content = &d.arena.get(styles[0]).unwrap().text_content;
  assert!(content.contains("color: red"));
  assert!(content.contains(".a > .b"));
}

// ======================================================================
// Auto-closing
// ======================================================================

#[test]
fn test_auto_close_li() {
  let d = doc("<ul><li>One<li>Two<li>Three</ul>");
  let lis = d.get_elements_by_tag_name("li");
  assert_eq!(lis.len(), 3);
  let ul = d.get_elements_by_tag_name("ul")[0];
  let ul_kids: Vec<usize> = d
    .children(ul)
    .iter()
    .copied()
    .filter(|&id| d.node_type(id) == NodeType::Element)
    .collect();
  assert_eq!(ul_kids.len(), 3);
}

#[test]
fn test_auto_close_p() {
  let d = doc("<div><p>First<p>Second</div>");
  let ps = d.get_elements_by_tag_name("p");
  assert_eq!(ps.len(), 2);
  let div = d.get_elements_by_tag_name("div")[0];
  let div_kids: Vec<usize> = d
    .children(div)
    .iter()
    .copied()
    .filter(|&id| d.node_type(id) == NodeType::Element)
    .collect();
  assert_eq!(div_kids.len(), 2);
}

#[test]
fn test_auto_close_td() {
  let d = doc("<table><tr><td>A<td>B<th>C</tr></table>");
  let tds = d.get_elements_by_tag_name("td");
  assert_eq!(tds.len(), 2);
  let ths = d.get_elements_by_tag_name("th");
  assert_eq!(ths.len(), 1);
}

// ======================================================================
// Malformed HTML
// ======================================================================

#[test]
fn test_unclosed_tags() {
  let d = doc("<div><span>text");
  let divs = d.get_elements_by_tag_name("div");
  assert_eq!(divs.len(), 1);
  let spans = d.get_elements_by_tag_name("span");
  assert_eq!(spans.len(), 1);
}

#[test]
fn test_extra_closing_tags() {
  let d = doc("<div>text</span></div>");
  let divs = d.get_elements_by_tag_name("div");
  assert_eq!(divs.len(), 1);
  assert_eq!(d.text(divs[0]), "text");
}

#[test]
fn test_nested_same_tags() {
  let d = doc("<div><div>inner</div></div>");
  let divs = d.get_elements_by_tag_name("div");
  assert_eq!(divs.len(), 2);
}

// ======================================================================
// Attributes
// ======================================================================

#[test]
fn test_double_quoted_attr() {
  let d = doc(r#"<input type="text" value="hello world">"#);
  let input = d.get_elements_by_tag_name("input")[0];
  assert_eq!(d.get_attribute(input, "type"), Some("text"));
  assert_eq!(d.get_attribute(input, "value"), Some("hello world"));
}

#[test]
fn test_single_quoted_attr() {
  let d = doc("<input type='text' value='hello'>");
  let input = d.get_elements_by_tag_name("input")[0];
  assert_eq!(d.get_attribute(input, "type"), Some("text"));
  assert_eq!(d.get_attribute(input, "value"), Some("hello"));
}

#[test]
fn test_unquoted_attr() {
  let d = doc("<input type=text value=hello>");
  let input = d.get_elements_by_tag_name("input")[0];
  assert_eq!(d.get_attribute(input, "type"), Some("text"));
  assert_eq!(d.get_attribute(input, "value"), Some("hello"));
}

#[test]
fn test_boolean_attr() {
  let d = doc("<input disabled readonly>");
  let input = d.get_elements_by_tag_name("input")[0];
  assert!(d.has_attribute(input, "disabled"));
  assert!(d.has_attribute(input, "readonly"));
  assert_eq!(d.get_attribute(input, "disabled"), Some(""));
}

#[test]
fn test_multiple_attributes() {
  let d = doc(r#"<div id="main" class="container fluid" data-role="page" hidden></div>"#);
  let div = d.get_elements_by_tag_name("div")[0];
  assert_eq!(d.get_attribute(div, "id"), Some("main"));
  assert_eq!(d.get_attribute(div, "class"), Some("container fluid"));
  assert_eq!(d.get_attribute(div, "data-role"), Some("page"));
  assert!(d.has_attribute(div, "hidden"));
}

// ======================================================================
// Text content
// ======================================================================

#[test]
fn test_text_content_recursive() {
  let d = doc("<div>Hello <span>beautiful <b>world</b></span>!</div>");
  let div = d.get_elements_by_tag_name("div")[0];
  let text = d.text(div);
  assert!(text.contains("Hello"));
  assert!(text.contains("beautiful"));
  assert!(text.contains("world"));
}

#[test]
fn test_inner_html_serialization() {
  let d = doc("<div><span>hi</span></div>");
  let div = d.get_elements_by_tag_name("div")[0];
  let html = d.inner_html(div);
  assert!(html.contains("<span>"));
  assert!(html.contains("hi"));
  assert!(html.contains("</span>"));
}

#[test]
fn test_outer_html_serialization() {
  let d = doc("<div><span>hi</span></div>");
  let div = d.get_elements_by_tag_name("div")[0];
  let html = d.outer_html(div);
  assert!(html.starts_with("<div>"));
  assert!(html.ends_with("</div>"));
  assert!(html.contains("<span>hi</span>"));
}

// ======================================================================
// Search methods
// ======================================================================

#[test]
fn test_get_elements_by_tag_name() {
  let d = doc("<div><p>1</p><p>2</p><span><p>3</p></span></div>");
  let ps = d.get_elements_by_tag_name("p");
  assert_eq!(ps.len(), 3);
}

#[test]
fn test_get_element_by_id() {
  let d = doc(r#"<div id="a"></div><div id="b"><span id="c"></span></div>"#);
  assert!(d.get_element_by_id("a").is_some());
  assert!(d.get_element_by_id("b").is_some());
  assert!(d.get_element_by_id("c").is_some());
  assert!(d.get_element_by_id("z").is_none());

  let c = d.get_element_by_id("c").unwrap();
  assert_eq!(d.tag_name(c), "span");
}

#[test]
fn test_get_elements_by_class_name() {
  let d = doc(r#"<div class="a b"><span class="b c"></span><p class="a"></p></div>"#);
  assert_eq!(d.get_elements_by_class_name("a").len(), 2);
  assert_eq!(d.get_elements_by_class_name("b").len(), 2);
  assert_eq!(d.get_elements_by_class_name("c").len(), 1);
  assert_eq!(d.get_elements_by_class_name("z").len(), 0);
}

// ======================================================================
// Entity decoding
// ======================================================================

#[test]
fn test_decode_named_entities() {
  assert_eq!(decode_entities("&amp;"), "&");
  assert_eq!(decode_entities("&lt;"), "<");
  assert_eq!(decode_entities("&gt;"), ">");
  assert_eq!(decode_entities("&quot;"), "\"");
  assert_eq!(decode_entities("&apos;"), "'");
  assert_eq!(decode_entities("&nbsp;"), "\u{00A0}");
  assert_eq!(decode_entities("a &amp; b &lt; c"), "a & b < c");
}

#[test]
fn test_decode_numeric_entities() {
  assert_eq!(decode_entities("&#65;"), "A");
  assert_eq!(decode_entities("&#97;"), "a");
  assert_eq!(decode_entities("&#169;"), "\u{00A9}"); // copyright
}

#[test]
fn test_decode_hex_entities() {
  assert_eq!(decode_entities("&#x41;"), "A");
  assert_eq!(decode_entities("&#x61;"), "a");
  assert_eq!(decode_entities("&#xA9;"), "\u{00A9}");
  assert_eq!(decode_entities("&#X42;"), "B"); // uppercase X
}

#[test]
fn test_entities_in_text() {
  let d = doc("<p>5 &gt; 3 &amp;&amp; 2 &lt; 4</p>");
  let p = d.get_elements_by_tag_name("p")[0];
  assert_eq!(d.text(p), "5 > 3 && 2 < 4");
}

#[test]
fn test_entities_in_attributes() {
  let d = doc(r#"<a href="a&amp;b=1" title="&lt;tag&gt;">x</a>"#);
  let a = d.get_elements_by_tag_name("a")[0];
  assert_eq!(d.get_attribute(a, "href"), Some("a&b=1"));
  assert_eq!(d.get_attribute(a, "title"), Some("<tag>"));
}

// ======================================================================
// class_list and id helpers
// ======================================================================

#[test]
fn test_class_list() {
  let d = doc(r#"<div class="foo bar baz"></div>"#);
  let div = d.get_elements_by_tag_name("div")[0];
  assert_eq!(d.class_list(div), vec!["foo", "bar", "baz"]);
}

#[test]
fn test_id_helper() {
  let d = doc(r#"<div id="main"></div>"#);
  let div = d.get_elements_by_tag_name("div")[0];
  assert_eq!(d.id(div), Some("main"));
}

// ======================================================================
// Real-world HTML: login page
// ======================================================================

#[test]
fn test_parse_login_page() {
  let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login - My App</title>
  <link rel="stylesheet" href="/css/app.css">
  <script src="/js/app.js"></script>
  <style>
    body { font-family: sans-serif; }
    .login-form { max-width: 400px; margin: 0 auto; }
  </style>
</head>
<body>
  <nav id="main-nav" class="navbar fixed-top">
    <a href="/" class="brand">My App</a>
    <ul>
      <li><a href="/about">About</a>
      <li><a href="/contact">Contact</a>
    </ul>
  </nav>

  <main class="container">
    <div class="login-form" id="login-section">
      <h1>Sign In</h1>
      <form action="/auth/login" method="post">
        <input type="hidden" name="_token" value="abc123">
        <div class="form-group">
          <label for="email">Email</label>
          <input type="email" id="email" name="email" required placeholder="you@example.com">
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
        </div>
        <div class="form-check">
          <input type="checkbox" id="remember" name="remember">
          <label for="remember">Remember me</label>
        </div>
        <button type="submit" class="btn btn-primary">Log In</button>
      </form>
      <p>Don&apos;t have an account? <a href="/register">Sign up</a></p>
    </div>
  </main>

  <!-- footer -->
  <footer>
    <p>&copy; 2025 My App. All rights reserved.</p>
  </footer>
</body>
</html>"#;

  let d = doc(html);

  // Title element
  let titles = d.get_elements_by_tag_name("title");
  assert_eq!(titles.len(), 1);
  assert_eq!(d.text(titles[0]), "Login - My App");

  // Navigation
  let nav = d.get_element_by_id("main-nav").unwrap();
  assert_eq!(d.tag_name(nav), "nav");
  assert!(d.class_list(nav).contains(&"navbar"));

  // Form
  let forms = d.get_elements_by_tag_name("form");
  assert_eq!(forms.len(), 1);
  assert_eq!(d.get_attribute(forms[0], "action"), Some("/auth/login"));
  assert_eq!(d.get_attribute(forms[0], "method"), Some("post"));

  // Inputs (hidden + email + password + checkbox = 4 minimum)
  let inputs = d.get_elements_by_tag_name("input");
  assert!(inputs.len() >= 4);

  // Email input by id
  let email = d.get_element_by_id("email").unwrap();
  assert_eq!(d.get_attribute(email, "type"), Some("email"));
  assert!(d.has_attribute(email, "required"));
  assert_eq!(
    d.get_attribute(email, "placeholder"),
    Some("you@example.com")
  );

  // Auto-closed <li> tags
  let lis = d.get_elements_by_tag_name("li");
  assert_eq!(lis.len(), 2);

  // Class search
  let form_groups = d.get_elements_by_class_name("form-group");
  assert_eq!(form_groups.len(), 2);

  // Entity in text: "Don't"
  let login_section = d.get_element_by_id("login-section").unwrap();
  let section_text = d.text(login_section);
  assert!(section_text.contains("Don't"));

  // Footer exists
  let footer = d.get_elements_by_tag_name("footer");
  assert_eq!(footer.len(), 1);

  // Style raw content
  let styles = d.get_elements_by_tag_name("style");
  assert_eq!(styles.len(), 1);
  let style_content = &d.arena.get(styles[0]).unwrap().text_content;
  assert!(style_content.contains("font-family"));
  assert!(style_content.contains(".login-form"));

  // Links
  let links = d.get_elements_by_tag_name("a");
  assert!(links.len() >= 3);
}

// ======================================================================
// Edge cases
// ======================================================================

#[test]
fn test_empty_input() {
  let d = doc("");
  assert_eq!(d.children(d.root).len(), 0);
}

#[test]
fn test_text_only() {
  let d = doc("just some text");
  let text = d.text(d.root);
  assert_eq!(text, "just some text");
}

#[test]
fn test_case_insensitive_tags() {
  let d = doc("<DIV><SPAN>hi</SPAN></DIV>");
  assert_eq!(d.get_elements_by_tag_name("div").len(), 1);
  assert_eq!(d.get_elements_by_tag_name("span").len(), 1);
}

#[test]
fn test_doctype_skipped() {
  let d = doc("<!DOCTYPE html><html><body>ok</body></html>");
  let bodies = d.get_elements_by_tag_name("body");
  assert_eq!(bodies.len(), 1);
  assert_eq!(d.text(bodies[0]), "ok");
}

#[test]
fn test_case_insensitive_tag_search() {
  let d = doc("<div>x</div>");
  assert_eq!(d.get_elements_by_tag_name("DIV").len(), 1);
  assert_eq!(d.get_elements_by_tag_name("Div").len(), 1);
}

#[test]
fn test_raw_text_script_with_nested_tags() {
  let d = doc("<script>var x = '<div>not a tag</div>';</script><p>after</p>");
  let scripts = d.get_elements_by_tag_name("script");
  assert_eq!(scripts.len(), 1);
  let content = &d.arena.get(scripts[0]).unwrap().text_content;
  assert!(content.contains("<div>not a tag</div>"));
  // <p> after the script should still parse
  assert_eq!(d.get_elements_by_tag_name("p").len(), 1);
}

#[test]
fn test_void_tags_no_children() {
  let d = doc("<br><hr><img src=\"x\"><p>after</p>");
  let brs = d.get_elements_by_tag_name("br");
  let hrs = d.get_elements_by_tag_name("hr");
  assert_eq!(d.children(brs[0]).len(), 0);
  assert_eq!(d.children(hrs[0]).len(), 0);
  // <p> must NOT be a child of <img>
  let ps = d.get_elements_by_tag_name("p");
  assert_eq!(ps.len(), 1);
  let p_parent = d.parent(ps[0]).unwrap();
  assert_ne!(d.tag_name(p_parent), "img");
}

#[test]
fn test_outer_html_void_tag() {
  let d = doc(r#"<img src="photo.jpg" alt="pic">"#);
  let imgs = d.get_elements_by_tag_name("img");
  let html = d.outer_html(imgs[0]);
  assert!(html.contains("<img"));
  assert!(html.contains("src=\"photo.jpg\""));
  assert!(html.contains("/>"));
}

#[test]
fn test_deeply_nested() {
  let mut html = String::new();
  for _ in 0..50 {
    html.push_str("<div>");
  }
  html.push_str("deep");
  for _ in 0..50 {
    html.push_str("</div>");
  }
  let d = doc(&html);
  let divs = d.get_elements_by_tag_name("div");
  assert_eq!(divs.len(), 50);
  let deepest = divs.last().unwrap();
  assert_eq!(d.text(*deepest), "deep");
}

#[test]
fn test_text_content_alias() {
  // text_content() is an alias for text() kept for backward compat
  let d = doc("<p>hello <b>world</b></p>");
  let p = d.get_elements_by_tag_name("p")[0];
  assert_eq!(d.text_content(p), d.text(p));
}

#[test]
fn test_node_ids_depth_first() {
  let d = doc("<div><span>a</span><em>b</em></div>");
  let ids = d.node_ids();
  // Should include: div, span, text(a), em, text(b)
  assert!(ids.len() >= 4);
  // The root itself should NOT be in the list
  assert!(!ids.contains(&d.root));
}

#[test]
fn test_element_children() {
  let d = doc("<div>text<span>a</span>more text<em>b</em></div>");
  let div = d.get_elements_by_tag_name("div")[0];
  let elem_kids = d.element_children(div);
  // Only span and em, not text nodes
  assert_eq!(elem_kids.len(), 2);
  assert_eq!(d.tag_name(elem_kids[0]), "span");
  assert_eq!(d.tag_name(elem_kids[1]), "em");
}

#[test]
fn test_has_attribute() {
  let d = doc(r#"<input type="text" disabled>"#);
  let input = d.get_elements_by_tag_name("input")[0];
  assert!(d.has_attribute(input, "type"));
  assert!(d.has_attribute(input, "disabled"));
  assert!(!d.has_attribute(input, "readonly"));
}

#[test]
fn test_parent_tracking() {
  let d = doc("<div><p>text</p></div>");
  let div = d.children(d.root)[0];
  let p = d.children(div)[0];
  assert_eq!(d.parent(p), Some(div));
  assert_eq!(d.parent(div), Some(d.root));
}

#[test]
fn test_comment_nodes() {
  let d = doc("<div><!-- a comment --><p>text</p></div>");
  let div = d.children(d.root)[0];
  let children = d.children(div);
  assert!(children.len() >= 2);
  assert_eq!(d.node_type(children[0]), NodeType::Comment);
}

#[test]
fn test_entity_decoding_basic() {
  let d = doc("<p>&amp; &lt; &gt; &quot;</p>");
  let p = d.children(d.root)[0];
  let text = d.text_content(p);
  assert!(text.contains('&'));
  assert!(text.contains('<'));
  assert!(text.contains('>'));
  assert!(text.contains('"'));
}

#[test]
fn test_parse_self_closing_void() {
  let d = doc("<div><br/><img src='x.png'/><p>text</p></div>");
  let div = d.children(d.root)[0];
  let children = d.children(div);
  assert_eq!(children.len(), 3);
  assert_eq!(d.tag_name(children[0]), "br");
  assert_eq!(d.tag_name(children[1]), "img");
  assert_eq!(d.tag_name(children[2]), "p");
}

#[test]
fn test_void_elements_not_pushed() {
  let d = doc("<div><input type='text'><span>hi</span></div>");
  let div = d.children(d.root)[0];
  let children = d.children(div);
  assert_eq!(children.len(), 2);
  assert_eq!(d.tag_name(children[0]), "input");
  assert_eq!(d.tag_name(children[1]), "span");
}
