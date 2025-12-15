//! ASCII Tree Renderer for hierarchical data visualization
//!
//! Renders domain/subdomain/IP/port hierarchies as ASCII trees:
//!
//! ```text
//! example.com
//! ├── api.example.com (1.2.3.4)
//! │   ├── ASN12345 (Example Corp)
//! │   └── :443 (HTTPS)
//! └── mail.example.com (5.6.7.8)
//!     └── :25 (SMTP)
//! ```
//!
//! Zero external dependencies - uses only Rust std.

use std::fmt;
use std::net::IpAddr;

/// Node types for recon graph visualization
#[derive(Debug, Clone, PartialEq)]
pub enum NodeType {
    /// Root domain (e.g., "example.com")
    Domain,
    /// Subdomain (e.g., "api.example.com")
    Subdomain,
    /// IP address (v4 or v6)
    Ip,
    /// Autonomous System Number
    Asn,
    /// Network port
    Port,
    /// Service detected on a port
    Service,
    /// Technology detected
    Technology,
    /// CNAME alias
    Cname,
    /// Nameserver
    Nameserver,
    /// MX record
    MailServer,
    /// Generic/custom node
    Generic,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::Domain => write!(f, "domain"),
            NodeType::Subdomain => write!(f, "subdomain"),
            NodeType::Ip => write!(f, "ip"),
            NodeType::Asn => write!(f, "asn"),
            NodeType::Port => write!(f, "port"),
            NodeType::Service => write!(f, "service"),
            NodeType::Technology => write!(f, "tech"),
            NodeType::Cname => write!(f, "cname"),
            NodeType::Nameserver => write!(f, "ns"),
            NodeType::MailServer => write!(f, "mx"),
            NodeType::Generic => write!(f, "node"),
        }
    }
}

/// A node in the recon graph
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Unique identifier
    pub id: String,
    /// Node type for categorization
    pub node_type: NodeType,
    /// Display label
    pub label: String,
    /// Additional metadata shown in parentheses
    pub metadata: Option<String>,
    /// Child nodes
    pub children: Vec<TreeNode>,
    /// Is this node expanded (for interactive TUI)
    pub expanded: bool,
}

impl TreeNode {
    /// Create a new tree node
    pub fn new(id: impl Into<String>, node_type: NodeType, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            node_type,
            label: label.into(),
            metadata: None,
            children: Vec::new(),
            expanded: true,
        }
    }

    /// Add metadata to display
    pub fn with_metadata(mut self, meta: impl Into<String>) -> Self {
        self.metadata = Some(meta.into());
        self
    }

    /// Add a child node
    pub fn add_child(&mut self, child: TreeNode) {
        self.children.push(child);
    }

    /// Add multiple children
    pub fn with_children(mut self, children: Vec<TreeNode>) -> Self {
        self.children = children;
        self
    }

    /// Create a domain node
    pub fn domain(name: impl Into<String>) -> Self {
        let name = name.into();
        Self::new(name.clone(), NodeType::Domain, name)
    }

    /// Create a subdomain node
    pub fn subdomain(name: impl Into<String>) -> Self {
        let name = name.into();
        Self::new(name.clone(), NodeType::Subdomain, name)
    }

    /// Create an IP node
    pub fn ip(addr: IpAddr) -> Self {
        Self::new(addr.to_string(), NodeType::Ip, addr.to_string())
    }

    /// Create an IP node from string
    pub fn ip_str(addr: impl Into<String>) -> Self {
        let addr = addr.into();
        Self::new(addr.clone(), NodeType::Ip, addr)
    }

    /// Create an ASN node
    pub fn asn(number: u32, org: impl Into<String>) -> Self {
        let org = org.into();
        Self::new(
            format!("AS{}", number),
            NodeType::Asn,
            format!("AS{}", number),
        )
        .with_metadata(org)
    }

    /// Create a port node
    pub fn port(port: u16, service: Option<impl Into<String>>) -> Self {
        let label = format!(":{}", port);
        let mut node = Self::new(label.clone(), NodeType::Port, label);
        if let Some(svc) = service {
            node.metadata = Some(svc.into());
        }
        node
    }

    /// Create a service node
    pub fn service(name: impl Into<String>) -> Self {
        let name = name.into();
        Self::new(name.clone(), NodeType::Service, name)
    }

    /// Create a technology node
    pub fn technology(tech: impl Into<String>, version: Option<impl Into<String>>) -> Self {
        let tech = tech.into();
        let mut node = Self::new(tech.clone(), NodeType::Technology, tech);
        if let Some(ver) = version {
            node.metadata = Some(ver.into());
        }
        node
    }

    /// Create a CNAME node
    pub fn cname(target: impl Into<String>) -> Self {
        let target = target.into();
        Self::new(format!("cname:{}", target), NodeType::Cname, target)
    }

    /// Create a nameserver node
    pub fn nameserver(ns: impl Into<String>) -> Self {
        let ns = ns.into();
        Self::new(format!("ns:{}", ns), NodeType::Nameserver, ns)
    }

    /// Create a mail server node
    pub fn mail_server(mx: impl Into<String>, priority: Option<u16>) -> Self {
        let mx = mx.into();
        let mut node = Self::new(format!("mx:{}", mx), NodeType::MailServer, mx);
        if let Some(pri) = priority {
            node.metadata = Some(format!("pri:{}", pri));
        }
        node
    }

    /// Count all nodes in the tree (including self)
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(|c| c.count()).sum::<usize>()
    }

    /// Get maximum depth of the tree
    pub fn depth(&self) -> usize {
        if self.children.is_empty() {
            1
        } else {
            1 + self.children.iter().map(|c| c.depth()).max().unwrap_or(0)
        }
    }

    /// Toggle expanded state
    pub fn toggle(&mut self) {
        self.expanded = !self.expanded;
    }

    /// Find a node by ID
    pub fn find(&self, id: &str) -> Option<&TreeNode> {
        if self.id == id {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find(id) {
                return Some(found);
            }
        }
        None
    }

    /// Find a node by ID (mutable)
    pub fn find_mut(&mut self, id: &str) -> Option<&mut TreeNode> {
        if self.id == id {
            return Some(self);
        }
        for child in &mut self.children {
            if let Some(found) = child.find_mut(id) {
                return Some(found);
            }
        }
        None
    }
}

/// ASCII tree renderer
pub struct TreeRenderer {
    /// Use colors in output
    pub colorize: bool,
    /// Show node types as prefixes
    pub show_types: bool,
    /// Collapse nodes with more than this many children
    pub collapse_threshold: Option<usize>,
}

impl Default for TreeRenderer {
    fn default() -> Self {
        Self {
            colorize: true,
            show_types: false,
            collapse_threshold: None,
        }
    }
}

impl TreeRenderer {
    /// Create a new renderer
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable/disable colors
    pub fn with_color(mut self, colorize: bool) -> Self {
        self.colorize = colorize;
        self
    }

    /// Show node type prefixes
    pub fn with_types(mut self, show: bool) -> Self {
        self.show_types = show;
        self
    }

    /// Set collapse threshold
    pub fn collapse_after(mut self, threshold: usize) -> Self {
        self.collapse_threshold = Some(threshold);
        self
    }

    /// Render tree to string
    pub fn render(&self, root: &TreeNode) -> String {
        let mut output = String::new();
        self.render_root(root, &mut output);
        output
    }

    /// Render to stdout
    pub fn display(&self, root: &TreeNode) {
        print!("{}", self.render(root));
    }

    /// Render root node (no connector)
    fn render_root(&self, node: &TreeNode, output: &mut String) {
        // Format root label
        let label = if let Some(ref meta) = node.metadata {
            format!("{} ({})", node.label, meta)
        } else {
            node.label.clone()
        };

        let type_prefix = if self.show_types {
            format!("[{}] ", node.node_type)
        } else {
            String::new()
        };

        let colored_label = if self.colorize {
            self.colorize_node(&node.node_type, &format!("{}{}", type_prefix, label))
        } else {
            format!("{}{}", type_prefix, label)
        };

        output.push_str(&colored_label);
        output.push('\n');

        // Render children with proper prefix
        if node.expanded && !node.children.is_empty() {
            let len = node.children.len();
            for (i, child) in node.children.iter().enumerate() {
                self.render_child(child, output, "", i == len - 1);
            }
        }
    }

    /// Internal: render a child node and its descendants
    fn render_child(&self, node: &TreeNode, output: &mut String, prefix: &str, is_last: bool) {
        // Build connector
        let connector = if is_last { "└── " } else { "├── " };

        // Format label with optional metadata
        let label = if let Some(ref meta) = node.metadata {
            format!("{} ({})", node.label, meta)
        } else {
            node.label.clone()
        };

        // Add type prefix if enabled
        let type_prefix = if self.show_types {
            format!("[{}] ", node.node_type)
        } else {
            String::new()
        };

        // Colorize based on node type
        let colored_label = if self.colorize {
            self.colorize_node(&node.node_type, &format!("{}{}", type_prefix, label))
        } else {
            format!("{}{}", type_prefix, label)
        };

        // Write the line
        output.push_str(prefix);
        output.push_str(connector);
        output.push_str(&colored_label);
        output.push('\n');

        // Render children if expanded
        if node.expanded && !node.children.is_empty() {
            let child_prefix = if is_last {
                format!("{}    ", prefix)
            } else {
                format!("{}│   ", prefix)
            };

            // Check collapse threshold
            let children_to_show = if let Some(threshold) = self.collapse_threshold {
                if node.children.len() > threshold {
                    // Show first few and add "... and N more"
                    let remaining = node.children.len() - threshold;

                    for (i, child) in node.children.iter().take(threshold).enumerate() {
                        self.render_child(
                            child,
                            output,
                            &child_prefix,
                            i == threshold - 1 && remaining == 0,
                        );
                    }

                    // Add ellipsis node
                    output.push_str(&child_prefix);
                    output.push_str("└── ");
                    if self.colorize {
                        output.push_str("\x1b[90m");
                    }
                    output.push_str(&format!("... and {} more", remaining));
                    if self.colorize {
                        output.push_str("\x1b[0m");
                    }
                    output.push('\n');

                    return;
                }
                &node.children[..]
            } else {
                &node.children[..]
            };

            let len = children_to_show.len();
            for (i, child) in children_to_show.iter().enumerate() {
                self.render_child(child, output, &child_prefix, i == len - 1);
            }
        }
    }

    /// Apply ANSI colors based on node type
    fn colorize_node(&self, node_type: &NodeType, text: &str) -> String {
        let color = match node_type {
            NodeType::Domain => "\x1b[1;36m",   // Bold cyan
            NodeType::Subdomain => "\x1b[36m",  // Cyan
            NodeType::Ip => "\x1b[33m",         // Yellow
            NodeType::Asn => "\x1b[35m",        // Magenta
            NodeType::Port => "\x1b[32m",       // Green
            NodeType::Service => "\x1b[34m",    // Blue
            NodeType::Technology => "\x1b[94m", // Light blue
            NodeType::Cname => "\x1b[90m",      // Gray
            NodeType::Nameserver => "\x1b[33m", // Yellow
            NodeType::MailServer => "\x1b[31m", // Red
            NodeType::Generic => "\x1b[0m",     // Default
        };
        format!("{}{}\x1b[0m", color, text)
    }
}

/// Builder for constructing recon trees from scan data
pub struct ReconTreeBuilder {
    root: TreeNode,
}

impl ReconTreeBuilder {
    /// Create a new builder with a domain root
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            root: TreeNode::domain(domain),
        }
    }

    /// Add a subdomain with optional IP addresses
    pub fn add_subdomain(&mut self, subdomain: impl Into<String>, ips: &[IpAddr]) {
        let subdomain = subdomain.into();
        let mut node = TreeNode::subdomain(&subdomain);

        for ip in ips {
            node.add_child(TreeNode::ip(*ip));
        }

        self.root.add_child(node);
    }

    /// Add a subdomain with IP string
    pub fn add_subdomain_with_ip(&mut self, subdomain: impl Into<String>, ip: impl Into<String>) {
        let subdomain = subdomain.into();
        let mut node = TreeNode::subdomain(&subdomain);
        node.add_child(TreeNode::ip_str(ip));
        self.root.add_child(node);
    }

    /// Add a nameserver
    pub fn add_nameserver(&mut self, ns: impl Into<String>) {
        self.root.add_child(TreeNode::nameserver(ns));
    }

    /// Add a mail server
    pub fn add_mail_server(&mut self, mx: impl Into<String>, priority: Option<u16>) {
        self.root.add_child(TreeNode::mail_server(mx, priority));
    }

    /// Add open port to a subdomain
    pub fn add_port_to_subdomain(&mut self, subdomain: &str, port: u16, service: Option<&str>) {
        if let Some(node) = self.root.find_mut(subdomain) {
            node.add_child(TreeNode::port(port, service));
        }
    }

    /// Add technology to a subdomain
    pub fn add_tech_to_subdomain(&mut self, subdomain: &str, tech: &str, version: Option<&str>) {
        if let Some(node) = self.root.find_mut(subdomain) {
            node.add_child(TreeNode::technology(tech, version));
        }
    }

    /// Build and return the tree
    pub fn build(self) -> TreeNode {
        self.root
    }

    /// Get reference to root
    pub fn root(&self) -> &TreeNode {
        &self.root
    }

    /// Get mutable reference to root
    pub fn root_mut(&mut self) -> &mut TreeNode {
        &mut self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tree_node_creation() {
        let node = TreeNode::domain("example.com");
        assert_eq!(node.label, "example.com");
        assert_eq!(node.node_type, NodeType::Domain);
    }

    #[test]
    fn test_tree_with_children() {
        let mut root = TreeNode::domain("example.com");
        root.add_child(TreeNode::subdomain("api.example.com"));
        root.add_child(TreeNode::subdomain("www.example.com"));

        assert_eq!(root.count(), 3);
        assert_eq!(root.depth(), 2);
    }

    #[test]
    fn test_tree_render() {
        let mut root = TreeNode::domain("example.com");
        let mut api = TreeNode::subdomain("api.example.com").with_metadata("1.2.3.4");
        api.add_child(TreeNode::port(443, Some("HTTPS")));
        root.add_child(api);
        root.add_child(TreeNode::subdomain("mail.example.com"));

        let renderer = TreeRenderer::new().with_color(false);
        let output = renderer.render(&root);

        assert!(output.contains("example.com"));
        assert!(output.contains("├── api.example.com (1.2.3.4)"));
        assert!(output.contains("│   └── :443 (HTTPS)"));
        assert!(output.contains("└── mail.example.com"));
    }

    #[test]
    fn test_recon_tree_builder() {
        let mut builder = ReconTreeBuilder::new("example.com");
        builder.add_subdomain("api.example.com", &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        builder.add_nameserver("ns1.example.com");

        let tree = builder.build();
        assert_eq!(tree.count(), 4); // root + subdomain + IP + NS
    }

    #[test]
    fn test_find_node() {
        let mut root = TreeNode::domain("example.com");
        root.add_child(TreeNode::subdomain("api.example.com"));

        assert!(root.find("api.example.com").is_some());
        assert!(root.find("nonexistent").is_none());
    }
}
