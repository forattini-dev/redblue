use crate::modules::web::dom::{Document, Node};
use crate::compression::crc32;
use std::collections::HashMap;

pub struct Clusterer;

impl Clusterer {
    /// Computes a structural signature for the HTML content.
    /// The signature is a CRC32 hash of the tag structure.
    pub fn compute_signature(html: &str) -> String {
        let doc = Document::parse(html);
        let mut structure = String::new();
        
        // Traverse roots
        for &root_idx in doc.roots() {
            Self::traverse(&doc, root_idx, &mut structure);
        }
        
        let hash = crc32(structure.as_bytes());
        format!("{:08x}", hash)
    }

    fn traverse(doc: &Document, elem_idx: usize, buffer: &mut String) {
        if let Some(elem) = doc.get_element(elem_idx) {
            buffer.push_str(&elem.tag);
            buffer.push('(');
            for child in &elem.children {
                if let Node::ElementRef(child_idx) = child {
                    Self::traverse(doc, *child_idx, buffer);
                }
            }
            buffer.push(')');
        }
    }

    /// Clusters a list of HTML documents based on their structural similarity.
    /// Returns a map of Signature -> List of Indices.
    pub fn cluster(documents: &[String]) -> HashMap<String, Vec<usize>> {
        let mut clusters: HashMap<String, Vec<usize>> = HashMap::new();
        
        for (i, html) in documents.iter().enumerate() {
            let sig = Self::compute_signature(html);
            clusters.entry(sig).or_default().push(i);
        }
        
        clusters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clustering_identical_structure() {
        let html1 = "<div><p>Hello</p></div>";
        let html2 = "<div><p>World</p></div>"; // Same structure
        
        let sig1 = Clusterer::compute_signature(html1);
        let sig2 = Clusterer::compute_signature(html2);
        
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_clustering_different_structure() {
        let html1 = "<div><p>Hello</p></div>";
        let html2 = "<div><a>Link</a></div>"; // Different tag
        
        let sig1 = Clusterer::compute_signature(html1);
        let sig2 = Clusterer::compute_signature(html2);
        
        assert_ne!(sig1, sig2);
    }
    
    #[test]
    fn test_clustering_batch() {
        let docs = vec![
            "<div>A</div>".to_string(),
            "<span>B</span>".to_string(),
            "<div>C</div>".to_string(),
        ];
        
        let clusters = Clusterer::cluster(&docs);
        assert_eq!(clusters.len(), 2);
        
        // Find signature for div
        let div_sig = Clusterer::compute_signature("<div></div>");
        // Find signature for span
        let span_sig = Clusterer::compute_signature("<span></span>");
        
        assert!(clusters.values().any(|v| v.len() == 2)); // Two divs
    }
}
