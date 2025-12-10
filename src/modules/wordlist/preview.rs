pub struct Preview;

impl Preview {
    pub fn top_n(words: &[String], n: usize) -> Vec<String> {
        words.iter().take(n).cloned().collect()
    }
}
