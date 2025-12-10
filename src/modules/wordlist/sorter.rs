pub enum SortOrder {
    Ascending,
    Descending,
}

pub enum SortKey {
    Alpha,
    Length,
}

pub struct Sorter;

impl Sorter {
    pub fn sort(words: &mut [String], key: SortKey, order: SortOrder) {
        match key {
            SortKey::Alpha => {
                words.sort();
            }
            SortKey::Length => {
                words.sort_by(|a, b| a.len().cmp(&b.len()));
            }
        }
        
        if let SortOrder::Descending = order {
            words.reverse();
        }
    }
}
