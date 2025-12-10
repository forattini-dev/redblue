pub struct CredentialIterator {
    users: Vec<String>,
    passwords: Vec<String>,
    user_idx: usize,
    pass_idx: usize,
}

impl CredentialIterator {
    pub fn new(users: Vec<String>, passwords: Vec<String>) -> Self {
        Self {
            users,
            passwords,
            user_idx: 0,
            pass_idx: 0,
        }
    }
}

impl Iterator for CredentialIterator {
    type Item = (String, String);

    fn next(&mut self) -> Option<Self::Item> {
        if self.user_idx >= self.users.len() {
            return None;
        }

        let user = &self.users[self.user_idx];
        let pass = if self.passwords.is_empty() {
            String::new()
        } else {
            self.passwords[self.pass_idx].clone()
        };

        let result = (user.clone(), pass);

        // Advance
        if !self.passwords.is_empty() {
            self.pass_idx += 1;
            if self.pass_idx >= self.passwords.len() {
                self.pass_idx = 0;
                self.user_idx += 1;
            }
        } else {
            self.user_idx += 1;
        }

        Some(result)
    }
}
