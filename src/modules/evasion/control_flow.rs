//! Control Flow Obfuscation
//!
//! Techniques to make static analysis and reverse engineering harder:
//! - Opaque predicates (conditions that always evaluate to true/false)
//! - Dead code insertion
//! - Control flow flattening simulation
//! - Jump tables for indirect calls
//!
//! These techniques increase code complexity without affecting functionality.

use std::hint::black_box;
use std::time::{SystemTime, UNIX_EPOCH};

/// Opaque predicates - conditions that always evaluate to a known value
/// but are difficult for static analysis to determine
pub struct OpaquePredicates;

impl OpaquePredicates {
    /// Always returns true, but hard to determine statically
    /// Uses mathematical property: x^2 + x is always even
    #[inline(never)]
    pub fn always_true_math(seed: u32) -> bool {
        let x = black_box(seed);
        let result = x.wrapping_mul(x).wrapping_add(x);
        result % 2 == 0
    }

    /// Always returns false
    /// Uses property: (x^2 - 1) % 4 != 3 when x is odd
    #[inline(never)]
    pub fn always_false_math(seed: u32) -> bool {
        let x = black_box(seed | 1); // Ensure odd
        let result = x.wrapping_mul(x).wrapping_sub(1);
        result % 4 == 3
    }

    /// Always true using pointer arithmetic
    #[inline(never)]
    pub fn always_true_ptr() -> bool {
        let x: u64 = 0x12345678;
        let ptr = &x as *const u64;
        // Pointer to itself equals itself
        black_box(ptr) == black_box(ptr)
    }

    /// Always true using time (time always advances)
    #[inline(never)]
    pub fn always_true_time() -> bool {
        let t1 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::hint::spin_loop();
        let t2 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        black_box(t2) >= black_box(t1)
    }

    /// Always false - compares unequal constants through indirection
    #[inline(never)]
    pub fn always_false_const() -> bool {
        let a = black_box(0xDEADBEEFu32);
        let b = black_box(0xCAFEBABEu32);
        a == b
    }

    /// Opaque predicate using floating point properties
    #[inline(never)]
    pub fn always_true_float() -> bool {
        let x = black_box(1.0f64);
        let y = black_box(2.0f64);
        // (x + y)^2 >= 4xy is always true (AM-GM inequality)
        let sum = x + y;
        let product = x * y;
        sum * sum >= 4.0 * product
    }

    /// Get a random-looking but deterministic true value
    pub fn opaque_true(seed: u32) -> bool {
        match seed % 5 {
            0 => Self::always_true_math(seed),
            1 => Self::always_true_ptr(),
            2 => Self::always_true_time(),
            3 => Self::always_true_float(),
            _ => Self::always_true_math(seed.rotate_left(7)),
        }
    }

    /// Get a random-looking but deterministic false value
    pub fn opaque_false(seed: u32) -> bool {
        match seed % 3 {
            0 => Self::always_false_math(seed),
            1 => Self::always_false_const(),
            _ => Self::always_false_math(seed.rotate_right(5)),
        }
    }
}

/// Dead code blocks that are compiled but never executed
pub struct DeadCode;

impl DeadCode {
    /// Insert dead code that looks like real functionality
    #[inline(never)]
    pub fn fake_network_code() {
        if OpaquePredicates::always_false_const() {
            let _socket = black_box(42);
            let _addr = black_box([127u8, 0, 0, 1]);
            let _port = black_box(8080u16);
            // This never executes but appears in binary
            let mut _data = vec![0u8; 1024];
            for i in 0..1024 {
                _data[i] = (i & 0xFF) as u8;
            }
        }
    }

    /// Fake cryptographic code
    #[inline(never)]
    pub fn fake_crypto_code() {
        if OpaquePredicates::always_false_math(0xDEAD) {
            let mut _key = [0u8; 32];
            let mut _iv = [0u8; 16];
            for i in 0..32 {
                _key[i] = black_box((i * 7) as u8);
            }
            for i in 0..16 {
                _iv[i] = black_box((i * 11) as u8);
            }
        }
    }

    /// Fake file operations
    #[inline(never)]
    pub fn fake_file_code() {
        if OpaquePredicates::always_false_const() {
            let _path = black_box("/tmp/data.bin");
            let _mode = black_box(0o755);
            let _buffer = black_box(vec![0u8; 4096]);
        }
    }

    /// Fake string processing
    #[inline(never)]
    pub fn fake_string_code() {
        if OpaquePredicates::always_false_math(0xBEEF) {
            let _strings = black_box(vec![
                "config.xml",
                "settings.json",
                "data.db",
                "credentials.txt",
            ]);
            let _joined = black_box("fake|data|here");
        }
    }

    /// Insert all dead code blocks (call periodically)
    #[inline(never)]
    pub fn insert_all() {
        Self::fake_network_code();
        Self::fake_crypto_code();
        Self::fake_file_code();
        Self::fake_string_code();
    }
}

/// Control flow flattening - converts structured code to switch statement
pub struct ControlFlowFlattener {
    state: u32,
    states: Vec<u32>,
}

impl ControlFlowFlattener {
    /// Create new flattener with random-looking state sequence
    pub fn new(seed: u32) -> Self {
        let mut states = Vec::new();
        let mut state = seed;

        // Generate pseudo-random state sequence
        for _ in 0..10 {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            states.push(state);
        }

        Self {
            state: states[0],
            states,
        }
    }

    /// Execute flattened control flow
    /// Each "block" is represented by a state value
    pub fn execute<F>(&mut self, mut blocks: Vec<(u32, F)>)
    where
        F: FnMut() -> Option<u32>,
    {
        let mut iterations = 0;
        let max_iterations = 1000; // Prevent infinite loops

        while iterations < max_iterations {
            let mut found = false;

            for (block_state, block_fn) in blocks.iter_mut() {
                if *block_state == self.state {
                    found = true;
                    if let Some(next_state) = block_fn() {
                        self.state = next_state;
                    } else {
                        return; // Terminal state
                    }
                    break;
                }
            }

            if !found {
                return; // No matching state, exit
            }

            iterations += 1;
        }
    }

    /// Get current state
    pub fn state(&self) -> u32 {
        self.state
    }

    /// Get state at index
    pub fn get_state(&self, index: usize) -> u32 {
        self.states.get(index).copied().unwrap_or(0)
    }
}

/// Jump table for indirect function calls
pub struct JumpTable<F> {
    table: Vec<F>,
    mapping: Vec<usize>,
}

impl<F> JumpTable<F>
where
    F: Fn(),
{
    /// Create new jump table with shuffled indices
    pub fn new(functions: Vec<F>, seed: u32) -> Self {
        let len = functions.len();
        let mut mapping: Vec<usize> = (0..len).collect();

        // Shuffle mapping using seed
        let mut state = seed;
        for i in (1..len).rev() {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            let j = (state as usize) % (i + 1);
            mapping.swap(i, j);
        }

        Self {
            table: functions,
            mapping,
        }
    }

    /// Call function by logical index (uses shuffled mapping)
    pub fn call(&self, logical_index: usize) {
        if let Some(&actual_index) = self.mapping.get(logical_index) {
            if let Some(func) = self.table.get(actual_index) {
                func();
            }
        }
    }

    /// Call function by actual index (direct)
    pub fn call_direct(&self, actual_index: usize) {
        if let Some(func) = self.table.get(actual_index) {
            func();
        }
    }

    /// Get the actual index for a logical index
    pub fn get_actual_index(&self, logical_index: usize) -> Option<usize> {
        self.mapping.get(logical_index).copied()
    }
}

/// Instruction substitution patterns
pub struct InstructionSubstitution;

impl InstructionSubstitution {
    /// Substitute addition with equivalent operations
    #[inline(never)]
    pub fn add_substitute(a: u32, b: u32) -> u32 {
        // a + b = a - (-b) = a ^ b + 2*(a & b)
        let method = black_box(a.wrapping_add(b)) % 3;
        match method {
            0 => a.wrapping_sub((!b).wrapping_add(1)), // a - (-b)
            1 => (a ^ b).wrapping_add((a & b) << 1),   // XOR + carry
            _ => a.wrapping_add(b),                    // Normal
        }
    }

    /// Substitute subtraction with equivalent operations
    #[inline(never)]
    pub fn sub_substitute(a: u32, b: u32) -> u32 {
        let method = black_box(a.wrapping_add(b)) % 3;
        match method {
            0 => a.wrapping_add((!b).wrapping_add(1)), // a + (-b)
            1 => (a ^ b).wrapping_sub(((!a) & b) << 1),
            _ => a.wrapping_sub(b),
        }
    }

    /// Substitute XOR with equivalent operations
    #[inline(never)]
    pub fn xor_substitute(a: u32, b: u32) -> u32 {
        let method = black_box(a.wrapping_add(b)) % 3;
        match method {
            0 => (a | b) & !(a & b), // (a | b) & ~(a & b)
            1 => (a & !b) | (!a & b), // (a & ~b) | (~a & b)
            _ => a ^ b,
        }
    }

    /// Substitute multiplication with shifts and additions
    #[inline(never)]
    pub fn mul_substitute(a: u32, b: u32) -> u32 {
        // Only for small b values
        if b < 16 {
            let mut result = 0u32;
            for i in 0..32 {
                if (b >> i) & 1 == 1 {
                    result = result.wrapping_add(a << i);
                }
            }
            result
        } else {
            a.wrapping_mul(b)
        }
    }
}

/// Generate code with control flow obfuscation
pub fn generate_obfuscated_code(original_code: &str) -> String {
    let mut result = String::new();

    result.push_str("// Obfuscated code block\n");
    result.push_str("{\n");

    // Add opaque predicate guard
    result.push_str("    if OpaquePredicates::opaque_true(0x12345678) {\n");

    // Insert dead code
    result.push_str("        DeadCode::insert_all();\n");

    // Original code with indentation
    for line in original_code.lines() {
        result.push_str("        ");
        result.push_str(line);
        result.push('\n');
    }

    result.push_str("    }\n");
    result.push_str("}\n");

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_true() {
        for seed in 0..100 {
            assert!(OpaquePredicates::always_true_math(seed));
            assert!(OpaquePredicates::opaque_true(seed));
        }
    }

    #[test]
    fn test_opaque_false() {
        for seed in 0..100 {
            assert!(!OpaquePredicates::always_false_math(seed));
            assert!(!OpaquePredicates::always_false_const());
            assert!(!OpaquePredicates::opaque_false(seed));
        }
    }

    #[test]
    fn test_dead_code_no_side_effects() {
        // Dead code should not affect program state
        DeadCode::insert_all();
        // If we get here, dead code didn't cause issues
    }

    #[test]
    fn test_instruction_substitution() {
        for a in 0..100u32 {
            for b in 0..100u32 {
                assert_eq!(
                    InstructionSubstitution::add_substitute(a, b),
                    a.wrapping_add(b)
                );
                assert_eq!(
                    InstructionSubstitution::sub_substitute(a, b),
                    a.wrapping_sub(b)
                );
                assert_eq!(InstructionSubstitution::xor_substitute(a, b), a ^ b);
            }
        }
    }

    #[test]
    fn test_jump_table() {
        let mut called = vec![false; 3];
        let called_ref = &mut called;

        // Can't easily test with closures that mutate, so just test structure
        let table = JumpTable::new(
            vec![|| println!("0"), || println!("1"), || println!("2")],
            0x12345678,
        );

        // Verify mapping exists
        assert!(table.get_actual_index(0).is_some());
        assert!(table.get_actual_index(1).is_some());
        assert!(table.get_actual_index(2).is_some());
    }
}
