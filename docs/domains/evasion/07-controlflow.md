# Control Flow Obfuscation

> Make static analysis and reverse engineering harder.

## Overview

The `controlflow` resource provides techniques to obfuscate code:
- Opaque predicates
- Dead code insertion
- Instruction substitution
- Control flow flattening

## Commands

| Command | Description |
|---------|-------------|
| `demo` | Demo all control flow techniques |
| `predicates` | Show opaque predicate examples |
| `substitute` | Show instruction substitution |

## Usage

### Demo All Techniques

```bash
rb evasion controlflow demo
```

Output:
```
▸ Control Flow Obfuscation Demo

ℹ 1. Opaque Predicates (always true/false, hard to analyze):
    always_true_math(42):   true
    always_true_ptr():      true
    always_true_float():    true
    always_false_math(42):  false
    always_false_const():   false

ℹ 2. Dead Code Insertion:
    fake_crypto_code():  [complex but unused code]
    fake_network_code(): [socket-like operations]
    fake_file_code():    [file handling stubs]
    All blocks contain dead code (never executed)

ℹ 3. Instruction Substitution:
    add_substitute(10, 5): 15
    sub_substitute(10, 5): 5
    xor_substitute(10, 5): 15
```

## Techniques

### 1. Opaque Predicates

Conditions that always evaluate to known values but are hard to analyze statically:

```rust
use redblue::modules::evasion::control_flow::OpaquePredicates;

// Always returns true (x^2 + x is always even)
if OpaquePredicates::always_true_math(seed) {
    // Real code here
}

// Always returns false
if OpaquePredicates::always_false_const() {
    // Dead code - never executes
}
```

**Available predicates:**
- `always_true_math(seed)` - Mathematical property
- `always_true_ptr()` - Pointer comparison
- `always_true_time()` - Time always advances
- `always_true_float()` - AM-GM inequality
- `always_false_math(seed)` - Mathematical property
- `always_false_const()` - Constant comparison

### 2. Dead Code Insertion

Insert code that looks real but never executes:

```rust
use redblue::modules::evasion::control_flow::DeadCode;

// Insert all dead code blocks
DeadCode::insert_all();

// Or individually:
DeadCode::fake_network_code();   // Socket-like operations
DeadCode::fake_crypto_code();    // Encryption-looking code
DeadCode::fake_file_code();      // File handling
DeadCode::fake_string_code();    // String processing
```

### 3. Instruction Substitution

Replace operations with equivalent but obfuscated versions:

```rust
use redblue::modules::evasion::control_flow::InstructionSubstitution;

// These all produce correct results via different methods:
let sum = InstructionSubstitution::add_substitute(a, b);
let diff = InstructionSubstitution::sub_substitute(a, b);
let xored = InstructionSubstitution::xor_substitute(a, b);
let product = InstructionSubstitution::mul_substitute(a, b);
```

**Substitution examples:**
- `a + b` → `a - (-b)` or `(a ^ b) + 2*(a & b)`
- `a - b` → `a + (!b + 1)`
- `a ^ b` → `(a | b) & ~(a & b)`

### 4. Control Flow Flattening

Convert structured code to state machine:

```rust
use redblue::modules::evasion::control_flow::ControlFlowFlattener;

let mut flattener = ControlFlowFlattener::new(seed);

// Define blocks with state transitions
let blocks = vec![
    (state1, || { do_block1(); Some(state2) }),
    (state2, || { do_block2(); Some(state3) }),
    (state3, || { do_block3(); None }),  // Terminal
];

flattener.execute(blocks);
```

## Why Control Flow Obfuscation?

| Threat | Defense |
|--------|---------|
| Decompiler | Opaque predicates confuse analysis |
| Pattern matching | Dead code adds noise |
| Static analysis | Instruction substitution hides intent |
| IDA Pro | Control flow flattening hides structure |

## Related

- [strings](/domains/evasion/08-strings.md) - String encryption
- [apihash](/domains/evasion/06-apihash.md) - API hashing
- [memory](/domains/evasion/04-memory.md) - Memory protection
