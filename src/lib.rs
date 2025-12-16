// Crate-level lint configuration
// These are stylistic warnings that don't affect correctness
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::new_without_default)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::inherent_to_string)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::get_first)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::for_kv_map)]
#![allow(clippy::useless_conversion)]
#![allow(clippy::manual_is_ascii_check)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_swap)]
#![allow(clippy::manual_contains)]
#![allow(clippy::unnecessary_lazy_evaluations)]
#![allow(clippy::unnecessary_get_then_check)]
#![allow(clippy::trim_split_whitespace)]
#![allow(clippy::option_as_ref_deref)]
#![allow(clippy::map_clone)]
#![allow(clippy::explicit_auto_deref)]
#![allow(clippy::useless_vec)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::io_other_error)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::single_char_add_str)]
#![allow(clippy::same_item_push)]
#![allow(clippy::no_effect_replace)]
#![allow(clippy::needless_return)]
#![allow(clippy::module_inception)]
#![allow(clippy::manual_strip)]
#![allow(clippy::manual_flatten)]
#![allow(clippy::lines_filter_map_ok)]
#![allow(clippy::let_and_return)]
#![allow(clippy::iter_kv_map)]
#![allow(clippy::identity_op)]
#![allow(clippy::double_ended_iterator_last)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::clone_on_copy)]
#![allow(clippy::write_with_newline)]
#![allow(clippy::match_ref_pats)]
#![allow(clippy::search_is_some)]
#![allow(clippy::single_match)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::needless_late_init)]
#![allow(clippy::cmp_owned)]
#![allow(clippy::assign_op_pattern)]
#![allow(clippy::neg_multiply)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::suspicious_else_formatting)]
#![allow(clippy::blocks_in_conditions)]
#![allow(clippy::bind_instead_of_map)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_str_replace)]
#![allow(clippy::default_constructed_unit_structs)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::implicit_saturating_sub)]
#![allow(clippy::ineffective_open_options)]
#![allow(clippy::iter_cloned_collect)]
#![allow(clippy::iter_skip_next)]
#![allow(clippy::len_zero)]
#![allow(clippy::let_unit_value)]
#![allow(clippy::manual_abs_diff)]
#![allow(clippy::manual_clamp)]
#![allow(clippy::manual_find)]
#![allow(clippy::manual_map)]
#![allow(clippy::manual_range_patterns)]
#![allow(clippy::manual_repeat_n)]
#![allow(clippy::manual_unwrap_or_default)]
#![allow(clippy::map_identity)]
#![allow(clippy::missing_const_for_thread_local)]
#![allow(clippy::needless_as_bytes)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::question_mark)]
#![allow(clippy::sliced_string_as_bytes)]
#![allow(clippy::slow_vector_initialization)]
#![allow(clippy::unnecessary_filter_map)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::unnecessary_sort_by)]
#![allow(clippy::wildcard_in_or_patterns)]

pub mod accessors; // System accessors for agent
pub mod agent; // C2 Agent and Server
pub mod assess; // Assessment workflow - fingerprint → vuln → playbook
pub mod cli;
pub mod compression; // Native gzip/DEFLATE decompression (RFC 1952/1951)
pub mod config;
pub mod core;
pub mod crypto;
pub mod error;
pub mod intelligence;
pub mod mcp;
pub mod modules;
pub mod playbooks; // Red Team playbooks with internal MITRE mapping
pub mod protocols;
pub mod scripts; // Zero-dependency scripting engine for security checks
pub mod storage;
pub mod ui; // Terminal graphics library (Braille canvas, charts, colors)
pub mod utils;
pub mod wordlists; // Wordlist management for bruteforce operations
