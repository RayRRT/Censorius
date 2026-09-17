//! Interactive wizard: collects a RunConfig via prompts and runs the pipeline.
//! Thin by design — all logic lives in `pipeline::run_pipeline` (tested there).

use std::path::PathBuf;

use anyhow::Result;
use inquire::{Confirm, CustomType, Select, Text};

use crate::pipeline::{run_pipeline, InputSource, RunConfig};
use crate::policy::{ClassMins, Constraint, PasswordPolicy};

/// How the policy requires character classes.
pub enum ClassMode {
    /// Explicit minimum count of each class.
    PerClass { lower: u8, upper: u8, digit: u8, special: u8 },
    /// At least N distinct classes among {lower, upper, digit, special} (M-of-N).
    MOfN(u8),
}

/// Pure mapping from wizard answers to a PasswordPolicy (unit-tested).
pub fn build_policy(
    min_len: u8,
    max_len: u8,
    mode: ClassMode,
    special_set: String,
    forbidden_chars: String,
    not_start_with_digit: bool,
) -> PasswordPolicy {
    let (require, min_classes) = match mode {
        ClassMode::PerClass { lower, upper, digit, special } => {
            (ClassMins { lower, upper, digit, special }, None)
        }
        ClassMode::MOfN(n) => (ClassMins::default(), Some(n)),
    };
    let mut constraints = Vec::new();
    if not_start_with_digit {
        constraints.push(Constraint::NotStartWithDigit);
    }
    PasswordPolicy { min_len, max_len, require, special_set, forbidden_chars, min_classes, constraints }
}

pub fn run_wizard() -> Result<()> {
    println!("Censorius — authorized pentesting use only.\n");

    let min_len: u8 = CustomType::new("Minimum length?").prompt()?;
    let max_len: u8 = CustomType::new("Maximum length?").prompt()?;
    let upper: u8 = CustomType::new("Required uppercase (min)?").with_default(1).prompt()?;
    let lower: u8 = CustomType::new("Required lowercase (min)?").with_default(1).prompt()?;
    let digit: u8 = CustomType::new("Required digits (min)?").with_default(1).prompt()?;
    let special: u8 = CustomType::new("Required specials (min)?").with_default(0).prompt()?;
    let special_set = Text::new("Allowed special chars?").with_default("!@#$%._-").prompt()?;

    let policy = PasswordPolicy {
        min_len,
        max_len,
        require: ClassMins { lower, upper, digit, special },
        special_set,
        forbidden_chars: String::new(),
        min_classes: None,
        constraints: vec![],
    };
    policy.validate()?;

    let source = Select::new("Wordlist source?", vec!["Existing file", "Generate from seeds"]).prompt()?;
    let (input, years): (InputSource, Vec<u16>) = if source == "Existing file" {
        let path = Text::new("Path to base wordlist?").prompt()?;
        let years_raw = Text::new("Relevant years (comma-separated)?").with_default("2024,2025").prompt()?;
        let years: Vec<u16> = years_raw.split(',').filter_map(|s| s.trim().parse::<u16>().ok()).collect();
        (InputSource::Wordlist(PathBuf::from(path)), years)
    } else {
        let tokens_raw = Text::new("Seed tokens (comma-separated: company, product, city)?").prompt()?;
        let tokens = tokens_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        let years_raw = Text::new("Relevant years (comma-separated)?").with_default("2024,2025").prompt()?;
        let years: Vec<u16> = years_raw.split(',').filter_map(|s| s.trim().parse::<u16>().ok()).collect();
        (
            InputSource::Seeds(crate::genwl::SeedInput { tokens, years: years.clone(), max_size: 100_000 }),
            years,
        )
    };

    let out_dir = Text::new("Output directory?").with_default("censorius-out").prompt()?;
    let hashes_path = Text::new("Path to hashes file?").with_default("hashes.txt").prompt()?;
    let hash_mode = Text::new("hashcat -m mode (blank = fill later)?").prompt()?;
    let hash_mode = if hash_mode.trim().is_empty() { None } else { Some(hash_mode) };
    let mask_budget: u64 = CustomType::new("Max keyspace per mask (budget)?").with_default(100_000_000_000).prompt()?;
    let hashrate: u64 = CustomType::new("Assumed hash rate (H/s) for time estimate?").with_default(1_000_000_000).prompt()?;

    let cfg = RunConfig {
        policy,
        input,
        out_dir: PathBuf::from(out_dir),
        hash_mode,
        hashes_path,
        rule_budget: 500,
        mask_budget_per: mask_budget,
        len_span: 3,
        years,
    };

    if !Confirm::new("Generate artifacts now?").with_default(true).prompt()? {
        println!("Aborted.");
        return Ok(());
    }

    let art = run_pipeline(&cfg)?;
    crate::pipeline::print_summary(&art, hashrate);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Constraint;

    #[test]
    fn per_class_mode_sets_requires_and_no_min_classes() {
        let p = build_policy(8, 16,
            ClassMode::PerClass { lower: 1, upper: 1, digit: 1, special: 0 },
            "!@#$".into(), String::new(), false);
        assert_eq!(p.require.lower, 1);
        assert_eq!(p.require.special, 0);
        assert_eq!(p.min_classes, None);
        assert!(p.constraints.is_empty());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn m_of_n_mode_sets_min_classes_and_zero_requires() {
        let p = build_policy(8, 16, ClassMode::MOfN(3), "!@#$".into(), String::new(), false);
        assert_eq!(p.min_classes, Some(3));
        assert_eq!(p.require, crate::policy::ClassMins::default());
        assert!(p.validate().is_ok());
    }

    #[test]
    fn not_start_with_digit_adds_constraint() {
        let p = build_policy(8, 16, ClassMode::MOfN(3), "!@#$".into(), " ".into(), true);
        assert!(p.constraints.contains(&Constraint::NotStartWithDigit));
        assert_eq!(p.forbidden_chars, " ");
    }
}
