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
    println!("Censorius — build a hashcat attack from a password policy.");
    println!("Authorized penetration testing only. Press Ctrl+C to quit.\n");
    println!("== Password policy ==");

    let min_len: u8 = CustomType::new("Minimum password length:")
        .with_default(8)
        .with_help_message("Shortest length the target policy allows (e.g. 8).")
        .prompt()?;
    let max_len: u8 = CustomType::new("Maximum password length:")
        .with_default(16)
        .with_help_message("Longest length to consider (bounds mask generation).")
        .prompt()?;

    let mode_label = Select::new(
        "How does the policy require character classes?",
        vec!["Minimum of each class", "At least N of the 4 classes (M-of-N)"],
    )
    .with_help_message("M-of-N is typical Active Directory complexity, e.g. '3 of 4 categories'.")
    .prompt()?;

    let mode = if mode_label.starts_with("At least N") {
        let n: u8 = CustomType::new("How many of the 4 classes must be present? (1-4)")
            .with_default(3)
            .with_help_message("Classes = lowercase, UPPERCASE, digits, symbols.")
            .prompt()?;
        ClassMode::MOfN(n)
    } else {
        let upper: u8 = CustomType::new("Minimum UPPERCASE letters:").with_default(1)
            .with_help_message("0 = not required.").prompt()?;
        let lower: u8 = CustomType::new("Minimum lowercase letters:").with_default(1)
            .with_help_message("0 = not required.").prompt()?;
        let digit: u8 = CustomType::new("Minimum digits:").with_default(1)
            .with_help_message("0 = not required.").prompt()?;
        let special: u8 = CustomType::new("Minimum symbols:").with_default(0)
            .with_help_message("0 = not required. Symbols are the special characters below.").prompt()?;
        ClassMode::PerClass { lower, upper, digit, special }
    };

    let special_set = Text::new("Allowed special characters:")
        .with_default("!@#$%^&*()-_=+")
        .with_help_message("Punctuation ONLY (no letters, digits, or comma). Press Enter for the default set. This is the symbol alphabet used to build masks — not a yes/no.")
        .prompt()?;

    let forbidden_chars = Text::new("Characters to forbid (optional):")
        .with_default("")
        .with_help_message("Any characters the policy disallows, e.g. a space. Press Enter for none.")
        .prompt()?;

    let not_start_with_digit = Confirm::new("Forbid passwords that start with a digit?")
        .with_default(false)
        .with_help_message("Some policies disallow a leading digit.")
        .prompt()?;

    let policy = build_policy(min_len, max_len, mode, special_set, forbidden_chars, not_start_with_digit);
    if let Err(e) = policy.validate() {
        // Friendly, actionable message instead of a raw error.
        return Err(anyhow::anyhow!("That policy isn't valid: {e}. Please re-run and adjust."));
    }

    println!("\n== Target words ==");
    let source = Select::new(
        "Where do the base words come from?",
        vec![
            "An existing wordlist file (e.g. rockyou.txt)",
            "Generate from target details (company, product, city, ...)",
        ],
    )
    .with_help_message("The dictionary+rules attack mutates these base words into policy-compliant candidates.")
    .prompt()?;

    let (input, years): (InputSource, Vec<u16>) = if source.starts_with("An existing") {
        let path = Text::new("Path to the wordlist file:")
            .with_help_message("e.g. C:\\wordlists\\rockyou.txt")
            .prompt()?;
        let years = ask_years()?;
        (InputSource::Wordlist(PathBuf::from(path)), years)
    } else {
        let tokens_raw = Text::new("Target seed words (comma-separated):")
            .with_help_message("Company, product, city, mascot, ... e.g. acme, widgets, madrid")
            .prompt()?;
        let tokens: Vec<String> = tokens_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        let years = ask_years()?;
        (
            InputSource::Seeds(crate::genwl::SeedInput { tokens, years: years.clone(), max_size: 100_000 }),
            years,
        )
    };

    println!("\n== Attack settings ==");
    let hash_mode = Text::new("hashcat hash-type (-m), optional:")
        .with_help_message("Examples: 0 = MD5, 1000 = NTLM, 1800 = sha512crypt, 3200 = bcrypt. Press Enter to fill in later.")
        .prompt()?;
    let hash_mode = if hash_mode.trim().is_empty() { None } else { Some(hash_mode) };

    let mask_budget: u64 = CustomType::new("Max candidates per mask (budget):")
        .with_default(100_000_000_000)
        .with_help_message("Masks larger than this are skipped. Higher = more/longer masks. ~1e11 is seconds on a fast hash.")
        .prompt()?;
    let hashrate: u64 = CustomType::new("Assumed hash rate in H/s (for the time estimate):")
        .with_default(1_000_000_000)
        .with_help_message("Measure your real rate with:  censorius bench --mode <m> --hashcat <path>")
        .prompt()?;

    println!("\n== Output ==");
    let hashes_path = Text::new("Path to your hashes file:")
        .with_default("hashes.txt")
        .with_help_message("The file of hashes you'll crack (used to build the ready hashcat command).")
        .prompt()?;
    let out_dir = Text::new("Output directory:")
        .with_default("censorius-out")
        .with_help_message("Where the wordlist, rules, masks, and commands are written.")
        .prompt()?;

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

    println!();
    if !Confirm::new("Generate the attack artifacts now?").with_default(true).prompt()? {
        println!("Cancelled — nothing written.");
        return Ok(());
    }

    let art = run_pipeline(&cfg)?;
    crate::pipeline::print_summary(&art, hashrate);
    Ok(())
}

/// Prompt for comma-separated relevant years.
fn ask_years() -> Result<Vec<u16>> {
    let raw = Text::new("Relevant years (comma-separated):")
        .with_default("2024,2025")
        .with_help_message("Years appended to base words (birth years, current year, ...).")
        .prompt()?;
    Ok(raw.split(',').filter_map(|s| s.trim().parse::<u16>().ok()).collect())
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
