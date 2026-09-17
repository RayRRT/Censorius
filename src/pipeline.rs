//! Orchestration: resolve inputs, run the pipeline, write artifacts.

use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use indicatif::ProgressBar;

use crate::command::{build_commands, CommandInputs};
use crate::genwl::{self, SeedInput};
use crate::maskgen::{self, MaskGenOpts};
use crate::policy::PasswordPolicy;
use crate::prune;
use crate::ruleengine::{apply, complies};
use crate::rulegen::{generate_rules, RuleGenOpts};

const PREVIEW_SAMPLE: usize = 200;

pub enum InputSource {
    Wordlist(PathBuf),
    Seeds(SeedInput),
}

pub struct RunConfig {
    pub policy: PasswordPolicy,
    pub input: InputSource,
    pub out_dir: PathBuf,
    pub hash_mode: Option<String>,
    pub hashes_path: String,
    pub rule_budget: usize,
    pub mask_budget_per: u64,
    pub len_span: u8,
    pub years: Vec<u16>,
}

pub struct Stats {
    pub input_count: usize,
    pub kept_count: usize,
    pub rule_count: usize,
    pub mask_count: usize,
    pub sample: Vec<String>,
    pub compliance_rate: f64,
    pub dict_keyspace: u64,
    pub mask_keyspace: u64,
}

pub struct Artifacts {
    pub out_dir: PathBuf,
    pub wordlist_file: PathBuf,
    pub rule_file: PathBuf,
    pub mask_file: PathBuf,
    pub commands_file: PathBuf,
    pub policy_file: PathBuf,
    pub stats: Stats,
}

pub fn run_pipeline(cfg: &RunConfig) -> Result<Artifacts> {
    cfg.policy.validate().map_err(|e| anyhow::anyhow!("invalid policy: {e}"))?;
    fs::create_dir_all(&cfg.out_dir)
        .with_context(|| format!("creating output dir {}", cfg.out_dir.display()))?;

    // 1) Resolve base words + prune conservatively. The Wordlist branch
    // streams the file (read line -> test -> write kept line) for bounded
    // memory on multi-GB lists, wrapping the reader with a progress bar at
    // the I/O edge. The Seeds branch stays in-memory (genwl is bounded by
    // max_size).
    let (wordlist_file, input_count, kept_count, sample_words): (PathBuf, usize, usize, Vec<String>) =
        match &cfg.input {
            InputSource::Wordlist(path) => {
                let wl_file = cfg.out_dir.join("pruned.txt");
                let file = File::open(path)
                    .with_context(|| format!("opening wordlist {}", path.display()))?;
                let total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
                let pb = ProgressBar::new(total_bytes);
                pb.set_style(
                    indicatif::ProgressStyle::with_template(
                        "  pruning {bar:30} {bytes}/{total_bytes} ({eta})",
                    )
                    .unwrap_or_else(|_| indicatif::ProgressStyle::default_bar()),
                );
                let reader = BufReader::new(pb.wrap_read(file));
                let mut out = BufWriter::new(
                    File::create(&wl_file)
                        .with_context(|| format!("creating {}", wl_file.display()))?,
                );
                let stream_res = prune::prune_stream(reader, &cfg.policy, &mut out, PREVIEW_SAMPLE);
                pb.finish_and_clear();
                let (total, kept, sample) = stream_res?; // bar already cleared on error
                out.flush()
                    .with_context(|| format!("flushing {}", wl_file.display()))?;
                (wl_file, total, kept, sample)
            }
            InputSource::Seeds(seed) => {
                let base = genwl::generate_wordlist(seed);
                let kept = prune::prune(&base, &cfg.policy);
                let wl_file = cfg.out_dir.join("seeds.txt");
                write_lines(&wl_file, &kept)?;
                let sample: Vec<String> = kept.iter().take(PREVIEW_SAMPLE).cloned().collect();
                (wl_file, base.len(), kept.len(), sample)
            }
        };

    // 3) Rules.
    let rules = generate_rules(
        &cfg.policy,
        &RuleGenOpts { years: cfg.years.clone(), budget: cfg.rule_budget },
    );

    // 4) Masks.
    let mask_opts = MaskGenOpts { budget_per_mask: cfg.mask_budget_per, len_span: cfg.len_span, filler: 'l' };
    let masks = maskgen::generate_masks(&cfg.policy, &mask_opts);
    if masks.is_empty() {
        match maskgen::min_compliant_keyspace(&cfg.policy, &mask_opts) {
            Some(k) => eprintln!("warning: 0 masks within budget {} — smallest compliant mask keyspace is {}. Re-run with --mask-budget {} (or higher) to include it, or rely on the dictionary+rules attack.", cfg.mask_budget_per, k, k),
            None => eprintln!("warning: 0 masks generated — no mask shape satisfies this policy's length/class requirements; rely on the dictionary+rules attack."),
        }
    }

    // 5) Write artifacts (wordlist already written above, per-branch).
    let rule_file = cfg.out_dir.join("policy.rule");
    write_lines(&rule_file, &rules)?;

    let mask_file = cfg.out_dir.join("masks.hcmask");
    let mask_lines: Vec<String> = masks
        .iter()
        .map(|m| match &m.custom1 {
            Some(c) => format!("{c},{}", m.mask),
            None => m.mask.clone(),
        })
        .collect();
    write_lines(&mask_file, &mask_lines)?;

    let policy_file = cfg.out_dir.join("policy.toml");
    fs::write(&policy_file, cfg.policy.to_toml())
        .with_context(|| format!("writing {}", policy_file.display()))?;

    let dict_keyspace = (kept_count as u64).saturating_mul(rules.len() as u64);
    let ss = if cfg.policy.special_set.is_empty() { None } else { Some(cfg.policy.special_set.as_str()) };
    let mask_keyspace = masks
        .iter()
        .fold(0u64, |acc, m| acc.saturating_add(maskgen::keyspace(ss, &m.mask)));

    let cmds = build_commands(&CommandInputs {
        hash_mode: cfg.hash_mode.as_deref(),
        hashes_path: &cfg.hashes_path,
        wordlist_path: &wordlist_file.to_string_lossy(),
        rule_path: &rule_file.to_string_lossy(),
        hcmask_path: &mask_file.to_string_lossy(),
    });
    let commands_file = cfg.out_dir.join("commands.txt");
    let commands_body = format!(
        "# {}\n# attack size (candidates): dict+rules={}, masks={}\n\n{}\n{}\n",
        cmds.note, dict_keyspace, mask_keyspace, cmds.dict, cmds.mask
    );
    fs::write(&commands_file, commands_body)
        .with_context(|| format!("writing {}", commands_file.display()))?;

    // 6) Honest preview sample: apply first rule to first few kept words.
    let mut sample = Vec::new();
    if let Some(first_rule) = rules.first() {
        for w in sample_words.iter().take(5) {
            if let Ok(out) = apply(w, first_rule) {
                sample.push(out);
            }
        }
    }

    // 7) Honest-preview compliance rate: over a bounded sample of kept words
    // (streamed or collected, capped at PREVIEW_SAMPLE), the fraction for
    // which ANY generated rule yields a compliant candidate.
    let sample_len = sample_words.len();
    let covered = sample_words
        .iter()
        .filter(|w| {
            rules.iter().any(|rule| {
                apply(w, rule).map(|cand| complies(&cand, &cfg.policy)).unwrap_or(false)
            })
        })
        .count();
    let compliance_rate = if sample_len == 0 { 0.0 } else { covered as f64 / sample_len as f64 };

    Ok(Artifacts {
        out_dir: cfg.out_dir.clone(),
        wordlist_file,
        rule_file,
        mask_file,
        commands_file,
        policy_file,
        stats: Stats {
            input_count,
            kept_count,
            rule_count: rules.len(),
            mask_count: masks.len(),
            sample,
            compliance_rate,
            dict_keyspace,
            mask_keyspace,
        },
    })
}

/// Print a human-readable summary of a completed run. Shared by the wizard
/// and the non-interactive `run` subcommand.
pub fn print_summary(art: &Artifacts, hashrate: u64) {
    use crate::estimate::{estimate_seconds, format_duration};
    println!("\nDone. Wrote artifacts to {}", art.out_dir.display());
    println!("  input words:   {}", art.stats.input_count);
    println!("  kept (pruned): {}", art.stats.kept_count);
    println!("  rules:         {}", art.stats.rule_count);
    println!("  masks:         {}", art.stats.mask_count);
    println!(
        "  compliance preview: {:.0}% of sampled base words have a compliant variant",
        art.stats.compliance_rate * 100.0
    );
    if !art.stats.sample.is_empty() {
        println!("  preview:       {}", art.stats.sample.join(", "));
    }
    println!("  attack size (assumed {} H/s):", hashrate);
    println!(
        "    dict+rules: {} candidates (~{})",
        art.stats.dict_keyspace,
        format_duration(estimate_seconds(art.stats.dict_keyspace, hashrate))
    );
    println!(
        "    masks:      {} candidates (~{})",
        art.stats.mask_keyspace,
        format_duration(estimate_seconds(art.stats.mask_keyspace, hashrate))
    );
    println!("  commands:      {}", art.commands_file.display());
}

fn write_lines(path: &Path, lines: &[String]) -> Result<()> {
    let mut f = fs::File::create(path)
        .with_context(|| format!("creating {}", path.display()))?;
    for l in lines {
        writeln!(f, "{l}").with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ClassMins, PasswordPolicy};

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_len: 8,
            max_len: 12,
            require: ClassMins { lower: 1, upper: 1, digit: 1, special: 1 },
            special_set: "!@#$".to_string(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![],
        }
    }

    #[test]
    fn produces_all_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = RunConfig {
            policy: policy(),
            input: InputSource::Seeds(crate::genwl::SeedInput {
                tokens: vec!["acme".to_string(), "verano".to_string()],
                years: vec![2024],
                max_size: 1000,
            }),
            out_dir: dir.path().to_path_buf(),
            hash_mode: Some("1000".to_string()),
            hashes_path: "hashes.txt".to_string(),
            rule_budget: 200,
            mask_budget_per: 1_000_000_000_000_000,
            len_span: 3,
            years: vec![2024],
        };
        let art = run_pipeline(&cfg).unwrap();

        assert!(art.rule_file.exists());
        assert!(art.mask_file.exists());
        assert!(art.wordlist_file.exists());
        assert!(art.commands_file.exists());
        assert!(art.policy_file.exists());
        assert!(art.stats.rule_count > 0);
        assert!(art.stats.mask_count > 0);
        assert_eq!(art.stats.dict_keyspace, (art.stats.kept_count as u64) * (art.stats.rule_count as u64));
        assert!(art.stats.mask_keyspace > 0);

        // Every emitted mask must guarantee compliance.
        let masks = std::fs::read_to_string(&art.mask_file).unwrap();
        for line in masks.lines().filter(|l| !l.is_empty()) {
            let (custom, mask) = match line.split_once(',') {
                Some((c, m)) => (Some(c), m),
                None => (None, line),
            };
            assert!(crate::maskgen::mask_guarantees_compliance(custom, mask, &policy()));
        }

        // commands.txt mentions both attack modes.
        let cmds = std::fs::read_to_string(&art.commands_file).unwrap();
        assert!(cmds.contains("-a 0"));
        assert!(cmds.contains("-a 3"));

        // Honest-preview compliance rate is computed and positive for this fixture.
        assert!(art.stats.compliance_rate > 0.0);
    }

    #[test]
    fn wordlist_input_is_pruned_streaming_to_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let wl = dir.path().join("base.txt");
        let mut f = std::fs::File::create(&wl).unwrap();
        // The 16-char line exceeds max_len 12 (only-impossible case here, since the
        // pipeline `policy()` fixture has empty forbidden_chars).
        writeln!(f, "cat\nhola mundo\nverano\nabcdefghijklmnop").unwrap();
        drop(f);
        let cfg = RunConfig {
            policy: policy(),                      // module fixture: min8 max12, require all 1, forbidden empty
            input: InputSource::Wordlist(wl),
            out_dir: dir.path().join("out"),
            hash_mode: Some("0".into()), hashes_path: "h".into(),
            rule_budget: 100, mask_budget_per: 1_000_000_000_000_000, len_span: 3, years: vec![2024],
        };
        let art = run_pipeline(&cfg).unwrap();
        assert_eq!(art.stats.input_count, 4);
        assert_eq!(art.stats.kept_count, 3);       // only the 16-char line is impossible (> max_len 12)
        let pruned = std::fs::read_to_string(&art.wordlist_file).unwrap();
        assert_eq!(pruned, "cat\nhola mundo\nverano\n");
        assert!(art.wordlist_file.file_name().unwrap() == "pruned.txt");
    }
}
