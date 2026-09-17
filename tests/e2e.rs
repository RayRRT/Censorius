use censorius::genwl::SeedInput;
use censorius::pipeline::{run_pipeline, InputSource, RunConfig};
use censorius::policy::{ClassMins, PasswordPolicy};
use censorius::ruleengine::complies;

#[test]
fn seeds_to_artifacts_end_to_end() {
    let policy = PasswordPolicy {
        min_len: 8,
        max_len: 12,
        require: ClassMins { lower: 1, upper: 1, digit: 1, special: 1 },
        special_set: "!@#$".to_string(),
        forbidden_chars: String::new(),
        min_classes: None,
        constraints: vec![],
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = RunConfig {
        policy: policy.clone(),
        input: InputSource::Seeds(SeedInput {
            tokens: vec!["acme".into(), "verano".into()],
            years: vec![2024, 2025],
            max_size: 10_000,
        }),
        out_dir: dir.path().to_path_buf(),
        hash_mode: Some("1000".into()),
        hashes_path: "hashes.txt".into(),
        rule_budget: 500,
        mask_budget_per: 1_000_000_000_000_000,
        len_span: 3,
        years: vec![2024, 2025],
    };

    let art = run_pipeline(&cfg).unwrap();

    // Artifacts exist and are non-trivial.
    assert!(art.stats.rule_count > 0);
    assert!(art.stats.mask_count > 0);
    assert!(art.stats.kept_count > 0);

    // Central invariant, checked end-to-end: at least one (word, rule) pair
    // among the generated artifacts yields a compliant candidate.
    let words = std::fs::read_to_string(&art.wordlist_file).unwrap();
    let rules = std::fs::read_to_string(&art.rule_file).unwrap();
    let any_compliant = words.lines().take(50).any(|w| {
        rules.lines().any(|r| {
            censorius::ruleengine::apply(w, r)
                .map(|out| complies(&out, &policy))
                .unwrap_or(false)
        })
    });
    assert!(any_compliant, "expected at least one compliant (word,rule) result");
}

#[test]
fn run_config_from_ad_default_profile_yields_masks() {
    // Ties Task 1 (M-of-N masks) and Task 2 (profile loading) together:
    // the ad-default profile is min_classes=3 with zero per-class floors, which
    // previously produced ZERO masks. It must now produce masks end to end.
    let args = censorius::cli::RunArgs {
        profile: Some("ad-default".to_string()),
        policy: None,
        wordlist: None,
        seeds: Some("acme,verano".to_string()),
        years: "2024,2025".to_string(),
        out: tempfile::tempdir().unwrap().keep(),
        hashes: "hashes.txt".to_string(),
        mode: Some("1000".to_string()),
        mask_budget: 100_000_000_000,
        hashrate: 1_000_000_000,
    };
    let cfg = censorius::cli::build_run_config(&args).unwrap();
    cfg.policy.validate().unwrap();
    let art = censorius::pipeline::run_pipeline(&cfg).unwrap();
    assert!(art.stats.mask_count > 0, "ad-default must now yield masks");
    assert!(art.stats.rule_count > 0);
}

#[test]
fn large_mask_budget_enables_masks_for_long_policy() {
    use censorius::policy::{ClassMins, PasswordPolicy};
    use censorius::pipeline::{run_pipeline, InputSource, RunConfig};
    use censorius::genwl::SeedInput;
    let policy = PasswordPolicy { min_len:10, max_len:12,
        require: ClassMins{lower:1,upper:1,digit:1,special:1}, special_set:"!@#$%".into(),
        forbidden_chars:String::new(), min_classes:None, constraints:vec![] };
    let mk = |budget: u64| RunConfig { policy: policy.clone(),
        input: InputSource::Seeds(SeedInput{tokens:vec!["acme".into()],years:vec![2024],max_size:1000}),
        out_dir: tempfile::tempdir().unwrap().keep(), hash_mode:None, hashes_path:"h".into(),
        rule_budget:100, mask_budget_per:budget, len_span:3, years:vec![2024] };
    assert_eq!(run_pipeline(&mk(100_000_000_000)).unwrap().stats.mask_count, 0);
    assert!(run_pipeline(&mk(1_000_000_000_000_000_000)).unwrap().stats.mask_count > 0);
}

#[test]
fn analyze_writes_frequency_ranked_artifacts() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let cracked = dir.path().join("cracked.txt");
    let mut f = std::fs::File::create(&cracked).unwrap();
    // 3 of the ?u?l..?d shape ending in 2024, 1 outlier
    writeln!(f, "Verano2024\nMadrid2024\nOtono2024\nx").unwrap();
    drop(f);
    let out = tempfile::tempdir().unwrap().keep();
    let args = censorius::cli::AnalyzeArgs {
        input: cracked, top: 20, policy: None, out: out.clone(),
    };
    censorius::cli::run_analyze(&args).unwrap();
    let masks = std::fs::read_to_string(out.join("analysis-masks.hcmask")).unwrap();
    // most frequent mask (the ?u?l...?d?d?d?d shape) is the first line
    assert_eq!(masks.lines().next().unwrap(), "?u?l?l?l?l?l?d?d?d?d");
    let rules = std::fs::read_to_string(out.join("analysis.rule")).unwrap();
    assert!(rules.lines().any(|l| l == "$2 $0 $2 $4"));
    assert!(out.join("analysis-report.txt").exists());
}
