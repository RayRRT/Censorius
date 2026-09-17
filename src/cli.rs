//! Command-line interface. Authorized pentesting use only.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::genwl::SeedInput;
use crate::pipeline::{run_pipeline, InputSource, RunConfig};
use crate::policy::PasswordPolicy;

#[derive(Parser, Debug)]
#[command(name = "censorius", about = "Policy-driven hashcat artifact generator (authorized pentesting only).")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the interactive wizard (default).
    Wizard,
    /// Manage built-in policy profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Generate artifacts non-interactively from a profile or policy file.
    Run(RunArgs),
    /// Analyze already-cracked passwords into target-tailored masks/rules/stats.
    Analyze(AnalyzeArgs),
    /// Measure your hardware's hash rate for a mode by running `hashcat -b` (runs hashcat).
    Bench(BenchArgs),
}

#[derive(Subcommand, Debug)]
pub enum ProfileAction {
    /// List built-in profiles.
    List,
    /// Show a built-in profile as TOML.
    Show { name: String },
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Embedded profile name (e.g. ad-default). Use this OR --policy.
    #[arg(long)]
    pub profile: Option<String>,
    /// Path to a policy TOML file. Use this OR --profile.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Base wordlist file. Use this OR --seeds.
    #[arg(long)]
    pub wordlist: Option<PathBuf>,
    /// Seed tokens, comma-separated. Use this OR --wordlist.
    #[arg(long)]
    pub seeds: Option<String>,
    /// Relevant years, comma-separated.
    #[arg(long, default_value = "2024,2025")]
    pub years: String,
    /// Output directory.
    #[arg(long, default_value = "censorius-out")]
    pub out: PathBuf,
    /// Hashes file path (placeholder in the generated command).
    #[arg(long, default_value = "hashes.txt")]
    pub hashes: String,
    /// hashcat -m mode (optional).
    #[arg(long)]
    pub mode: Option<String>,
    /// Max keyspace (candidate count) allowed per generated mask. Raise for longer policies.
    #[arg(long, default_value_t = 100_000_000_000)]
    pub mask_budget: u64,
    /// Assumed hash rate (H/s) for the time estimate in the summary. Get yours from `hashcat -b`.
    #[arg(long, default_value_t = 1_000_000_000)]
    pub hashrate: u64,
}

#[derive(clap::Args, Debug)]
pub struct AnalyzeArgs {
    /// File of already-cracked plaintext passwords (one per line).
    pub input: PathBuf,
    /// How many top masks/rules to emit.
    #[arg(long, default_value_t = 20)]
    pub top: usize,
    /// Optional policy TOML to filter masks to those consistent with it.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Output directory.
    #[arg(long, default_value = "censorius-analysis")]
    pub out: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct BenchArgs {
    /// hashcat -m hash mode to benchmark (e.g. 0 = MD5, 1000 = NTLM, 3200 = bcrypt).
    #[arg(long)]
    pub mode: String,
    /// Path to the hashcat binary (default: `hashcat`, i.e. on PATH).
    #[arg(long, default_value = "hashcat")]
    pub hashcat: String,
}

pub fn run_analyze(args: &AnalyzeArgs) -> anyhow::Result<()> {
    let words = crate::wordlist::read_words(&args.input)?;
    let a = crate::analyze::analyze(&words);
    let policy = match &args.policy {
        Some(p) => {
            let s = std::fs::read_to_string(p).with_context(|| format!("reading policy {}", p.display()))?;
            Some(PasswordPolicy::from_toml(&s).map_err(|e| anyhow::anyhow!("parsing policy: {e}"))?)
        }
        None => None,
    };
    let masks = crate::analyze::select_masks(&a, args.top, policy.as_ref());
    let rules = crate::analyze::derive_rules(&words, args.top);

    std::fs::create_dir_all(&args.out).with_context(|| format!("creating {}", args.out.display()))?;
    let write = |name: &str, lines: &[String]| -> anyhow::Result<()> {
        let path = args.out.join(name);
        let mut f = std::fs::File::create(&path).with_context(|| format!("writing {}", path.display()))?;
        for l in lines { writeln!(f, "{l}")?; }
        Ok(())
    };
    write("analysis-masks.hcmask", &masks)?;
    write("analysis.rule", &rules)?;

    // Report
    let mut rep = String::new();
    rep.push_str(&format!("Censorius analysis — {} passwords\n\n", a.total));
    rep.push_str("Top lengths:\n");
    let mut lens: Vec<(&usize,&usize)> = a.length_hist.iter().collect();
    lens.sort_by(|x,y| y.1.cmp(x.1));
    for (len, c) in lens.iter().take(10) {
        rep.push_str(&format!("  len {:>2}: {} ({:.0}%)\n", len, c, 100.0 * **c as f64 / a.total.max(1) as f64));
    }
    let pct = |n: usize| 100.0 * n as f64 / a.total.max(1) as f64;
    rep.push_str(&format!("\nClass prevalence: lower {:.0}%  upper {:.0}%  digit {:.0}%  special {:.0}%\n",
        pct(a.prevalence.lower), pct(a.prevalence.upper), pct(a.prevalence.digit), pct(a.prevalence.special)));
    rep.push_str(&format!("\nTop {} masks (by frequency):\n", args.top));
    for (m, c) in a.mask_freq.iter().take(args.top) {
        rep.push_str(&format!("  {:<28} {} ({:.0}%)\n", m, c, pct(*c)));
    }
    std::fs::write(args.out.join("analysis-report.txt"), &rep)
        .with_context(|| "writing analysis-report.txt")?;

    print!("{rep}");
    println!("\nWrote: analysis-masks.hcmask ({} masks), analysis.rule ({} rules), analysis-report.txt in {}",
        masks.len(), rules.len(), args.out.display());
    Ok(())
}

const AD_DEFAULT: &str = include_str!("../templates/ad-default.toml");

/// Resolve an embedded profile name to its TOML text.
pub fn profile_toml(name: &str) -> anyhow::Result<&'static str> {
    match name {
        "ad-default" => Ok(AD_DEFAULT),
        other => anyhow::bail!("unknown profile: {other}"),
    }
}

pub fn build_run_config(args: &RunArgs) -> anyhow::Result<RunConfig> {
    let policy = match (&args.profile, &args.policy) {
        (Some(name), None) => PasswordPolicy::from_toml(profile_toml(name)?)
            .map_err(|e| anyhow::anyhow!("parsing profile {name}: {e}"))?,
        (None, Some(path)) => {
            let s = std::fs::read_to_string(path)
                .with_context(|| format!("reading policy {}", path.display()))?;
            PasswordPolicy::from_toml(&s).map_err(|e| anyhow::anyhow!("parsing policy: {e}"))?
        }
        _ => anyhow::bail!("provide exactly one of --profile or --policy"),
    };
    let years: Vec<u16> = args
        .years
        .split(',')
        .filter_map(|s| s.trim().parse::<u16>().ok())
        .collect();
    let input = match (&args.wordlist, &args.seeds) {
        (Some(p), None) => InputSource::Wordlist(p.clone()),
        (None, Some(csv)) => {
            let tokens = csv
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            InputSource::Seeds(SeedInput {
                tokens,
                years: years.clone(),
                max_size: 100_000,
            })
        }
        _ => anyhow::bail!("provide exactly one of --wordlist or --seeds"),
    };
    Ok(RunConfig {
        policy,
        input,
        out_dir: args.out.clone(),
        hash_mode: args.mode.clone(),
        hashes_path: args.hashes.clone(),
        rule_budget: 500,
        mask_budget_per: args.mask_budget,
        len_span: 3,
        years,
    })
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None | Some(Command::Wizard) => crate::wizard::run_wizard(),
        Some(Command::Profile { action }) => match action {
            ProfileAction::List => {
                println!("ad-default");
                Ok(())
            }
            ProfileAction::Show { name } => {
                println!("{}", profile_toml(&name)?);
                Ok(())
            }
        },
        Some(Command::Run(args)) => {
            let cfg = build_run_config(&args)?;
            cfg.policy.validate()?;
            let art = run_pipeline(&cfg)?;
            crate::pipeline::print_summary(&art, args.hashrate);
            Ok(())
        }
        Some(Command::Analyze(args)) => run_analyze(&args),
        Some(Command::Bench(args)) => {
            eprintln!("Benchmarking mode {} with '{}' (this runs hashcat and can take a minute)...", args.mode, args.hashcat);
            let hs = crate::bench::run_bench(&args.hashcat, &args.mode)?;
            let ghs = hs as f64 / 1e9;
            println!("mode {}: {} H/s (~{:.2} GH/s)", args.mode, hs, ghs);
            println!("use it with:  censorius run ... --hashrate {hs}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_profile_show() {
        let cli = Cli::parse_from(["censorius", "profile", "show", "ad-default"]);
        match cli.command {
            Some(Command::Profile { action: ProfileAction::Show { name } }) => {
                assert_eq!(name, "ad-default");
            }
            _ => panic!("expected profile show"),
        }
    }

    #[test]
    fn defaults_to_wizard_when_no_subcommand() {
        let cli = Cli::parse_from(["censorius"]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_run_with_profile_and_seeds() {
        let cli = Cli::parse_from([
            "censorius", "run", "--profile", "ad-default",
            "--seeds", "acme,verano", "--out", "out",
        ]);
        match cli.command {
            Some(Command::Run(args)) => {
                assert_eq!(args.profile.as_deref(), Some("ad-default"));
                assert_eq!(args.seeds.as_deref(), Some("acme,verano"));
            }
            _ => panic!("expected run"),
        }
    }

    #[test]
    fn build_run_config_from_profile_seeds() {
        let args = RunArgs {
            profile: Some("ad-default".to_string()),
            policy: None,
            wordlist: None,
            seeds: Some("acme,verano".to_string()),
            years: "2024,2025".to_string(),
            out: std::path::PathBuf::from("out"),
            hashes: "hashes.txt".to_string(),
            mode: Some("1000".to_string()),
            mask_budget: 100_000_000_000,
            hashrate: 1_000_000_000,
        };
        let cfg = build_run_config(&args).unwrap();
        assert_eq!(cfg.policy.min_classes, Some(3)); // from ad-default
        assert!(matches!(cfg.input, crate::pipeline::InputSource::Seeds(_)));
    }

    #[test]
    fn build_run_config_rejects_both_policy_sources() {
        let args = RunArgs {
            profile: Some("ad-default".to_string()),
            policy: Some(std::path::PathBuf::from("x.toml")),
            wordlist: None,
            seeds: Some("a".to_string()),
            years: "2024".to_string(),
            out: std::path::PathBuf::from("o"),
            hashes: "h".to_string(),
            mode: None,
            mask_budget: 100_000_000_000,
            hashrate: 1_000_000_000,
        };
        assert!(build_run_config(&args).is_err());
    }

    #[test]
    fn build_run_config_rejects_no_input() {
        let args = RunArgs {
            profile: Some("ad-default".to_string()),
            policy: None,
            wordlist: None,
            seeds: None,
            years: "2024".to_string(),
            out: std::path::PathBuf::from("o"),
            hashes: "h".to_string(),
            mode: None,
            mask_budget: 100_000_000_000,
            hashrate: 1_000_000_000,
        };
        assert!(build_run_config(&args).is_err());
    }

    #[test]
    fn parses_analyze() {
        let cli = Cli::parse_from(["censorius","analyze","cracked.txt","--top","10","--out","o"]);
        match cli.command {
            Some(Command::Analyze(a)) => { assert_eq!(a.top, 10); assert_eq!(a.input, std::path::PathBuf::from("cracked.txt")); }
            _ => panic!("expected analyze"),
        }
    }

    #[test]
    fn run_accepts_hashrate() {
        let cli = Cli::parse_from(["censorius","run","--profile","ad-default","--seeds","a","--hashrate","5000000000","--out","o"]);
        match cli.command { Some(Command::Run(a)) => assert_eq!(a.hashrate, 5_000_000_000), _ => panic!() }
    }

    #[test]
    fn run_accepts_mask_budget_flag() {
        let cli = Cli::parse_from(["censorius","run","--profile","ad-default","--seeds","acme","--mask-budget","5000000000000","--out","o"]);
        match cli.command { Some(Command::Run(a)) => assert_eq!(a.mask_budget, 5_000_000_000_000), _ => panic!() }
    }

    #[test]
    fn build_run_config_uses_mask_budget() {
        let a = RunArgs { profile: Some("ad-default".into()), policy: None, wordlist: None, seeds: Some("acme".into()),
            years: "2024".into(), out: std::path::PathBuf::from("o"), hashes: "h".into(), mode: None, mask_budget: 7_000_000_000_000,
            hashrate: 1_000_000_000 };
        assert_eq!(build_run_config(&a).unwrap().mask_budget_per, 7_000_000_000_000);
    }

    #[test]
    fn parses_bench() {
        let cli = Cli::parse_from(["censorius","bench","--mode","1000","--hashcat","/opt/hashcat/hashcat.bin"]);
        match cli.command {
            Some(Command::Bench(a)) => { assert_eq!(a.mode, "1000"); assert_eq!(a.hashcat, "/opt/hashcat/hashcat.bin"); }
            _ => panic!("expected bench"),
        }
    }

    #[test]
    fn bench_hashcat_defaults_to_path_name() {
        let cli = Cli::parse_from(["censorius","bench","--mode","0"]);
        match cli.command {
            Some(Command::Bench(a)) => assert_eq!(a.hashcat, "hashcat"),
            _ => panic!("expected bench"),
        }
    }
}
