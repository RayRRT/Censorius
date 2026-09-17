//! Directed hashcat rule generation. Emits a compact, ordered repertoire of
//! rules that push base words toward policy compliance.

use crate::policy::PasswordPolicy;

pub struct RuleGenOpts {
    pub years: Vec<u16>,
    pub budget: usize,
}

/// Turn a year like 2024 into an append sequence "$2 $0 $2 $4".
fn year_append(year: u16) -> String {
    year.to_string()
        .chars()
        .map(|c| format!("${c}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn generate_rules(p: &PasswordPolicy, opts: &RuleGenOpts) -> Vec<String> {
    // Case transforms (ordered by real-world frequency).
    let cases = ["c", ":", "u", "C", "t"];

    // Digit appends: single digits plus each year as a group.
    let mut digit_tails: Vec<String> = Vec::new();
    for y in &opts.years {
        digit_tails.push(year_append(*y));
    }
    for d in 0..=9 {
        digit_tails.push(format!("${d}"));
    }

    // Special appends: one per allowed special char.
    let specials: Vec<String> = p.special_set.chars().map(|s| format!("${s}")).collect();

    // Leetspeak substitutions (common ones intersected with reality).
    let leet = ["sa@", "se3", "si1", "so0", "ss$"];

    let mut out: Vec<String> = Vec::new();
    let push = |parts: &[&str], out: &mut Vec<String>| {
        let line = parts
            .iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if !line.is_empty() {
            out.push(line);
        }
    };

    // 1) Case + digit-tail + special (the workhorse for U/D/S policies).
    for case in cases {
        for dt in &digit_tails {
            if specials.is_empty() {
                push(&[case, dt.as_str()], &mut out);
            } else {
                for sp in &specials {
                    push(&[case, dt.as_str(), sp.as_str()], &mut out);
                }
            }
        }
    }

    // 2) Case only, and case + single special (lighter variants).
    for case in cases {
        push(&[case], &mut out);
        for sp in &specials {
            push(&[case, sp.as_str()], &mut out);
        }
    }

    // 3) Leetspeak, alone and combined with capitalize.
    for l in leet {
        push(&[l], &mut out);
        push(&["c", l], &mut out);
    }

    // Dedup preserving order, then truncate to budget.
    let mut seen = std::collections::HashSet::new();
    out.retain(|r| seen.insert(r.clone()));
    out.truncate(opts.budget);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ClassMins, PasswordPolicy};
    use crate::ruleengine::{apply, complies};

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_len: 8,
            max_len: 20,
            require: ClassMins { lower: 1, upper: 1, digit: 1, special: 1 },
            special_set: "!@#$".to_string(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![],
        }
    }

    #[test]
    fn respects_budget_and_dedupes() {
        let opts = RuleGenOpts { years: vec![2024], budget: 50 };
        let rules = generate_rules(&policy(), &opts);
        assert!(!rules.is_empty());
        assert!(rules.len() <= 50);
        let mut sorted = rules.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), rules.len(), "rules must be unique");
    }

    #[test]
    fn capitalize_precedes_noop_block() {
        let opts = RuleGenOpts { years: vec![2024], budget: 1000 };
        let rules = generate_rules(&policy(), &opts);
        let c = rules.iter().position(|r| r.starts_with('c')).unwrap();
        let noop = rules.iter().position(|r| r.starts_with(':')).unwrap();
        assert!(c < noop);
    }

    #[test]
    fn some_rule_makes_a_plain_base_comply() {
        let opts = RuleGenOpts { years: vec![2024], budget: 500 };
        let rules = generate_rules(&policy(), &opts);
        let base = "verano";
        let ok = rules.iter().any(|r| {
            apply(base, r).map(|w| complies(&w, &policy())).unwrap_or(false)
        });
        assert!(ok, "at least one generated rule should make '{base}' comply");
    }
}
