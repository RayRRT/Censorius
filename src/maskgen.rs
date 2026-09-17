//! Policy-compliant hashcat mask generation. Every emitted mask is guaranteed
//! (by construction and by `mask_guarantees_compliance`) to yield candidates
//! that satisfy the policy.

use crate::policy::{Constraint, PasswordPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskLine {
    pub custom1: Option<String>,
    pub mask: String,
}

#[derive(Debug, Clone, Copy)]
pub struct MaskGenOpts {
    pub budget_per_mask: u64,
    pub len_span: u8,
    pub filler: char, // 'l' (lowercase, small keyspace) or 'a' (all)
}

/// Iterate mask tokens: "?l", "?u", "?d", "?s", "?a", "?1", or a literal char.
fn tokens(mask: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = mask.chars().peekable();
    while let Some(c) = it.next() {
        if c == '?' {
            if let Some(k) = it.next() {
                out.push(format!("?{k}"));
            }
        } else {
            out.push(c.to_string());
        }
    }
    out
}

fn charset_size(tok: &str, custom1: Option<&str>) -> u64 {
    match tok {
        "?l" | "?u" => 26,
        "?d" => 10,
        "?s" => 33,
        "?a" => 95,
        "?1" => custom1.map(|c| c.chars().count() as u64).unwrap_or(0),
        lit => lit.chars().count() as u64, // literal: exactly 1
    }
}

pub fn keyspace(custom1: Option<&str>, mask: &str) -> u64 {
    tokens(mask)
        .iter()
        .map(|t| charset_size(t, custom1))
        .fold(1u64, |acc, sz| acc.saturating_mul(sz))
}

/// The 33 characters hashcat's `?s` charset covers.
const SPECIAL_CHARSET: &str = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// Whether a mask token's charset can ever produce the character `ch`.
fn token_can_produce(tok: &str, ch: char, custom1: Option<&str>) -> bool {
    match tok {
        "?l" => ch.is_ascii_lowercase(),
        "?u" => ch.is_ascii_uppercase(),
        "?d" => ch.is_ascii_digit(),
        "?s" => SPECIAL_CHARSET.contains(ch),
        "?a" => {
            ch.is_ascii_lowercase()
                || ch.is_ascii_uppercase()
                || ch.is_ascii_digit()
                || SPECIAL_CHARSET.contains(ch)
        }
        "?1" => custom1.map(|c| c.contains(ch)).unwrap_or(false),
        lit => lit.chars().next() == Some(ch),
    }
}

/// Whether a mask token's charset is guaranteed to exclude ASCII digits
/// entirely. Used to certify `NotStartWithDigit` / `NotEndWithDigit`: `?d`
/// and `?a` can always produce a digit so they never qualify; `?1` qualifies
/// only if the actual custom charset contains no digit.
fn token_excludes_digits(tok: &str, custom1: Option<&str>) -> bool {
    match tok {
        "?d" | "?a" => false,
        "?1" => custom1
            .map(|c| !c.chars().any(|ch| ch.is_ascii_digit()))
            .unwrap_or(true),
        "?l" | "?u" | "?s" => true,
        lit => lit.chars().next().map(|c| !c.is_ascii_digit()).unwrap_or(true),
    }
}

/// Which single class a token GUARANTEES (None = guarantees nothing specific).
fn guaranteed_class(tok: &str, custom1: Option<&str>, special_set: &str) -> Option<&'static str> {
    match tok {
        "?l" => Some("lower"),
        "?u" => Some("upper"),
        "?d" => Some("digit"),
        "?1" if custom1.is_some() => Some("special"),
        "?s" | "?a" => None,
        lit => {
            let ch = lit.chars().next().unwrap();
            if special_set.contains(ch) {
                Some("special")
            } else if ch.is_ascii_digit() {
                Some("digit")
            } else if ch.is_ascii_uppercase() {
                Some("upper")
            } else if ch.is_ascii_lowercase() {
                Some("lower")
            } else {
                None
            }
        }
    }
}

pub fn mask_guarantees_compliance(custom1: Option<&str>, mask: &str, p: &PasswordPolicy) -> bool {
    let toks = tokens(mask);
    let len = toks.len();
    if len < p.min_len as usize || len > p.max_len as usize {
        return false;
    }
    if !p.forbidden_chars.is_empty()
        && toks.iter().any(|t| {
            p.forbidden_chars
                .chars()
                .any(|fc| token_can_produce(t, fc, custom1))
        })
    {
        return false;
    }
    for con in &p.constraints {
        match con {
            Constraint::NotStartWithDigit => {
                if let Some(first) = toks.first() {
                    if !token_excludes_digits(first, custom1) {
                        return false;
                    }
                }
            }
            Constraint::NotEndWithDigit => {
                if let Some(last) = toks.last() {
                    if !token_excludes_digits(last, custom1) {
                        return false;
                    }
                }
            }
        }
    }
    let (mut lower, mut upper, mut digit, mut special) = (0u32, 0u32, 0u32, 0u32);
    for t in &toks {
        match guaranteed_class(t, custom1, &p.special_set) {
            Some("lower") => lower += 1,
            Some("upper") => upper += 1,
            Some("digit") => digit += 1,
            Some("special") => special += 1,
            _ => {}
        }
    }
    if lower < p.require.lower as u32
        || upper < p.require.upper as u32
        || digit < p.require.digit as u32
        || special < p.require.special as u32
    {
        return false;
    }
    if let Some(m) = p.min_classes {
        let present = [lower > 0, upper > 0, digit > 0, special > 0]
            .iter()
            .filter(|b| **b)
            .count();
        if (present as u8) < m {
            return false;
        }
    }
    true
}

/// k-combinations of `items` (small inputs: at most 4 classes). k==0 yields
/// one empty combination, preserving the "floors only" path.
fn combinations<'a>(items: &[&'a str], k: usize) -> Vec<Vec<&'a str>> {
    if k == 0 {
        return vec![Vec::new()];
    }
    if k > items.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let head = items[i];
        for mut tail in combinations(&items[i + 1..], k - 1) {
            let mut combo = vec![head];
            combo.append(&mut tail);
            out.push(combo);
        }
    }
    out
}

/// Every certifier-passing mask (ignoring the budget) with its keyspace.
/// `MaskLine.custom1` is `Some(special_set)` iff the mask contains `?1`,
/// else `None` — `keyspace` is still computed against the true custom1 so
/// `?1` sizing is correct regardless of what gets emitted.
fn candidate_masks(p: &PasswordPolicy, opts: &MaskGenOpts) -> Vec<(MaskLine, u64)> {
    let custom1 = if p.special_set.is_empty() {
        None
    } else {
        Some(p.special_set.clone())
    };
    let filler_tok = format!("?{}", opts.filler);
    let max_l = (p.min_len as u16 + opts.len_span as u16).min(p.max_len as u16);
    let target_distinct = p.min_classes.unwrap_or(0) as usize;

    // Required tokens from explicit per-class floors, in a stable order.
    let forced: Vec<(&str, u8)> = [
        ("?u", p.require.upper),
        ("?d", p.require.digit),
        ("?1", p.require.special),
        ("?l", p.require.lower),
    ]
    .into_iter()
    .filter(|(_, n)| *n > 0)
    .collect();
    let forced_classes: Vec<&str> = forced.iter().map(|(t, _)| *t).collect();

    // Classes we can additionally guarantee (only ?1 if a custom set exists).
    let mut available: Vec<&str> = vec!["?u", "?d", "?l"];
    if custom1.is_some() {
        available.push("?1");
    }
    let addable: Vec<&str> = available
        .into_iter()
        .filter(|c| !forced_classes.contains(c))
        .collect();
    let need_extra = target_distinct.saturating_sub(forced_classes.len());

    let mut out: Vec<(MaskLine, u64)> = Vec::new();
    for l in (p.min_len as u16)..=max_l {
        let l = l as usize;
        for combo in combinations(&addable, need_extra) {
            let mut req: Vec<&str> = Vec::new();
            for (t, n) in &forced {
                for _ in 0..*n {
                    req.push(t);
                }
            }
            for c in &combo {
                req.push(c);
            }
            if req.len() > l {
                continue;
            }
            let fill_count = l - req.len();
            let fill: Vec<&str> = std::iter::repeat(filler_tok.as_str())
                .take(fill_count)
                .collect();
            let front: String = req.iter().chain(fill.iter()).copied().collect();
            let back: String = fill.iter().chain(req.iter()).copied().collect();
            for mask in [front, back] {
                if mask_guarantees_compliance(custom1.as_deref(), &mask, p)
                    && !out.iter().any(|(m, _)| m.mask == mask)
                {
                    let ks = keyspace(custom1.as_deref(), &mask);
                    out.push((
                        MaskLine {
                            custom1: if mask.contains("?1") { custom1.clone() } else { None },
                            mask,
                        },
                        ks,
                    ));
                }
            }
        }
    }
    out
}

pub fn generate_masks(p: &PasswordPolicy, opts: &MaskGenOpts) -> Vec<MaskLine> {
    candidate_masks(p, opts)
        .into_iter()
        .filter(|(_, ks)| *ks <= opts.budget_per_mask)
        .map(|(m, _)| m)
        .collect()
}

pub fn min_compliant_keyspace(p: &PasswordPolicy, opts: &MaskGenOpts) -> Option<u64> {
    candidate_masks(p, opts).into_iter().map(|(_, ks)| ks).min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ClassMins, Constraint, PasswordPolicy};

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_len: 8,
            max_len: 10,
            require: ClassMins { lower: 1, upper: 1, digit: 1, special: 1 },
            special_set: "!@#$".to_string(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![],
        }
    }

    #[test]
    fn keyspace_multiplies_charset_sizes() {
        // ?u?d = 26 * 10
        assert_eq!(keyspace(None, "?u?d"), 260);
        // custom ?1 of size 4, plus ?l
        assert_eq!(keyspace(Some("!@#$"), "?1?l"), 4 * 26);
    }

    #[test]
    fn guarantees_compliance_true_for_covering_mask() {
        // 8 long: one upper, one digit, one special(?1), five lower.
        assert!(mask_guarantees_compliance(Some("!@#$"), "?u?d?1?l?l?l?l?l", &policy()));
    }

    #[test]
    fn guarantees_compliance_false_when_short() {
        assert!(!mask_guarantees_compliance(Some("!@#$"), "?u?d?1?l?l", &policy())); // len 5 < 8
    }

    #[test]
    fn guarantees_compliance_false_when_missing_class() {
        // no ?1 => special not guaranteed
        assert!(!mask_guarantees_compliance(Some("!@#$"), "?u?d?l?l?l?l?l?l", &policy()));
    }

    #[test]
    fn every_generated_mask_is_compliant_and_within_budget() {
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000, len_span: 2, filler: 'l' };
        let masks = generate_masks(&policy(), &opts);
        assert!(!masks.is_empty());
        for m in &masks {
            assert!(mask_guarantees_compliance(m.custom1.as_deref(), &m.mask, &policy()));
            assert!(keyspace(m.custom1.as_deref(), &m.mask) <= opts.budget_per_mask);
        }
    }

    // --- Fix round 1 regression tests ---

    #[test]
    fn forbidden_chars_reject_digit_token() {
        let mut p = policy();
        p.forbidden_chars = "0".to_string();
        // ?d can produce '0', so this mask can no longer be certified.
        assert!(!mask_guarantees_compliance(Some("!@#$"), "?u?d?1?l?l?l?l?l", &p));
    }

    #[test]
    fn forbidden_chars_reject_lower_token() {
        let mut p = policy();
        p.forbidden_chars = "e".to_string();
        // ?l can produce 'e', so this mask can no longer be certified.
        assert!(!mask_guarantees_compliance(Some("!@#$"), "?u?d?1?l?l?l?l?l", &p));
    }

    #[test]
    fn generate_masks_excludes_front_loaded_when_not_start_with_digit() {
        // No upper required, so the front-loaded arrangement would normally
        // start with the required "?d" token — that must now be rejected.
        let p = PasswordPolicy {
            min_len: 8,
            max_len: 8,
            require: ClassMins { lower: 1, upper: 0, digit: 1, special: 0 },
            special_set: String::new(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![Constraint::NotStartWithDigit],
        };
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000, len_span: 0, filler: 'l' };
        let masks = generate_masks(&p, &opts);
        assert!(!masks.is_empty());
        for m in &masks {
            assert!(
                !m.mask.starts_with("?d"),
                "front-loaded digit-first mask must be excluded: {}",
                m.mask
            );
        }
    }

    #[test]
    fn generate_masks_never_violates_forbidden_chars() {
        let mut p = policy();
        // A digit is required by the policy, so every candidate mask must
        // contain "?d" — which can always produce the forbidden '0'. No
        // mask can be certified, so none should be generated.
        p.forbidden_chars = "0".to_string();
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000, len_span: 2, filler: 'l' };
        let masks = generate_masks(&p, &opts);
        assert!(
            masks.is_empty(),
            "no mask can avoid producing a forbidden '0' while satisfying a required digit"
        );
    }

    #[test]
    fn keyspace_saturates_on_overflow() {
        let mask: String = std::iter::repeat("?a").take(20).collect();
        assert_eq!(keyspace(None, &mask), u64::MAX);
    }

    #[test]
    fn generate_masks_excludes_overflowing_keyspace() {
        let p = PasswordPolicy {
            min_len: 100,
            max_len: 110,
            require: ClassMins::default(),
            special_set: String::new(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![],
        };
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000, len_span: 5, filler: 'a' };
        let masks = generate_masks(&p, &opts);
        assert!(
            masks.is_empty(),
            "keyspace at length >= 100 with ?a saturates past any reasonable budget"
        );
    }

    // --- Task 1: min_classes (M-of-N) ---

    #[test]
    fn min_classes_with_zero_floors_generates_masks() {
        // AD-style: min_classes=3, all per-class floors 0.
        let p = PasswordPolicy {
            min_len: 8,
            max_len: 10,
            require: ClassMins::default(),
            special_set: "!@#$".to_string(),
            forbidden_chars: String::new(),
            min_classes: Some(3),
            constraints: vec![],
        };
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000_000, len_span: 2, filler: 'l' };
        let masks = generate_masks(&p, &opts);
        assert!(!masks.is_empty(), "M-of-N policy must yield masks");
        for m in &masks {
            assert!(mask_guarantees_compliance(m.custom1.as_deref(), &m.mask, &p));
        }
    }

    #[test]
    fn custom_charset_only_present_when_mask_uses_it() {
        let p = PasswordPolicy { min_len: 8, max_len: 10, require: ClassMins::default(),
            special_set: "!@#$".into(), forbidden_chars: String::new(), min_classes: Some(3), constraints: vec![] };
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000_000, len_span: 2, filler: 'l' };
        let masks = generate_masks(&p, &opts);
        assert!(!masks.is_empty());
        for m in &masks { assert_eq!(m.custom1.is_some(), m.mask.contains("?1")); }
        assert!(masks.iter().any(|m| m.mask.contains("?1")));
        assert!(masks.iter().any(|m| !m.mask.contains("?1")));
    }

    #[test]
    fn min_compliant_keyspace_exceeds_tiny_budget_then_masks_appear() {
        let p = PasswordPolicy { min_len: 10, max_len: 14,
            require: ClassMins { lower:1, upper:1, digit:1, special:1 },
            special_set: "!@#$%".into(), forbidden_chars: String::new(), min_classes: None, constraints: vec![] };
        let tiny = MaskGenOpts { budget_per_mask: 100_000_000_000, len_span: 3, filler: 'l' };
        assert!(generate_masks(&p, &tiny).is_empty());
        let min_ks = min_compliant_keyspace(&p, &tiny).expect("a compliant shape exists");
        assert!(min_ks > tiny.budget_per_mask);
        let big = MaskGenOpts { budget_per_mask: min_ks, ..tiny };
        assert!(!generate_masks(&p, &big).is_empty());
    }

    #[test]
    fn min_classes_without_special_set() {
        let p = PasswordPolicy {
            min_len: 8,
            max_len: 8,
            require: ClassMins::default(),
            special_set: String::new(),
            forbidden_chars: String::new(),
            min_classes: Some(3),
            constraints: vec![],
        };
        let opts = MaskGenOpts { budget_per_mask: 1_000_000_000_000_000, len_span: 0, filler: 'l' };
        let masks = generate_masks(&p, &opts);
        assert!(!masks.is_empty());
        for m in &masks {
            assert!(mask_guarantees_compliance(m.custom1.as_deref(), &m.mask, &p));
        }
    }
}
