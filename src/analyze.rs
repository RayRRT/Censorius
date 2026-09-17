//! Analyze already-cracked passwords into target-tailored masks, rules, and
//! stats (a focused, modern take on PACK's statsgen/maskgen). Offline, pure.

use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ClassPrevalence {
    pub lower: usize,
    pub upper: usize,
    pub digit: usize,
    pub special: usize,
}

#[derive(Debug)]
pub struct Analysis {
    pub total: usize,
    pub length_hist: BTreeMap<usize, usize>,
    pub prevalence: ClassPrevalence,
    /// (mask, count) sorted by count desc, then mask asc.
    pub mask_freq: Vec<(String, usize)>,
}

/// hashcat standard-class mask: ?l ?u ?d ?s (?s = any non-alphanumeric char).
pub fn word_to_mask(w: &str) -> String {
    let mut m = String::with_capacity(w.chars().count() * 2);
    for c in w.chars() {
        m.push('?');
        if c.is_ascii_lowercase() {
            m.push('l');
        } else if c.is_ascii_uppercase() {
            m.push('u');
        } else if c.is_ascii_digit() {
            m.push('d');
        } else {
            m.push('s');
        }
    }
    m
}

pub fn analyze(words: &[String]) -> Analysis {
    let mut length_hist: BTreeMap<usize, usize> = BTreeMap::new();
    let mut prevalence = ClassPrevalence::default();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut total = 0;
    for w in words {
        if w.is_empty() {
            continue;
        }
        total += 1;
        *length_hist.entry(w.chars().count()).or_insert(0) += 1;
        if w.chars().any(|c| c.is_ascii_lowercase()) { prevalence.lower += 1; }
        if w.chars().any(|c| c.is_ascii_uppercase()) { prevalence.upper += 1; }
        if w.chars().any(|c| c.is_ascii_digit()) { prevalence.digit += 1; }
        if w.chars().any(|c| !c.is_ascii_alphanumeric()) { prevalence.special += 1; }
        *counts.entry(word_to_mask(w)).or_insert(0) += 1;
    }
    let mut mask_freq: Vec<(String, usize)> = counts.into_iter().collect();
    mask_freq.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Analysis { total, length_hist, prevalence, mask_freq }
}

pub fn top_masks(a: &Analysis, n: usize) -> Vec<String> {
    a.mask_freq.iter().take(n).map(|(m, _)| m.clone()).collect()
}

use crate::policy::PasswordPolicy;

/// Distinct class tokens present in a mask (?l/?u/?d/?s).
fn mask_class_tokens(mask: &str) -> (bool, bool, bool, bool) {
    // (lower, upper, digit, special)
    (mask.contains("?l"), mask.contains("?u"), mask.contains("?d"), mask.contains("?s"))
}

pub fn mask_matches_policy(mask: &str, p: &PasswordPolicy) -> bool {
    let len = mask.matches('?').count(); // one '?' per position
    if len < p.min_len as usize || len > p.max_len as usize {
        return false;
    }
    let (lo, up, di, sp) = mask_class_tokens(mask);
    if p.require.lower > 0 && !lo { return false; }
    if p.require.upper > 0 && !up { return false; }
    if p.require.digit > 0 && !di { return false; }
    if p.require.special > 0 && !sp { return false; }
    if let Some(m) = p.min_classes {
        let present = [lo, up, di, sp].iter().filter(|b| **b).count();
        if (present as u8) < m { return false; }
    }
    true
}

pub fn select_masks(a: &Analysis, n: usize, policy: Option<&PasswordPolicy>) -> Vec<String> {
    a.mask_freq
        .iter()
        .filter(|(m, _)| policy.map_or(true, |p| mask_matches_policy(m, p)))
        .take(n)
        .map(|(m, _)| m.clone())
        .collect()
}

pub fn derive_rules(words: &[String], top: usize) -> Vec<String> {
    let mut suffix: HashMap<String, usize> = HashMap::new();
    let mut prefix: HashMap<String, usize> = HashMap::new();
    let mut cap = 0usize;
    let mut total = 0usize;
    for w in words {
        if w.is_empty() {
            continue;
        }
        total += 1;
        let chars: Vec<char> = w.chars().collect();
        // trailing non-alpha run (bounded to 6)
        let mut i = chars.len();
        while i > 0 && !chars[i - 1].is_ascii_alphabetic() {
            i -= 1;
        }
        if i < chars.len() && chars.len() - i <= 6 {
            let s: String = chars[i..].iter().collect();
            *suffix.entry(s).or_insert(0) += 1;
        }
        // leading non-alpha run (bounded to 6)
        let mut j = 0;
        while j < chars.len() && !chars[j].is_ascii_alphabetic() {
            j += 1;
        }
        if j > 0 && j <= 6 {
            let p: String = chars[..j].iter().collect();
            *prefix.entry(p).or_insert(0) += 1;
        }
        // first-upper-rest-not-upper capitalization
        if chars[0].is_ascii_uppercase()
            && chars[1..].iter().all(|c| !c.is_ascii_uppercase())
            && chars.iter().any(|c| c.is_ascii_alphabetic())
        {
            cap += 1;
        }
    }
    let mut rules: Vec<String> = Vec::new();
    if total > 0 && cap * 2 >= total {
        rules.push("c".to_string());
    }
    let mut sfx: Vec<(String, usize)> = suffix.into_iter().collect();
    sfx.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (s, _) in sfx.into_iter().take(top) {
        let r = s.chars().map(|c| format!("${c}")).collect::<Vec<_>>().join(" ");
        rules.push(r.clone());
        rules.push(format!("c {r}"));
    }
    let mut pfx: Vec<(String, usize)> = prefix.into_iter().collect();
    pfx.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (p, _) in pfx.into_iter().take(top) {
        // ^X prepends X; emit chars reversed so the leading run is reconstructed.
        let r = p.chars().rev().map(|c| format!("^{c}")).collect::<Vec<_>>().join(" ");
        rules.push(r);
    }
    let mut seen = std::collections::HashSet::new();
    rules.retain(|r| seen.insert(r.clone()));
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_to_mask_maps_classes() {
        assert_eq!(word_to_mask("Password1!"), "?u?l?l?l?l?l?l?l?d?s");
        assert_eq!(word_to_mask("abc"), "?l?l?l");
    }

    #[test]
    fn analyze_counts_and_ranks_masks() {
        let words: Vec<String> = ["Verano1", "Madrid1", "Verano2", "x"]
            .iter().map(|s| s.to_string()).collect();
        let a = analyze(&words);
        assert_eq!(a.total, 4);
        // "Verano1"/"Madrid1"/"Verano2" all -> ?u?l?l?l?l?l?d (7 chars), "x" -> ?l
        assert_eq!(a.mask_freq[0].0, "?u?l?l?l?l?l?d");
        assert_eq!(a.mask_freq[0].1, 3);
        assert_eq!(*a.length_hist.get(&7).unwrap(), 3);
        assert_eq!(*a.length_hist.get(&1).unwrap(), 1);
        assert_eq!(a.prevalence.upper, 3);
        assert_eq!(a.prevalence.digit, 3);
        assert_eq!(a.prevalence.lower, 4);
        assert_eq!(a.prevalence.special, 0);
    }

    #[test]
    fn top_masks_returns_most_frequent_first() {
        let words: Vec<String> = ["ab1","cd2","ef3","g"].iter().map(|s| s.to_string()).collect();
        let a = analyze(&words);
        let top = top_masks(&a, 1);
        assert_eq!(top, vec!["?l?l?d".to_string()]); // 3 of these vs 1 of "?l"
    }

    use crate::policy::{ClassMins, PasswordPolicy};

    fn pol() -> PasswordPolicy {
        PasswordPolicy { min_len: 6, max_len: 12,
            require: ClassMins { lower:1, upper:1, digit:1, special:0 },
            special_set: "!@#$".into(), forbidden_chars: String::new(),
            min_classes: None, constraints: vec![] }
    }

    #[test]
    fn mask_matches_policy_checks_len_and_required_classes() {
        assert!(mask_matches_policy("?u?l?l?l?l?d", &pol()));   // 6, has upper/lower/digit
        assert!(!mask_matches_policy("?l?l?l?l?l?d", &pol()));  // no upper
        assert!(!mask_matches_policy("?u?l?d", &pol()));        // len 3 < 6
    }

    #[test]
    fn select_masks_filters_by_policy() {
        let words: Vec<String> = ["Verano1","otono12","Madrid9"].iter().map(|s| s.to_string()).collect();
        let a = analyze(&words);
        let sel = select_masks(&a, 10, Some(&pol()));
        assert!(sel.iter().all(|m| mask_matches_policy(m, &pol())));
        assert!(!sel.contains(&"?l?l?l?l?l?d?d".to_string())); // "otono12": no upper -> excluded
    }

    #[test]
    fn derive_rules_finds_suffix_and_capitalization() {
        // 3/3 capitalized, all end in "2024"
        let words: Vec<String> = ["Verano2024","Madrid2024","Otono2024"].iter().map(|s| s.to_string()).collect();
        let rules = derive_rules(&words, 5);
        assert!(rules.contains(&"c".to_string()));
        assert!(rules.contains(&"$2 $0 $2 $4".to_string()));
    }

    #[test]
    fn derive_rules_finds_prefix() {
        let words: Vec<String> = ["12verano","12madrid","12otono"].iter().map(|s| s.to_string()).collect();
        let rules = derive_rules(&words, 5);
        // prepend "12": ^2 then ^1 reconstructs the leading "12"
        assert!(rules.contains(&"^2 ^1".to_string()));
    }
}
