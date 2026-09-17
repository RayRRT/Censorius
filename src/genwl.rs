//! Offline, seed-based wordlist generation from target context. No network.

use std::collections::HashSet;

pub struct SeedInput {
    pub tokens: Vec<String>,
    pub years: Vec<u16>,
    pub max_size: usize,
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

pub fn generate_wordlist(seed: &SeedInput) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push = |w: String, out: &mut Vec<String>, seen: &mut HashSet<String>| {
        if !w.is_empty() && seen.insert(w.clone()) {
            out.push(w);
        }
    };

    for tok in &seed.tokens {
        let lower = tok.to_ascii_lowercase();
        let variants = [lower.clone(), capitalize(&lower)];
        for v in &variants {
            push(v.clone(), &mut out, &mut seen);
            for y in &seed.years {
                push(format!("{v}{y}"), &mut out, &mut seen);
            }
        }
    }

    out.truncate(seed.max_size);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tokens_with_case_and_years() {
        let seed = SeedInput {
            tokens: vec!["acme".to_string()],
            years: vec![2024],
            max_size: 100,
        };
        let wl = generate_wordlist(&seed);
        assert!(wl.contains(&"acme".to_string()));
        assert!(wl.contains(&"Acme".to_string()));
        assert!(wl.contains(&"acme2024".to_string()));
        assert!(wl.contains(&"Acme2024".to_string()));
    }

    #[test]
    fn dedupes_and_caps_at_max_size() {
        let seed = SeedInput {
            tokens: vec!["a".to_string(), "a".to_string()],
            years: vec![],
            max_size: 3,
        };
        let wl = generate_wordlist(&seed);
        assert!(wl.len() <= 3);
        let mut s = wl.clone();
        s.sort();
        s.dedup();
        assert_eq!(s.len(), wl.len());
    }
}
