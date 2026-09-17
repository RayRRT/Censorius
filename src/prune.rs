//! Conservative, policy-based wordlist pruning. Drops a base only when no
//! rule we generate could ever make it comply.

use std::io::{BufRead, Write};

use rayon::prelude::*;

use crate::policy::PasswordPolicy;

pub fn is_impossible(word: &str, p: &PasswordPolicy) -> bool {
    // We only ADD characters, so exceeding max_len is terminal.
    if word.chars().count() > p.max_len as usize {
        return true;
    }
    // A forbidden char is fatal only if none of our generated substitution
    // rules (sa@ se3 si1 so0 ss$, see rulegen) can remove it. Those rules
    // only ever remove lowercase a/e/i/o/s, so any other forbidden char
    // present now cannot be guaranteed removed by our rules.
    const SUBSTITUTABLE: &str = "aeios";
    if word
        .chars()
        .any(|ch| p.forbidden_chars.contains(ch) && !SUBSTITUTABLE.contains(ch))
    {
        return true;
    }
    false
}

pub fn prune(words: &[String], p: &PasswordPolicy) -> Vec<String> {
    words
        .par_iter()
        .filter(|w| !is_impossible(w, p))
        .cloned()
        .collect()
}

/// Streaming prune: read lines from `reader`, write kept lines to `writer`,
/// return (total_seen, kept, sample_of_kept). O(1) memory beyond the sample.
pub fn prune_stream<R: BufRead, W: Write>(
    reader: R,
    p: &PasswordPolicy,
    writer: &mut W,
    sample_cap: usize,
) -> std::io::Result<(usize, usize, Vec<String>)> {
    let mut total = 0usize;
    let mut kept = 0usize;
    let mut sample: Vec<String> = Vec::new();
    for line in reader.split(b'\n') {
        let bytes = line?;
        let s = String::from_utf8_lossy(&bytes);
        let w = s.trim_end_matches(['\r', '\n']);
        if w.is_empty() {
            continue;
        }
        total += 1;
        if !is_impossible(w, p) {
            kept += 1;
            writeln!(writer, "{w}")?;
            if sample.len() < sample_cap {
                sample.push(w.to_string());
            }
        }
    }
    Ok((total, kept, sample))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{ClassMins, PasswordPolicy};

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_len: 8,
            max_len: 10,
            require: ClassMins { lower: 1, upper: 1, digit: 1, special: 0 },
            special_set: "!@#".to_string(),
            forbidden_chars: " ".to_string(),
            min_classes: None,
            constraints: vec![],
        }
    }

    #[test]
    fn keeps_short_base_min_len_not_grounds() {
        // "cat" is short but append rules can reach min_len 8.
        assert!(!is_impossible("cat", &policy()));
    }

    #[test]
    fn drops_base_longer_than_max() {
        assert!(is_impossible("abcdefghijk", &policy())); // 11 > max 10
    }

    #[test]
    fn drops_base_with_forbidden_char() {
        assert!(is_impossible("hola mundo", &policy())); // contains space
    }

    #[test]
    fn keeps_base_whose_only_forbidden_char_is_substitutable() {
        // Our leetspeak rules include "sa@", which can remove every 'a'.
        let mut p = policy();
        p.forbidden_chars = "a".to_string();
        assert!(!is_impossible("casa", &p));
    }

    #[test]
    fn prune_filters_only_impossible() {
        let words = vec![
            "cat".to_string(),
            "abcdefghijk".to_string(),
            "hola mundo".to_string(),
            "verano".to_string(),
        ];
        let kept = prune(&words, &policy());
        assert_eq!(kept, vec!["cat".to_string(), "verano".to_string()]);
    }

    #[test]
    fn prune_stream_filters_writes_and_samples() {
        use std::io::Cursor;
        let input = Cursor::new("cat\r\nhola mundo\nverano\nabcdefghijk\n\n");
        let mut out: Vec<u8> = Vec::new();
        let (total, kept, sample) = prune_stream(input, &policy(), &mut out, 10).unwrap();
        assert_eq!(total, 4);              // 4 non-empty lines
        assert_eq!(kept, 2);               // "cat", "verano" (space forbidden; 11>max10 dropped)
        assert_eq!(String::from_utf8(out).unwrap(), "cat\nverano\n");
        assert_eq!(sample, vec!["cat".to_string(), "verano".to_string()]);
    }

    #[test]
    fn prune_stream_respects_sample_cap() {
        use std::io::Cursor;
        let input = Cursor::new("cat\ndog\nsun\n"); // all kept (short, no forbidden)
        let mut out: Vec<u8> = Vec::new();
        let (total, kept, sample) = prune_stream(input, &policy(), &mut out, 2).unwrap();
        assert_eq!((total, kept), (3, 3));
        assert_eq!(sample.len(), 2); // capped
    }
}
