//! The rule engine: the single source of truth for candidate transformation
//! and policy compliance. Implements the subset of hashcat rule ops that
//! Censorius emits (see docs/rules.txt).

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RuleError {
    #[error("rule op '{0}' is missing an argument")]
    MissingArg(char),
    #[error("rule op '{0}' has a bad position argument")]
    BadPosition(char),
    #[error("unsupported rule op '{0}'")]
    Unsupported(char),
}

fn toggle(c: char) -> char {
    if c.is_ascii_uppercase() {
        c.to_ascii_lowercase()
    } else if c.is_ascii_lowercase() {
        c.to_ascii_uppercase()
    } else {
        c
    }
}

/// hashcat position encoding: '0'-'9' => 0-9, 'A'-'Z' => 10-35.
fn pos_val(c: char) -> Option<usize> {
    match c {
        '0'..='9' => Some(c as usize - '0' as usize),
        'A'..='Z' => Some(c as usize - 'A' as usize + 10),
        _ => None,
    }
}

pub fn apply(word: &str, rule_line: &str) -> Result<String, RuleError> {
    let mut chars: Vec<char> = word.chars().collect();
    let mut it = rule_line.chars().peekable();
    while let Some(op) = it.next() {
        match op {
            ' ' | '\t' => continue,
            ':' => {}
            'l' => chars.iter_mut().for_each(|c| *c = c.to_ascii_lowercase()),
            'u' => chars.iter_mut().for_each(|c| *c = c.to_ascii_uppercase()),
            'c' => {
                for (i, c) in chars.iter_mut().enumerate() {
                    *c = if i == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
                }
            }
            'C' => {
                for (i, c) in chars.iter_mut().enumerate() {
                    *c = if i == 0 { c.to_ascii_lowercase() } else { c.to_ascii_uppercase() };
                }
            }
            't' => chars.iter_mut().for_each(|c| *c = toggle(*c)),
            'T' => {
                let n = it.next().ok_or(RuleError::MissingArg('T'))?;
                let pos = pos_val(n).ok_or(RuleError::BadPosition('T'))?;
                if pos < chars.len() {
                    chars[pos] = toggle(chars[pos]);
                }
            }
            '$' => {
                let x = it.next().ok_or(RuleError::MissingArg('$'))?;
                chars.push(x);
            }
            '^' => {
                let x = it.next().ok_or(RuleError::MissingArg('^'))?;
                chars.insert(0, x);
            }
            's' => {
                let x = it.next().ok_or(RuleError::MissingArg('s'))?;
                let y = it.next().ok_or(RuleError::MissingArg('s'))?;
                chars.iter_mut().for_each(|c| if *c == x { *c = y });
            }
            other => return Err(RuleError::Unsupported(other)),
        }
    }
    Ok(chars.into_iter().collect())
}

use crate::policy::{Constraint, PasswordPolicy};

#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct CharCounts {
    pub lower: u32,
    pub upper: u32,
    pub digit: u32,
    pub special: u32,
    pub other: u32,
}

pub fn count_classes(word: &str, special_set: &str) -> CharCounts {
    let mut c = CharCounts::default();
    for ch in word.chars() {
        if special_set.contains(ch) {
            c.special += 1;
        } else if ch.is_ascii_digit() {
            c.digit += 1;
        } else if ch.is_ascii_uppercase() {
            c.upper += 1;
        } else if ch.is_ascii_lowercase() {
            c.lower += 1;
        } else {
            c.other += 1;
        }
    }
    c
}

pub fn complies(word: &str, p: &PasswordPolicy) -> bool {
    let len = word.chars().count();
    if len < p.min_len as usize || len > p.max_len as usize {
        return false;
    }
    if word.chars().any(|ch| p.forbidden_chars.contains(ch)) {
        return false;
    }
    let c = count_classes(word, &p.special_set);
    if c.lower < p.require.lower as u32
        || c.upper < p.require.upper as u32
        || c.digit < p.require.digit as u32
        || c.special < p.require.special as u32
    {
        return false;
    }
    if let Some(m) = p.min_classes {
        let present = [c.lower > 0, c.upper > 0, c.digit > 0, c.special > 0]
            .iter()
            .filter(|b| **b)
            .count();
        if (present as u8) < m {
            return false;
        }
    }
    for con in &p.constraints {
        match con {
            Constraint::NotStartWithDigit => {
                if word.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    return false;
                }
            }
            Constraint::NotEndWithDigit => {
                if word.chars().last().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod apply_tests {
    use super::*;

    #[test]
    fn noop_and_case() {
        assert_eq!(apply("hello", ":").unwrap(), "hello");
        assert_eq!(apply("hello", "u").unwrap(), "HELLO");
        assert_eq!(apply("HeLLo", "l").unwrap(), "hello");
        assert_eq!(apply("hello", "c").unwrap(), "Hello"); // lower rest, upper 1st
        assert_eq!(apply("hello", "C").unwrap(), "hELLO"); // upper rest, lower 1st
        assert_eq!(apply("HeLLo", "t").unwrap(), "hEllO"); // toggle each
    }

    #[test]
    fn toggle_at_position() {
        assert_eq!(apply("hello", "T0").unwrap(), "Hello");
        assert_eq!(apply("hello", "T4").unwrap(), "hellO");
        assert_eq!(apply("hi", "T9").unwrap(), "hi"); // out of range: no-op
    }

    #[test]
    fn append_prepend() {
        assert_eq!(apply("hello", "$1").unwrap(), "hello1");
        assert_eq!(apply("hello", "^1").unwrap(), "1hello");
    }

    #[test]
    fn substitute() {
        assert_eq!(apply("hello", "so0").unwrap(), "hell0");
        assert_eq!(apply("hello", "sl1").unwrap(), "he11o");
    }

    #[test]
    fn chained_functions_with_spaces() {
        assert_eq!(apply("hello", "c $1 $2 $3").unwrap(), "Hello123");
        assert_eq!(apply("verano", "c $2 $0 $2 $4 $!").unwrap(), "Verano2024!");
    }

    #[test]
    fn unsupported_op_errors() {
        assert!(matches!(apply("hello", "r"), Err(RuleError::Unsupported('r'))));
    }
}

#[cfg(test)]
mod complies_tests {
    use super::*;
    use crate::policy::{ClassMins, Constraint, PasswordPolicy};

    fn policy() -> PasswordPolicy {
        PasswordPolicy {
            min_len: 8,
            max_len: 16,
            require: ClassMins { lower: 1, upper: 1, digit: 1, special: 1 },
            special_set: "!@#$".to_string(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![],
        }
    }

    #[test]
    fn counts_classes_by_special_set() {
        let c = count_classes("Ab1!x", "!@#$");
        assert_eq!(c, CharCounts { lower: 2, upper: 1, digit: 1, special: 1, other: 0 });
    }

    #[test]
    fn compliant_password_passes() {
        assert!(complies("Verano24!", &policy()));
    }

    #[test]
    fn too_short_fails() {
        assert!(!complies("Ab1!", &policy()));
    }

    #[test]
    fn missing_class_fails() {
        assert!(!complies("verano24x", &policy())); // no upper, no special
    }

    #[test]
    fn forbidden_char_fails() {
        let mut p = policy();
        p.forbidden_chars = " ".to_string();
        assert!(!complies("Ver ano24!", &p));
    }

    #[test]
    fn min_classes_of_n() {
        let mut p = policy();
        p.require = ClassMins::default();
        p.min_classes = Some(3);
        assert!(complies("Verano24", &p));   // lower+upper+digit = 3 classes
        assert!(!complies("verano24", &p));  // only 2 classes
    }

    #[test]
    fn constraint_not_start_with_digit() {
        let mut p = policy();
        p.constraints = vec![Constraint::NotStartWithDigit];
        assert!(!complies("1erano4!X", &p));
    }
}
