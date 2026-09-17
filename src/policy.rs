//! Password policy model, validation, and TOML (de)serialization.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClassMins {
    #[serde(default)]
    pub lower: u8,
    #[serde(default)]
    pub upper: u8,
    #[serde(default)]
    pub digit: u8,
    #[serde(default)]
    pub special: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constraint {
    NotStartWithDigit,
    NotEndWithDigit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_len: u8,
    pub max_len: u8,
    pub special_set: String,
    #[serde(default)]
    pub forbidden_chars: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_classes: Option<u8>,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
    // NOTE: `require` is a TOML table and MUST be the LAST field: the `toml`
    // crate requires all scalar/array value fields to serialize before any
    // table. Struct-literal field order elsewhere is irrelevant to this.
    pub require: ClassMins,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("min_len exceeds max_len")]
    MinExceedsMax,
    #[error("sum of required class minimums exceeds max_len")]
    ClassSumExceedsMax,
    #[error("special chars required but special_set is empty")]
    SpecialRequiredButEmptySet,
    #[error("min_classes exceeds available classes")]
    TooManyClasses,
    #[error("special_set must be punctuation only (no letters, digits, or comma)")]
    InvalidSpecialSet,
    #[error("TOML error: {0}")]
    Toml(String),
}

impl PasswordPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        let sum = self.require.lower as u16
            + self.require.upper as u16
            + self.require.digit as u16
            + self.require.special as u16;
        if sum > self.max_len as u16 {
            return Err(PolicyError::ClassSumExceedsMax);
        }
        if self.min_len > self.max_len {
            return Err(PolicyError::MinExceedsMax);
        }
        if self.require.special > 0 && self.special_set.is_empty() {
            return Err(PolicyError::SpecialRequiredButEmptySet);
        }
        if let Some(m) = self.min_classes {
            // Available classes: lower/upper/digit are always available;
            // special is available only when special_set is non-empty.
            let available = if self.special_set.is_empty() { 3 } else { 4 };
            if m > available {
                return Err(PolicyError::TooManyClasses);
            }
        }
        if self.special_set.chars().any(|c| c.is_ascii_alphanumeric() || c == ',') {
            return Err(PolicyError::InvalidSpecialSet);
        }
        Ok(())
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("policy serializes")
    }

    pub fn from_toml(s: &str) -> Result<Self, PolicyError> {
        toml::from_str(s).map_err(|e| PolicyError::Toml(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PasswordPolicy {
        PasswordPolicy {
            min_len: 8,
            max_len: 16,
            require: ClassMins { lower: 1, upper: 1, digit: 1, special: 0 },
            special_set: "!@#$%._-".to_string(),
            forbidden_chars: String::new(),
            min_classes: None,
            constraints: vec![],
        }
    }

    #[test]
    fn toml_round_trip() {
        let p = sample();
        let s = p.to_toml();
        let back = PasswordPolicy::from_toml(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn validate_ok() {
        assert!(sample().validate().is_ok());
    }

    #[test]
    fn validate_rejects_min_gt_max() {
        let mut p = sample();
        p.min_len = 20;
        assert!(matches!(p.validate(), Err(PolicyError::MinExceedsMax)));
    }

    #[test]
    fn validate_rejects_impossible_class_sum() {
        let mut p = sample();
        p.max_len = 2;
        p.require = ClassMins { lower: 1, upper: 1, digit: 1, special: 1 };
        assert!(matches!(p.validate(), Err(PolicyError::ClassSumExceedsMax)));
    }

    #[test]
    fn validate_rejects_special_required_without_set() {
        let mut p = sample();
        p.require.special = 1;
        p.special_set = String::new();
        assert!(matches!(p.validate(), Err(PolicyError::SpecialRequiredButEmptySet)));
    }

    #[test]
    fn validate_rejects_special_set_with_digit() {
        let mut p = sample();
        p.special_set = "5".to_string();
        assert!(matches!(p.validate(), Err(PolicyError::InvalidSpecialSet)));
    }

    #[test]
    fn validate_rejects_special_set_with_letter() {
        let mut p = sample();
        p.special_set = "a".to_string();
        assert!(matches!(p.validate(), Err(PolicyError::InvalidSpecialSet)));
    }

    #[test]
    fn validate_rejects_special_set_with_comma() {
        let mut p = sample();
        p.special_set = "!@#,".to_string();
        assert!(matches!(p.validate(), Err(PolicyError::InvalidSpecialSet)));
    }

    #[test]
    fn validate_rejects_min_classes_exceeding_available_without_special_set() {
        // Only 3 classes (lower/upper/digit) are available when special_set is empty.
        let mut p = sample();
        p.special_set = String::new();
        p.min_classes = Some(4);
        assert!(matches!(p.validate(), Err(PolicyError::TooManyClasses)));
    }

    #[test]
    fn validate_accepts_min_classes_at_available_max_without_special_set() {
        let mut p = sample();
        p.special_set = String::new();
        p.min_classes = Some(3);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_accepts_min_classes_three_and_four_with_special_set() {
        let mut p = sample();
        p.min_classes = Some(3);
        assert!(p.validate().is_ok());
        p.min_classes = Some(4);
        assert!(p.validate().is_ok());
    }
}
