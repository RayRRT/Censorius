//! Censorius library. Authorized penetration testing use only.

pub mod analyze;
pub mod bench;
pub mod cli;
pub mod command;
pub mod estimate;
pub mod genwl;
pub mod maskgen;
pub mod pipeline;
pub mod policy;
pub mod prune;
pub mod ruleengine;
pub mod rulegen;
pub mod wizard;
pub mod wordlist;

#[cfg(test)]
mod smoke {
    #[test]
    fn crate_builds() {
        assert_eq!(2 + 2, 4);
    }
}
