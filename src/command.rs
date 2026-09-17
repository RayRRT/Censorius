//! Builds ready-to-copy hashcat commands. Output paths are double-quoted so
//! they work on Windows and POSIX.

pub struct CommandInputs<'a> {
    pub hash_mode: Option<&'a str>,
    pub hashes_path: &'a str,
    pub wordlist_path: &'a str,
    pub rule_path: &'a str,
    pub hcmask_path: &'a str,
}

pub struct Commands {
    pub dict: String,
    pub mask: String,
    pub note: String,
}

pub fn build_commands(inp: &CommandInputs) -> Commands {
    let mode = inp.hash_mode.unwrap_or("<MODE>");
    let dict = format!(
        r#"hashcat -a 0 -m {mode} "{hashes}" "{wl}" -r "{rule}""#,
        hashes = inp.hashes_path,
        wl = inp.wordlist_path,
        rule = inp.rule_path,
    );
    let mask = format!(
        r#"hashcat -a 3 -m {mode} "{hashes}" "{mask}""#,
        hashes = inp.hashes_path,
        mask = inp.hcmask_path,
    );
    let note = "Recommended order: run the dictionary+rules attack first \
                (best cost/coverage), then the mask attack for the remainder."
        .to_string();
    Commands { dict, mask, note }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_dict_and_mask_commands() {
        let inp = CommandInputs {
            hash_mode: Some("1000"),
            hashes_path: "hashes.txt",
            wordlist_path: "out/pruned.txt",
            rule_path: "out/policy.rule",
            hcmask_path: "out/masks.hcmask",
        };
        let c = build_commands(&inp);
        assert_eq!(
            c.dict,
            r#"hashcat -a 0 -m 1000 "hashes.txt" "out/pruned.txt" -r "out/policy.rule""#
        );
        assert_eq!(c.mask, r#"hashcat -a 3 -m 1000 "hashes.txt" "out/masks.hcmask""#);
        assert!(c.note.to_lowercase().contains("dictionary"));
    }

    #[test]
    fn uses_placeholder_when_mode_unknown() {
        let inp = CommandInputs {
            hash_mode: None,
            hashes_path: "hashes.txt",
            wordlist_path: "wl.txt",
            rule_path: "r.rule",
            hcmask_path: "m.hcmask",
        };
        let c = build_commands(&inp);
        assert!(c.dict.contains("-m <MODE>"));
    }
}
