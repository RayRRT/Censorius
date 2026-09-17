//! Measure the local hash rate by running `hashcat -b`. This is the ONLY place
//! Censorius spawns a subprocess (user-authorized); all other commands are offline.

use std::process::Command;

use anyhow::{bail, Context, Result};

/// Sum the H/s speed (last colon-field) over hashcat --machine-readable benchmark
/// data lines. Returns None if no data line is present.
pub fn parse_benchmark(output: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut found = false;
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 6 {
            continue;
        }
        // data line: numeric device id in field 0, speed (H/s) in the last field.
        if parts[0].parse::<u32>().is_err() {
            continue;
        }
        if let Ok(speed) = parts[parts.len() - 1].parse::<u64>() {
            total = total.saturating_add(speed);
            found = true;
        }
    }
    if found {
        Some(total)
    } else {
        None
    }
}

/// Run `hashcat -b -m <mode> --machine-readable` and return total H/s.
pub fn run_bench(hashcat: &str, mode: &str) -> Result<u64> {
    // Some hashcat builds resolve their resource folders (e.g. ./OpenCL/) relative to
    // the process's current directory rather than the executable's own location, so
    // when a directory-qualified --hashcat path is given, run from that directory.
    // Canonicalize first so the PROGRAM path and the `current_dir` we hand to
    // `Command` are both absolute: a relative program path combined with
    // `current_dir` has platform/version-dependent resolution semantics in
    // std::process::Command (it may resolve against the original cwd or the new
    // one), so using an absolute program path sidesteps that ambiguity entirely.
    // A bare name (e.g. "hashcat" on PATH) is left as-is: no directory component
    // means no current_dir override, inheriting cwd and PATH resolution.
    let p = std::path::Path::new(hashcat);
    let has_dir = p.parent().is_some_and(|d| !d.as_os_str().is_empty());
    let (program, cwd): (std::ffi::OsString, Option<std::path::PathBuf>) = if has_dir {
        let abs = std::fs::canonicalize(p)
            .with_context(|| format!("resolving hashcat path '{hashcat}'"))?;
        let parent = abs.parent().map(|d| d.to_path_buf());
        (abs.into_os_string(), parent)
    } else {
        (hashcat.into(), None)
    };
    let mut cmd = Command::new(&program);
    cmd.args(["-b", "-m", mode, "--machine-readable"]);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = cmd.output().with_context(|| {
        format!("launching hashcat at '{hashcat}' (pass --hashcat <path> if it is not on PATH)")
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "hashcat benchmark failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.lines().last().unwrap_or("").trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_benchmark(&stdout)
        .with_context(|| "could not parse a hash rate from hashcat benchmark output")
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = "\
# version: v7.1.2
# option: --optimized-kernel-enable
1:0:4294967295:4294967295:84.64:2996865825
Started: Thu Sep 17 03:18:34 2026
Stopped: Thu Sep 17 03:18:45 2026
";

    #[test]
    fn parses_single_device_speed() {
        assert_eq!(parse_benchmark(REAL), Some(2_996_865_825));
    }

    #[test]
    fn sums_multiple_devices() {
        let s = "1:0:0:0:10.0:1000\n2:0:0:0:10.0:2000\n";
        assert_eq!(parse_benchmark(s), Some(3000));
    }

    #[test]
    fn ignores_comments_and_markers_and_returns_none_when_no_data() {
        let s = "# version: v7.1.2\nStarted: now\nStopped: later\n";
        assert_eq!(parse_benchmark(s), None);
    }
}
