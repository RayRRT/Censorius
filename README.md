# Censorius

Turns a password policy into ready-to-run, provably-compliant hashcat
artifacts: a pruned or generated wordlist, a directed rule file, and a
policy-compliant mask set — plus the hashcat commands to run them.

**Authorized penetration testing only.** Do not use against systems you do
not have explicit written permission to test.

## Usage

Interactive: `censorius` (wizard).

Non-interactive:

    censorius run --profile ad-default --seeds "acme,summer" --out out
    censorius run --policy my-policy.toml --wordlist rockyou.txt --mode 1000 --out out

`censorius profile show ad-default` prints the built-in policy.

Raise the mask budget for longer policies (default keeps mask attacks small):

    censorius run --policy long.toml --seeds "acme" --mask-budget 1000000000000 --out out

If a run prints `warning: 0 masks within budget …`, re-run with the suggested `--mask-budget`.

The run summary estimates attack time at an assumed hash rate; set yours
(measure with `hashcat -b -m <mode>`) for a realistic figure:

    censorius run --profile ad-default --seeds "acme" --hashrate 8000000000 --out out

Analyze already-cracked passwords (potfile, prior engagement) to build
target-tailored masks/rules ordered by real frequency:

    censorius analyze cracked.txt --top 25 --out analysis
    censorius analyze cracked.txt --policy target.toml   # filter masks to the policy

Measure your real hash rate for a mode (this one runs hashcat), then feed it to `run`:

    censorius bench --mode 1000 --hashcat /path/to/hashcat
    # -> mode 1000: 8200000000 H/s (~8.20 GH/s)
    censorius run --profile ad-default --seeds "acme" --hashrate 8200000000 --out out

Core commands (`run`, `analyze`, wizard) are fully offline — they never touch
the network or run a subprocess. `bench` is the sole exception: it executes
the local hashcat binary to measure your hardware's hash rate (no network).

## Known limitations (MVP)

- Wordlists are loaded fully into memory (not streamed); very large
  (multi-GB) lists use roughly 2x their size in RAM.
- `special_set` must contain only punctuation (no letters, digits, or
  comma); this is enforced by validation.
