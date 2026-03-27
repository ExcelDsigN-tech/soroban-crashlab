# Wave 3 Backlog (Curated, Non-Redundant)

This backlog is intentionally scoped for contributor onboarding and maintainer throughput. It is mirrored in `ops/wave3-issues.tsv` for automated issue creation.

## Current size

- Total issues prepared: 91
- Complexity distribution:
	- Trivial: 30
	- Medium: 48
	- High: 13

## Area breakdown

- `area:fuzzer`: mutation quality, seed management, campaign control, deterministic parallelism
- `area:runtime`: replay reliability, metadata integrity, retention, and run health
- `area:generator`: fixture export, shrinking, signature grouping, regression packs, fixture compatibility checking (#56)
- `area:web`: dashboard observability, triage UX, replay controls, and reporting views
- `area:docs`: reproducibility, onboarding, complexity rubric, release and debugging docs
- `area:ops`: triage cadence, issue hygiene, SLA visibility, and maintainer governance
- `area:security`: disclosure, policy hardening, threat modeling, and secret handling

## Completed

- **Duplicate crash de-dup index** (`area:generator`): Added `crash_index` module with `CrashIndex`, `CrashGroup`, and `CrashIndexSummary`. Groups repeated failures by `signature_hash`, tracks hit count and newest sample per group. `CrashIndexSummary::to_cli_table()` renders grouped counts and newest seed for CLI/dashboard consumption.

## Maintainer note

Do not expose all 91 issues as active wave tasks at once. Publish in phased batches with regular triage to preserve review quality and avoid low-signal throughput.

Recommended active window per wave:

- 25 to 40 active issues
- keep the remainder in reserve as queued, dependency-aware follow-up tasks

