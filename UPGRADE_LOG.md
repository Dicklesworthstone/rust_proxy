# Dependency Upgrade Log

**Date:** 2026-01-18  |  **Project:** rust_proxy  |  **Language:** Rust

## Summary
- **Updated:** 5  |  **Skipped:** 0  |  **Failed:** 0  |  **Needs attention:** 0

## Outdated Dependencies Detected

| Package | Current | Latest | Status |
|---------|---------|--------|--------|
| directories | 5.0.1 | 6.0.0 | ✅ Updated |
| inquire | 0.7.5 | 0.9.2 | ✅ Updated |
| reqwest | 0.11.27 | 0.13.1 | ✅ Updated |
| tabled | 0.16.0 | 0.20.0 | ✅ Updated |
| toml | 0.8.23 | 0.9.11 | ✅ Updated |

## Updates

### directories: 5.0.1 → 6.0.0
- **Breaking:** None (dependency update only - dirs-sys 0.4→0.5)
- **Research:** [GitHub Changelog](https://github.com/xdg-rs/dirs/blob/master/directories/CHANGELOG.md)
- **Tests:** ✓ cargo check passed

### inquire: 0.7.5 → 0.9.2
- **Breaking:** None (MSRV raised to 1.82, validator lifetime relaxation is non-breaking)
- **Research:** [GitHub Changelog](https://github.com/mikaelmello/inquire/blob/main/CHANGELOG.md)
- **Deps updated:** crossterm 0.25→0.29, removed fxhash/newline-converter
- **Tests:** ✓ cargo check passed

### reqwest: 0.11.27 → 0.13.1
- **Breaking:** Feature `rustls-tls` renamed to `rustls`
- **Migration:** Changed `features = ["json", "rustls-tls"]` to `features = ["json", "rustls"]`
- **Research:** [GitHub Changelog](https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md)
- **Major changes:**
  - Upgraded to hyper/http/http-body v1
  - rustls now uses aws-lc instead of ring
  - native-tls removed (not needed with rustls)
- **Tests:** ✓ cargo check passed

### tabled: 0.16.0 → 0.20.0
- **Breaking:** Multiple API changes (Disable→Remove, display_with→display, etc.)
- **Research:** [GitHub Changelog](https://github.com/zhiburt/tabled/blob/master/CHANGELOG.md)
- **Note:** Basic usage (`Table::new`, `#[derive(Tabled)]`, `Style`) unaffected
- **Deps updated:** papergrid 0.12→0.17, proc-macro-error→proc-macro-error2
- **Tests:** ✓ cargo check passed

### toml: 0.8.23 → 0.9.11
- **Breaking:** `FromStr for Value` behavior changed, Deserializer API changes
- **Research:** [GitHub Changelog](https://github.com/toml-rs/toml/blob/main/crates/toml/CHANGELOG.md)
- **Note:** Basic `from_str`/`to_string_pretty` usage unaffected
- **Deps updated:** toml_edit→toml_parser, toml_write→toml_writer
- **Tests:** ✓ cargo check passed

## Failed

(Any failed updates will be logged here)

## Needs Attention

(None)

## Final Validation

| Check | Status |
|-------|--------|
| `cargo clippy --all-targets` | ✓ No warnings |
| `cargo test` | ✓ 66 tests passed |
| `cargo build --release` | ✓ Build successful |
| `cargo audit` | ⏭️ Skipped (not installed) |

**Upgrade completed successfully!**
