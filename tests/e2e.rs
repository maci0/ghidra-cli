//! End-to-end smoke tests for ghidra-cli
//!
//! This is a lightweight smoke test that verifies basic CLI functionality.
//! Comprehensive test coverage is in:
//! - command_tests.rs (version, doctor, config)
//! - project_tests.rs (project management, import, analyze)
//! - daemon_tests.rs (daemon lifecycle)
//! - query_tests.rs (function, strings, memory, decompile, dump)
//! - unimplemented_tests.rs (graceful error messages)

use predicates::prelude::*;

#[macro_use]
mod common;

/// Smoke test - verifies basic CLI commands work.
/// Requires an installed Ghidra because it asserts `ghidra doctor` succeeds.
#[test]
fn test_smoke() {
    require_ghidra!();

    // Version command should always work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ghidra-cli"));

    // Doctor command verifies installation
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("doctor")
        .assert()
        .success();

    // Config list should work
    assert_cmd::cargo::cargo_bin_cmd!("ghidra")
        .arg("config")
        .arg("list")
        .assert()
        .success();
}
