#!/bin/bash
set -euo pipefail
export CORSO_TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$CORSO_TEST_ROOT"' EXIT
cd "$(dirname "$0")/.."
mkdir -p .build/safety
python3 - <<'GEN'
from pathlib import Path
s=Path('Tests/CorsoShieldTests/CoreTests.swift').read_text().replace('import XCTest','import Foundation').replace('@testable import CorsoShield','').replace('class CoreTests: XCTestCase','class CoreTests')
s=s.replace('XCTAssertEqual(', 'assertEqual(').replace('XCTAssertTrue(', 'assertTrue(').replace('XCTAssertFalse(', 'assertFalse(').replace('XCTAssertThrowsError(', 'assertThrows(')
helpers="""
func assertEqual<T: Equatable>(_ a: T, _ b: T, _ message: String = "") { precondition(a == b, message) }
func assertTrue(_ a: Bool) { precondition(a) }
func assertFalse(_ a: Bool) { precondition(!a) }
func assertThrows<T>(_ action: @autoclosure () throws -> T) { do { _ = try action(); fatalError("Expected refusal") } catch {} }
let tests = CoreTests()
try tests.testQuarantineRestore()
tests.testThreatIndicators()
tests.testParser()
tests.testExitStatus()
try tests.testRealClamAVWithIsolatedHarmlessSignature()
print("PASS: security-indicator fixtures, quarantine/restore, overwrite refusal, invalid ID, changed file, symlink refusal, parsing, real ClamAV infected/clean")
"""
Path('.build/safety/main.swift').write_text(s + helpers)
GEN
swiftc -module-cache-path .build/clang-cache Sources/CorsoShield/Core.swift Sources/CorsoShield/Service.swift Sources/CorsoShield/Threats.swift .build/safety/main.swift -o .build/safety/check
.build/safety/check
