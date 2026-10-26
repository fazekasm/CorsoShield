#!/bin/bash
set -euo pipefail
export CORSO_TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$CORSO_TEST_ROOT"' EXIT
cd "$(dirname "$0")/.."
mkdir -p .build/core-test
cat > .build/core-test/main.swift <<'SWIFT'
import Foundation
import CryptoKit
let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: dir) }
let sample = dir.appendingPathComponent("sample with spaces.txt")
let data = Data("Corso Shield harmless test fixture".utf8)
try data.write(to: sample)
let md5 = Insecure.MD5.hash(data: data).map { String(format: "%02x", $0) }.joined()
let db = dir.appendingPathComponent("fixture.hdb")
try "\(md5):\(data.count):Corso.Test\n".write(to: db, atomically: true, encoding: .utf8)
try Shield.setup()
let engine = try Shield.binary("clamscan")
let (infected, output) = try Shield.run(engine, ["--database=\(db.path)", "--", sample.path], log: dir.appendingPathComponent("run.log"))
precondition(infected == 1, output)
print(output)
precondition(URL(fileURLWithPath: Shield.parse(output).first!.path).resolvingSymlinksInPath() == sample.resolvingSymlinksInPath())
try Data("Clean sample".utf8).write(to: sample)
let (clean, cleanOutput) = try Shield.run(engine, ["--database=\(db.path)", "--", sample.path], log: dir.appendingPathComponent("run.log"))
precondition(clean == 0, cleanOutput)
let (error, _) = try Shield.run(engine, ["--database=\(db.path)", "--", dir.appendingPathComponent("missing").path], log: dir.appendingPathComponent("run.log"))
precondition(error == 2)
precondition(Shield.parse("/tmp/a: b: Test FOUND").first?.path == "/tmp/a: b")
print("PASS: real ClamAV detection, clean scan, error exit, paths with spaces, report parser")
SWIFT
swiftc -module-cache-path .build/clang-cache Sources/CorsoShield/Core.swift Sources/CorsoShield/Service.swift Sources/CorsoShield/Threats.swift .build/core-test/main.swift -o .build/core-test/check
.build/core-test/check
