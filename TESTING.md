# Validation for 2.1 development build

Executed on this Apple Silicon Mac with Swift command-line tools and ClamAV 1.4.2:

- Native optimized SwiftUI application build and ad-hoc signing.
- Isolated harmless local ClamAV signature: infected exit 1, clean exit 0, missing-target exit 2; filenames with spaces and colons; report parsing.
- Quarantine and restore round trip with SHA-256 verification, refusal to overwrite an existing destination, malformed quarantine ID, changed source, and symlink source.

Run `bash scripts/test-safety.sh` and `bash scripts/test-core.sh`. Fixtures use temporary app storage and a uniquely named harmless file under Documents/Codex, which is removed after testing. No real malware is used and no service is installed. `swift test` was unavailable here because this command-line-tools installation lacks XCTest; the standalone safety runner executes the same test methods without XCTest.

Not verified end to end: enabling launchd persistence, FDA granting/attribution, full real signature download, sleep/reboot/login behavior, download-monitor timing under live traffic, UI interaction, resource benchmarks, Intel build, or live Windows Defender execution. Installation and these checks require the owner to run the app in their normal desktop session. This deliverable has not changed your installed application or enabled background scanning.

2.1 additional checks: synthetic fixtures cover TCP PID association, connected-shell correlation, network redirection, interpreter socket wiring, netcat/socat patterns, clean shell/interpreter/SSH commands and SIP enabled/disabled/unrecognized output. Fixtures are strings only: no reverse shells, malware or external test connections are executed. An isolated on-host `--security-check` smoke test exercises the real macOS probes; it does not certify detection against live malware. Long-running service cadence, privilege-dependent visibility, timeout injection and actual kernel compromise remain unvalidated.

Host-specific probe results are kept locally and are not part of the public repository.

2.3 validation adds an isolated two-file removal test (one unchanged signature detection is quarantined; a modified file is retained), networksettings parser/validation tests, Keychain-independent authenticated-baseline fixtures and rejection of modified/wrong-key/wrong-device baselines. It does not change real network settings or create a trusted baseline of this Mac. Windows CI parses PowerShell 5.1 scripts and exercises DPAPI baselines, stale/unsafe/tampered recovery refusal, backup/read-back and mocked Defender remediation. Host security mutation functions are replaced with mocks. Live Windows UI, Defender remediation, policies, real settings restore and Windows installer/update flows have not been validated on an end-user PC.

Final review-build validation: GitHub run 40519458658 passed both macos and windows jobs at commit 5a0b045. Windows tests include hidden form initialization, DPAPI authentication, recovery backup/read-back and mocked Defender remediation; no real Defender/firewall/proxy changes or malware execution occurred in CI. Live end-user Windows acceptance remains outstanding.

Permission onboarding at commit a286063 passed both Mac and Windows CI jobs (run 40521350827). Tests cover per-build readiness/missing grants/dependencies and explicit limited-scope handling, Windows session readiness, protected installer ACL construction, alternate-user rejection and installer WhatIf. No actual FDA/Keychain/UAC grant or privileged installation was performed by these tests.
