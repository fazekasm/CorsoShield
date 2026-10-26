# Validation for 2.1 development build

Executed on this Apple Silicon Mac with Swift command-line tools and ClamAV 1.4.2:

- Native optimized SwiftUI application build and ad-hoc signing.
- Isolated harmless local ClamAV signature: infected exit 1, clean exit 0, missing-target exit 2; filenames with spaces and colons; report parsing.
- Quarantine and restore round trip with SHA-256 verification, refusal to overwrite an existing destination, malformed quarantine ID, changed source, and symlink source.

Run `bash scripts/test-safety.sh` and `bash scripts/test-core.sh`. Fixtures use temporary app storage and a uniquely named harmless file under Documents/Codex, which is removed after testing. No real malware is used and no service is installed. `swift test` was unavailable here because this command-line-tools installation lacks XCTest; the standalone safety runner executes the same test methods without XCTest.

Not verified end to end: enabling launchd persistence, FDA granting/attribution, full real signature download, sleep/reboot/login behavior, download-monitor timing under live traffic, UI interaction, resource benchmarks, Intel build, or Windows execution. Installation and these checks require the owner to run the app in their normal desktop session. This deliverable has not changed your installed application or enabled background scanning.

2.1 additional checks: synthetic fixtures cover TCP PID association, connected-shell correlation, network redirection, interpreter socket wiring, netcat/socat patterns, clean shell/interpreter/SSH commands and SIP enabled/disabled/unrecognized output. Fixtures are strings only: no reverse shells, malware or external test connections are executed. An isolated on-host `--security-check` smoke test exercises the real macOS probes; it does not certify detection against live malware. Long-running service cadence, privilege-dependent visibility, timeout injection and actual kernel compromise remain unvalidated.

Host-specific probe results are kept locally and are not part of the public repository.
