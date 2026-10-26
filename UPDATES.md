# GitHub app updates

Source: https://github.com/fazekasm/CorsoShield

The installed frontend uses Sparkle 2.10.1. It checks daily while the frontend is running and offers an explicit Check for app updates action. Closing its window normally leaves the app running; quitting the frontend stops its update checks. The separate scan service does not run Sparkle. Update installation requires confirmation; this build does not silently replace the app while the frontend is closed.

Feed: https://github.com/fazekasm/CorsoShield/releases/latest/download/appcast.xml

Each release contains a universal app ZIP and signed appcast.xml. HTTPS, pinned Ed25519 signatures, and pre-extraction archive verification are required. Both feed signing and archive signing are enabled. Only releases prepared with the local private key can be installed. Updates are complete packaged applications; no git pull, arbitrary repository scripts or code execution from the default branch occurs. Sparkle handles version comparisons, extraction and application replacement. No system profiling is enabled.

The application is currently ad-hoc signed. Ed25519 archive signatures authenticate updates but do not provide Apple Developer ID identity or notarization. Permission persistence, Gatekeeper behavior and the full install/relaunch flow require desktop testing. The service handoff records a resume marker, stops the launch agent before installation, and re-enables it on relaunch or an aborted update. An interrupted install can leave protection paused until the frontend is launched again. Check the service state afterward.

## Publishing a later version

1. Review and test changes. Increase both `version` and the integer `build` in `Config/updates.json`; never reuse a build number or release tag. Add `release-notes/VERSION.md`.
2. Commit and push to main; confirm the macOS build workflow passes.
3. Run `bash scripts/prepare-release.sh` on the signing Mac. It builds universal binaries, runs fixture/safety tests, creates the app-only ZIP with symlinks preserved, signs its archive and feed, verifies the pinned public key, and checks tamper rejection.
4. Review staged files under `releases/vVERSION/` and run `bash scripts/publish-release.sh`. This uploads both assets to a draft release before publishing it as latest. Do not modify either asset after signing. Do not mark an unsigned/testing release as latest.

The signing account is `local.corso.shield.updates` in the login Keychain. The private key is never placed in this repository, exported into the workspace, or sent to CI. The public key is intentionally committed. Keep a secure Keychain backup; loss of this key can require a manual reinstall to trust a replacement. Do not regenerate it casually. CI can build/test untrusted pull requests but has read-only repository permissions and cannot sign or publish app updates.

FreshClam continues to update virus signatures daily independently. Updating the ClamAV engine still requires Homebrew. Windows updater delivery remains future work.

Implementation reference: https://sparkle-project.org/documentation/
