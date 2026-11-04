# Security audit

Hardened fork of WebDriverAgent, for the owner to build in Xcode and let one assistant drive that owner's phone. Upstream code is used under its original BSD license and copyright headers. This document does not claim the upstream project reviewed these changes.

## Pin

Live tree: `appium/appium-ios` `main` at `4708fd53824e185312959e09335b1cd4995e9f45` (2026-10-20, a publish commit that did not change this package).

`packages/webdriveragent` tree id: `3e4d8adcba829e22749146f560ddaad2c3265877`.

Last commit that changed that tree: `9a31ba1944198c3a718165153394f53ab6b2b63f` (2026-10-19). Package version `16.16.3`.

The archived `appium/WebDriverAgent` repository was not imported. `appium-ios` added this package as a single-parent copy, so history before that copy is not in the monorepo. What this repo preserves is the eight commits `git subtree split` could recover for `packages/webdriveragent`, plus `LICENSE` and the copyright headers. Subtree-split SHAs differ from the monorepo SHAs. Authors, dates, and messages of those eight commits are unchanged.

Sibling monorepo packages (media proxy, RemoteXPC helpers, bundled codecs) were not imported.

No published GitHub security advisories were listed for `appium/WebDriverAgent` or `appium/appium-ios` at the time of the import. That is not a claim that the code is free of defects. `semgrep`, `gitleaks`, and `trufflehog` were not available in this environment and were not downloaded. `npm audit` was not run, because it contacts the registry.

Re-audit before moving the pin.

## Re-audit 2026-11-04

Compared this tree, then at `7489ea30d876fbd86b4260fad659459919871bb0`, with `appium/appium-ios` `main` at `afeb9cd03af16c7f3cea23633c82d715642c4e58` (2026-11-04, `chore: publish`). That monorepo tip is 65 commits ahead of the import pin `4708fd53824e185312959e09335b1cd4995e9f45`. Thirty-one files under `packages/webdriveragent` differ. Package version upstream is `16.17.9`; this tree is still `16.16.3`.

Those upstream edits are device-behavior and packaging changes (HID helpers, keyboard setting types, scroll direction case, an optional page-source filter, a new press-button listing route, Xcode 26 link lines, dropping `async-lock`, adding `axios`). None of them touch `FBHTTPServer`, `FBWebServer`, or `FBTCPSocket`. No upstream security fix was missing from this tree. The new press-button route was not imported.

GitHub listed no security advisories on `appium/appium-ios` or `appium/WebDriverAgent`. OSV returned no vulnerabilities for npm `appium-webdriveragent` `16.16.3`.

### Supply chain

Nothing in this checkout is a CocoaPods, Carthage, or Swift package manifest. There is no `package-lock.json`, `node_modules`, vendored archive, or linked third-party binary. `Scripts/fetch-prebuilt-wda.mjs` still prints a refusal and exits 1. `Scripts/build.sh` still refuses `bundle install` unless `WDA_ALLOW_BUNDLER=1`. A scan for private keys and common token prefixes found none.

`axios` is not a dependency of this tree. OSV currently reports 12 advisories against axios `1.18.1` (the version the monorepo bumped away from on 2026-10-30) and none against axios `1.21.0`. Representative ids: `GHSA-4hqw-qxg8-jxx2` / `CVE-2026-101900`, `GHSA-r4gj-5m52-g5wh` / `CVE-2026-101907`. They do not apply here because the package is not installed and the prebuilt download that used to call it is gone. Do not add axios back.

`semver` is a devDependency range `^7.3.7`. `GHSA-c2qf-rxjj-qqgw` / `CVE-2022-25883` affects semver `7.0.0`–`7.5.1` and is fixed in `7.5.2`. There is no lockfile and no `node_modules`, and the Xcode runner does not link it. Not an actionable device patch. Do not `npm install` as part of running the phone.

`Gemfile` pins fastlane `~> 2.229`. OSV returned no advisories for fastlane `2.229.0`. The gem is not installed by a normal Xcode build.

OSV returned no advisories for the declared versions of `asyncbox` `6.4.3`, `async-lock` `1.4.1`, `teen_process` `4.2.0`, `@appium/support` `7.2.6`, or `sinon` `22.0.0`. Those packages are not vendored.

### Controls that still hold

- `WDA_ENABLE` other than `1` returns from `startServing` without opening a socket.
- `validatedBindAddress` still rejects wildcards and any address that is not loopback or only on `lo`, `utun`, `tun`, `tap`, `ipsec`, or `tailscale`.
- `FBTCPSocket` still refuses a nil interface and does not call `nw_listener_create_with_port`. Peer-to-peer inclusion stays off.
- With `sessionRequestKey` set, every request still needs HMAC-SHA256, a fresh nonce, a 60-second timestamp, and an allowed `Host`. The runner sets that key before `listen`.
- Launch, pasteboard, location, lock, Siri, and Touch ID routes are still absent from `FBAllowedRouteKeys`. MJPEG is still not started.
- `/status` still reports a null address. The command log is still method, path without query, and accepted or rejected.

`FBHTTPServer` still admits a request when `sessionRequestKey` is nil. That path is what the framing unit tests use. `FBWebServer` does not listen without a token. Left as-is so those tests keep covering the parser.

### Fixes in this pass

No public CVE id applies to the three code fixes. They are defects in this fork.

| Severity | Finding | Change |
| --- | --- | --- |
| High | `POST /session` is allowlisted, and `handleCreateSession` launched `bundleId`, opened `initialUrl` even with no bundle id, and passed launch arguments and environment. Deleting the dedicated launch routes had not removed that path. `defaultAlertAction` on the same request armed later alert accepts that were not themselves logged commands. | The request is rejected before the current session is killed when any of those capabilities is present. The session is then created with a nil bundle id and a nil URL. `shouldTerminateApp` is forced off after configuration reset so session delete cannot terminate the foreground app. |
| Medium | The body is buffered before HMAC. The default limit was 1 GiB, and `MAX_HTTP_REQUEST_BODY_SIZE` could raise it, including through `longLongValue`. A full cache of that size is a local memory exhaustion from any process that can open the port. | Ceiling is 1 MiB. The environment variable can only select a smaller positive decimal. A non-numeric or overflowing value keeps the ceiling. The connection buffer cap no longer treats an overflowing addition as "no cap". |
| Low | `GET /wda/activeAppInfo` returned `processArguments.env` and `args`, which are the launch environment and arguments XCTest holds. | The response is pid, bundle id, and name. The helper that built the argument dictionary is removed. |

Screenshot, source, element, tap, swipe, type, and W3C actions are unchanged. A signed client can still drive the screen that is already open. It cannot ask this server to launch an app or open a URL.

Unit tests were not executed. This environment has no Xcode. `FBConfigurationTests` now expects the 1 MiB ceiling and the refusal to raise it. Run the unit-test target on a Mac before the device install.

## Verdict

**Safe to build, for the owner's own phone, when the launch follows [BUILD.md](BUILD.md).**

The listener stays off unless `WDA_ENABLE=1`. It then requires a new 32-character-or-longer token, binds only loopback or a private tunnel, signs every command with HMAC-SHA256, and stops itself on idle, on maximum lifetime, or after five rejected requests. Screenshot and source remain available to that one signed client. App launch, pasteboard, location, lock, and the MJPEG port are not registered.

This is not a general-purpose network service. A token stolen during a live session can still sign commands until that session ends. Details are in [RED_TEAM.md](RED_TEAM.md) and under Residual risks below.

The unit tests that encode the attacks have not been executed here. There is no Xcode in this environment. Run them on a Mac before the first device launch.

## What was reviewed

- The eight preserved commits and the pinned tree of `packages/webdriveragent`.
- Xcode build phases: no `PBXShellScriptBuildPhase`.
- Dependencies: no `Podfile`, `Cartfile`, `Package.swift`, or `.gitmodules`. No vendored `.a`, `.dylib`, `.framework`, or `.zip`.
- `Scripts/fetch-prebuilt-wda.mjs` (upstream downloaded release zips with axios). `Scripts/build.sh` (fastlane `bundle install`). `lib/` (the Node launcher shells out to `xcodebuild` and related tools if something invokes it).
- The HTTP stack: `FBHTTPServer`, `FBTCPSocket` (`Network.framework`), route registration, `/status`, MJPEG, and the runner entry in `UITestingUITests`.
- A search for `NSNetService`, Bonjour, `dlopen`, and outbound URL sessions. `dlopen` in this tree opens system frameworks and the on-device text-input preferences, not a downloaded binary. Private headers under `PrivateHeaders` are generated XCTest interfaces. Nothing in this package calls the telemetry protocol they declare.
- `DEVELOPMENT_TEAM` is an empty string. Shared bundle ids are the public `com.facebook.*` ids.

## Findings and what changed

| Severity | Finding | Change |
| --- | --- | --- |
| High | Listener bound every interface and had no authentication. | Default bind `127.0.0.1`. Any other address must exist only on `lo*`, `utun*`, `tun*`, `tap*`, `ipsec*`, or `tailscale*`. Wildcard and Wi-Fi addresses refuse to listen. HMAC required on every request when the runner is enabled. |
| High | A captured request or a long-lived token could be reused. | Per-launch token, minimum 32 characters. SHA-256 of the token stored after a successful listen; the same token is refused next time. Timestamp window of 60 seconds and a one-time nonce. The nonce cache does not evict a nonce that is still inside the window. |
| High | The runner stayed up for as long as the XCTest stayed up. | Idle timer default 120 seconds (clamped 30–900). Maximum lifetime default 1800 seconds (clamped 60–3600). Neither can be set to off. Five rejected requests stop the listener. |
| High | Routes included app launch, pasteboard, location, lock, Siri, Touch ID, and a raw MJPEG socket on port 9100 with no place to put an HMAC. | Those routes are not registered. MJPEG is not started. `FBTCPSocket` refuses to listen without an explicit address. Port 9100 stays closed. |
| High | `Scripts/fetch-prebuilt-wda.mjs` downloaded a prebuilt runner from GitHub releases. | The script prints a refusal and exits 1. axios was removed. `package.json` is `private`. |
| Medium | `Access-Control-Allow-Origin: *` and no `Host` check. A browser pointed at the phone by DNS rebinding could read responses. | CORS header removed. `Cache-Control: no-store`. With a key set, `Host` must be loopback or the bind address. |
| Medium | Duplicate `Content-Length` / `Transfer-Encoding`, and last-wins `Authorization`, are request-smuggling primitives. The request line accepted fewer than three tokens. | Duplicates of the framing headers and of `Authorization`, `Host`, `X-WDA-Timestamp`, and `X-WDA-Nonce` close the connection. Any `Transfer-Encoding` is rejected. The request line must be `METHOD TARGET HTTP/1.0` or `HTTP/1.1`. The target must be origin-form: one leading slash, no `..`, no `\`, no `%2e` / `%2f` / `%5c` / `%00`. |
| Medium | Logs and `/status` exposed the Wi-Fi address, and verbose logging printed typed text. | `/status` address is null. Command log is method, path without query, and accepted or rejected. Route arguments are not logged. |
| Medium | `Scripts/build.sh` ran `bundle install` from RubyGems when the fastlane path was used. | That path exits 1 unless `WDA_ALLOW_BUNDLER=1`. |
| Low | Peer-to-peer / AWDL was left at the Network.framework default, and nothing advertised Bonjour. | `nw_parameters_set_include_peer_to_peer(..., false)`. No Bonjour API is called. |
| Low | Upstream `package.json` said Apache-2.0 while `LICENSE` is BSD-3-Clause. | `license` set to `BSD-3-Clause` so it matches `LICENSE`. |

`WDA_ENABLE` defaults to off. A missing flag does not fail the test; it opens no socket. A bad token or a bad bind calls `webServer:didFailToStartWithError:`, and the runner turns that into a test failure.

## Controls

- Bind: loopback, or a private tunnel address confirmed with `getifaddrs`.
- Authentication: HMAC-SHA256. Canonical string `v1\nMETHOD\nPATHANDQUERY\nTIMESTAMP\nNONCE\nhex(sha256(body))`. Headers `X-WDA-Timestamp`, `X-WDA-Nonce`, `Authorization: WDA-HMAC <hex>`.
- Rotation: token compared by its hash with the previous launch. The token is not stored.
- Lifetime: idle and maximum timers, plus a five-rejection stop.
- Endpoints: explicit allowlist. Screenshot, source, element, tap, swipe, type, and W3C actions stay. Launch, pasteboard, location, and the rest do not.
- Audit log: one line per accepted or rejected command, without body or query.

## Residual risks

- A token stolen while the runner is up can forge requests until idle timeout, maximum lifetime, or the fifth rejection. mTLS is not in this build. See [RED_TEAM.md](RED_TEAM.md).
- Another app on the same phone can connect to loopback. It still cannot sign a request without the token, and it cannot read this app's environment from a different sandbox.
- The token lives in the process environment. Anything that can debug this process can read it. Do not put it in a shared scheme or in this repository.
- The Node launcher under `lib/` is upstream integration code. It is not the hardened control plane. Do not `npm install` or invoke it as part of running the phone.
- `pymobiledevice3` is an external helper. A forward bound to `0.0.0.0`, or lockdown Wi-Fi, would undo the bind restriction on the Mac side. [BUILD.md](BUILD.md) tells the operator not to do that. This repo does not start the helper.
- The allowlist still includes screenshot and source. That is intentional for the assistant. Those routes are useless without a valid HMAC.
- Moving the pin, or running `bundle install` / a prebuilt download, needs a new audit.
- Unit tests and a device check have not been run here.

## Supply chain

Do not fetch a prebuilt WebDriverAgent. Build the Xcode project you have checked out at this pin. The fetch script and the fastlane gem install are refused by default so a habitual `npm run` or `./Scripts/build.sh` does not pull new code.
