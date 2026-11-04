# Red team

Threat model: exactly one client may control the phone. That client is the owner's assistant, connecting from the owner's Mac over a private path (USB RemoteXPC, or a tunnel such as Tailscale). Everyone else must fail, including a neighbor on the same Wi-Fi, a different app on the phone, and anyone who later obtains a token that was already used.

## How the attacks were run

This environment has no Xcode and no iPhone. The attacks below were traced through the listener source (`FBWebServer`, `FBHTTPServer`, `FBTCPSocket`) and, where a socket can express them, written as XCTest cases in `WebDriverAgentTests/UnitTests/FBHTTPServerTests.m`. They were not executed against a running device, and no port scan of a phone was performed. A pass of those unit tests on a Mac is still required before the first real launch.

Mutual TLS was considered and not implemented. The HTTP stack calls `nw_parameters_create_secure_tcp` with TLS disabled, and shipping a client certificate would mean putting key material in the repo or on the device. The control that was implemented instead is HMAC-SHA256 with a per-launch token, a 60-second timestamp, a one-time nonce, an idle timeout, and a hard maximum lifetime.

## Attacks

### Unauthenticated request

- Tried: `GET /framing/ping` with no `Authorization` header, in `testSignedRequestIsAcceptedAndWeakerCredentialsAreNot`. The production server sets `sessionRequestKey` before it listens.
- Result: `401`, body `unauthorized`, route not run. `WWW-Authenticate` is `WDA-HMAC`. There is no `Access-Control-Allow-Origin`.
- Fix: `FBHTTPServer` admits a request only after HMAC when a key is set. `WDA_ENABLE` must be `1` or `startServing` returns without a socket.

### Bearer token and query token

- Tried: `Authorization: Bearer <key>` and `?access_token=<key>`, same test.
- Result: both `401`. The key is not accepted as a password header, and the query string is not an authenticator. The query is stripped before the command is logged.
- Fix: only `Authorization: WDA-HMAC <64 lowercase hex>` matches. The signature covers method, raw target, timestamp, nonce, and the body hash.

### Replayed request

- Tried: the same signed request sent twice, in `testReplayedSignedRequestIsRejected`.
- Result: the first response is the route body. The second is `401` and the route does not run again.
- Fix: after a valid signature the nonce is stored until the timestamp window has passed. A later copy of that nonce is rejected. The cache does not drop a nonce that is still inside the window, so filling the cache cannot revive an old request. The window is 60 seconds.

### Stale or future timestamp

- Tried: a correctly signed request whose timestamp is `1000000000`, in `testStaleTimestampAndForeignHostAndBadTargetAreRejected`.
- Result: `401`. The nonce is not stored, so the stale request cannot be kept as a way to burn a nonce.
- Fix: `abs(now - timestamp) <= 60`. The comparison runs after the HMAC so a wrong timestamp does not skip the signature work.

### Token brute force

- Tried: source trace of the failure counter in `FBWebServer`, plus the `401` path above. No online guessing run was performed.
- Result: each rejected request increments a counter. At five, the listener stops and the run loop exits. The token must be 32 to 128 characters. The comparison of the signature is constant-time. The body of every `401` is the same string, so the response is not an oracle for which check failed.
- Fix: `rejectedCommandHandler` and `FBRejectedRequestLimit`. A short token never starts the listener.

### Token reused from the previous launch

- Tried: source trace of `validatedAuthToken`. Not executed as a process, because it needs the XCTest host.
- Result: the SHA-256 of the token is compared with `FBHardenedLaunchTokenSHA256` in `NSUserDefaults`. An equal hash refuses to listen. The token and the hash are not logged. The hash is written only after the socket is up, so a failed bind does not burn a new token.
- Fix: that check. A token stolen from an old shell history or an old scheme does not work on the next start.

### Token leak through logs, status, and route dumps

- Tried: source trace of `FBLogger` call sites on the request path, `FBRouteRequest` `description`, and `/status`.
- Result: the route handler used to verbose-log the URL, parameters, and arguments, which include typed text. `/status` used to report a Wi-Fi address. Startup used to log that address.
- Fix: the verbose dump is gone. `description` prints the path only. `/status` reports a null address. Startup logs the bind address and port, not the token, the signature, the body, or the query. Command lines are `command result=accepted|rejected method=... path=...`.

### Same-Wi-Fi client, wildcard bind, port 8100 and 9100

- Tried: source trace of `validatedBindAddress`, `FBTCPSocket` `startWithError`, and `startServing`. No LAN scan was run.
- Result: `0.0.0.0`, `::`, and any address that is not loopback or solely on a private tunnel is rejected before `nw_listener` is created. `USE_IP` of a Wi-Fi address fails the test. The MJPEG broadcaster is never constructed, so nothing binds port 9100. `FBTCPSocket` refuses a nil interface, including the old "listen on every interface" branch. The unit test `testStartWithoutBindAddressFails` covers the HTTP server's half of that refusal.
- Fix: loopback by default; `getifaddrs` for any other address; peer-to-peer inclusion turned off on the `nw_parameters`.

### Bonjour / mDNS

- Tried: search of the tree for `NSNetService`, `bonjour`, `mdns`, and `nw_listener` advertise calls.
- Result: no service is registered. The only listener is the HTTP socket, and `nw_parameters_set_include_peer_to_peer` is false, so it is not offered on AWDL.
- Fix: those two facts. There is no advertisement to disable beyond refusing to add one.

### CORS and DNS rebinding

- Tried: `Host: rebind.example` on an otherwise signed request, and a request with no `Host`, in `testStaleTimestampAndForeignHostAndBadTargetAreRejected`. Also a source trace for `Access-Control-Allow-Origin`.
- Result: foreign and missing `Host` values are `401` and the route does not run. Responses set `Cache-Control: no-store` and do not set a CORS origin.
- Fix: when a key is set, `Host` must be `127.0.0.1`, `localhost`, `::1`, or the bind address, optional numeric port. Duplicate `Host` is a `400` and the connection closes.

### Request smuggling

- Tried: the existing framing tests (non-numeric and duplicate `Content-Length`, whitespace before the colon, a header line without a colon, `Transfer-Encoding`, oversized header blocks) plus `testDuplicateAuthorizationAndAbsoluteFormAreRejected`.
- Result: those shapes are `400` or `501`, the connection closes, and the smuggled second request is not dispatched. An absolute-form request line (`GET http://...`) is `400`. A request line that is not exactly three tokens, or not `HTTP/1.0` / `HTTP/1.1`, is `400`.
- Fix: duplicate `Content-Length`, `Transfer-Encoding`, `Authorization`, `Host`, `X-WDA-Timestamp`, and `X-WDA-Nonce` are rejected. Any `Transfer-Encoding` is rejected because there is no decoder. The signature covers the exact bytes of the body, so a body that survives framing still fails HMAC if it was swapped (`testSignatureCoversMethodTargetAndBody`).

### Path and endpoint abuse

- Tried: signed `GET /framing/%2e%2e/ping` in the host test, and a source trace of `FBAllowedRouteKeys` against `FBSessionCommands`, `FBCustomCommands`, and the screenshot / source handlers.
- Result: `%2e`, `%2f`, `%5c`, `%00`, a backslash, a second leading slash, and `..` never reach a route. When a key is set the response is `401`. App launch, activate, terminate, list, URL open, home, lock, pasteboard, location, Siri, Touch ID, video, and device info are not registered. `GET /screenshot` and `GET /source` stay registered because screen reading is the point of the assistant, and they require a valid HMAC like every other route. `/health` and `/wda/shutdown` also require HMAC; they are not open probes.
- Fix: the allowlist in `FBWebServer`. Fewer than 15 matching handlers refuses to listen, so a bad allowlist fails closed. `FBUnknownCommands` is not registered.
- Follow-up, 2026-11-04: `POST /session` stayed on the allowlist and `handleCreateSession` still launched `bundleId`, opened `initialUrl` with no bundle id, and could arm `defaultAlertAction`. A signed client could do that without calling the removed routes. Those capabilities are now rejected before the current session is torn down, and the created session is not given an application under test. `GET /wda/activeAppInfo` no longer returns launch arguments or environment.

### Malicious app on the phone

- Tried: source trace of the bind and of iOS loopback behavior. Not run on a device.
- Result: another app on the phone can open `127.0.0.1:8100`. It cannot read this process's environment or its `NSUserDefaults` from a different sandbox. Without the launch token it cannot produce a signature. Five failures stop the listener.
- Fix: HMAC plus the failure limit. Loopback is not, by itself, a barrier between apps on one phone. That is why the token exists.

### Stolen token

- Tried: source trace of what a captured token allows.
- Result: a token from a previous launch is refused. A token stolen while that launch is still running can sign new requests until the idle timeout (default 120 seconds), the maximum lifetime (default 1800 seconds), or the fifth rejection, whichever comes first. There is no client certificate to steal as well.
- Fix: rotation, short lifetime, and idle shutdown. This is the residual accepted in `SECURITY_AUDIT.md`. mTLS was not added, for the reason at the top of this file.

### Runner left on

- Tried: source trace of `startServing` after the socket is up.
- Result: an `NSTimer` on the main run loop fires after the idle interval with no accepted command, and another fires at the maximum lifetime. Both call `stopServing`, which closes the socket and ends the test run loop. Setting the environment variables to `0` or to a huge number does not keep the process up; the values are clamped.
- Fix: `WDA_IDLE_TIMEOUT` and `WDA_MAX_LIFETIME`.

## What still needs a Mac

Run the `WebDriverAgentTests` unit target in Xcode. Then, on a device you own, confirm with the unshared scheme that:

- omitting `WDA_ENABLE` opens nothing
- a second launch with the same token fails before listen
- `USE_IP` set to the phone's Wi-Fi address fails before listen
- from another machine on the Wi-Fi, ports 8100 and 9100 are closed
- a signed request from the Mac over the USB forward succeeds, and the same bytes sent again do not
