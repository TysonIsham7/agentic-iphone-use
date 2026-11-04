# Build and run

Build this tree yourself in Xcode, on the Mac that will talk to the phone. Nothing in this repository is a signing identity, a device name, a token, or a team id. `DEVELOPMENT_TEAM` in the shared project is empty. `xcuserdata` is gitignored. Put the team and the launch variables in an unshared scheme so they stay on that Mac.

## What you are building

WebDriverAgentRunner is an XCTest bundle. Product > Test starts `UITestingUITests` `testRunner`, which is what opens the HTTP listener. A normal app launch does not.

On current iOS, `xcrun devicectl device process launch` does not start that HTTP listener. Xcode Product > Test, `xcodebuild test`, or a RemoteXPC XCTest helper does.

## One-time Xcode setup

1. Open `WebDriverAgent.xcodeproj`.
2. Select the WebDriverAgentRunner target and set the signing team locally. Leave the shared project file unchanged.
3. Duplicate the shared scheme if you need different settings, and uncheck Shared. Do not commit the scheme.
4. In that unshared scheme, set these environment variables on the Test action:

| Variable | Value |
| --- | --- |
| `WDA_ENABLE` | `1` |
| `WDA_AUTH_TOKEN` | A new random value, 32 to 128 characters, with no spaces. Generate a different one every time you run the test. |
| `USE_IP` | Leave unset, or set `127.0.0.1`. Set a tunnel address only when that address exists only on a `utun`, `tun`, `tap`, `ipsec`, or `tailscale` interface. |
| `WDA_IDLE_TIMEOUT` | Optional. Whole seconds. Default 120. Values below 30 become 30 and values above 900 become 900. `0` does not disable it. |
| `WDA_MAX_LIFETIME` | Optional. Whole seconds. Default 1800. Clamped to 60–3600. `0` does not disable it. |

`WDA_ENABLE` unset, or set to anything other than `1`, opens no port and the test returns. A token shorter than 32 characters, a token that matches the previous launch, or a Wi-Fi / wildcard bind address fails the test before the socket opens. The process stores only the SHA-256 of the token, in `NSUserDefaults`, so the next launch can see that the same token was reused. The token itself is not written to the log, the repository, or the response.

The listener also stops after five rejected requests, after the idle timer, or after the maximum lifetime. Stop the test in Xcode when you are done; do not leave the runner up.

`POST /session` creates a session for the screen that is already open. It does not launch an app or open a URL. Omit `bundleId`, `initialUrl`, `arguments`, `environment`, and `defaultAlertAction`. Sending any of those is a session-not-created error, and the previous session is left running. Request bodies are capped at 1 MiB. `MAX_HTTP_REQUEST_BODY_SIZE` can only lower that cap.

## Signing and the bundle id

Sign with your own Apple ID from Xcode. The stock bundle id in this project is the public upstream id `com.facebook.WebDriverAgentRunner`. You may change it locally if your team already uses another id. Do not put that local id, the team id, or the device name into a commit.

## Reaching the phone

Prefer a USB or RemoteXPC path that lands on the phone's loopback, then connect from the Mac to `127.0.0.1` only.

`pymobiledevice3` is a tunnel helper. It is not vendored, not imported, and not started by this project. Install it yourself if you use it. Two public entry points matter:

- Start the XCTest on a device where `devicectl` will not bring up the HTTP server:

  `python3 -m pymobiledevice3 developer dvt xcuitest com.facebook.WebDriverAgentRunner.xctrunner`

  Pass `WDA_ENABLE` and a new `WDA_AUTH_TOKEN` with the helper's `--env key=value` form. Do not put the token in a file in this repo. Shell history will keep it if you type it; clear that history afterward.

- Forward the phone port to the Mac's loopback:

  `python3 -m pymobiledevice3 usbmux forward --host 127.0.0.1 8100 8100`

  The helper's own default bind is loopback. Do not pass `0.0.0.0`. Do not enable lockdown Wi-Fi connections, and do not add a Wi-Fi tunnel flag.

If the assistant reaches the phone over Tailscale, set `USE_IP` to the phone's tunnel address and no other address. The process checks `getifaddrs` and refuses to listen when that address is also on `en*`, `pdp*`, `awdl*`, `bridge*`, or any other shared interface.

Port 9100 is not opened. The MJPEG broadcaster is not started.

## Signing requests

Every request needs three headers. The method in the signature is uppercase. `PATHANDQUERY` is the raw request target, including the query string if there is one. The body hash is lowercase hex SHA-256 of the raw body. The empty-body hash is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

```text
canonical = v1 \n METHOD \n PATHANDQUERY \n TIMESTAMP \n NONCE \n BODY_SHA256
Authorization: WDA-HMAC <lowercase hex HMAC-SHA256 of canonical, key = UTF-8 token>
X-WDA-Timestamp: <unix seconds, within 60 seconds of the phone>
X-WDA-Nonce: <16 to 64 letters or digits, never reused for this launch>
Host: 127.0.0.1   (or localhost, ::1, or the tunnel address you bound)
```

A query parameter, a `Bearer` header, or a second copy of any of those headers does not authenticate. The response to a bad request is `401` with the body `unauthorized`. The same nonce is rejected. A timestamp more than 60 seconds off is rejected.

`Host` must be `127.0.0.1`, `localhost`, `::1`, or the exact bind address, with an optional numeric port. That is what stops a browser on another name from treating the phone as its own origin.

Do not log the token, the signature, the body, or the query string. The server's own command log is `method`, the path with the query removed, and `accepted` or `rejected`.

## What not to run

- `npm install`, `npm run bundle`, and `npm run fetch-prebuilt-wda`. The fetch script exits immediately and does not download a prebuilt runner. The Node launcher under `lib/` is the upstream Appium integration and is not part of the Xcode build.
- `Scripts/build.sh` fastlane path. It refuses `bundle install` unless `WDA_ALLOW_BUNDLER=1`. Leave that unset.
- A shared scheme that contains `WDA_AUTH_TOKEN`.

## Tests

`WebDriverAgentTests/UnitTests/FBHTTPServerTests.m` covers framing, HMAC, replay, host, and path checks. Run the unit-test target from Xcode on a Mac. This repository was prepared on a machine without Xcode, so those tests have not been executed here.
