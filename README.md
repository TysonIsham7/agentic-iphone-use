# WebDriverAgent (hardened fork)

This tree is a security-hardened fork of [WebDriverAgent](https://github.com/appium/appium-ios/tree/main/packages/webdriveragent), the XCTest server used by [Appium](https://appium.io) to drive an iOS device. The original work is by Facebook and the Appium contributors. Their copyright headers and the BSD license in `LICENSE` are unchanged. This copy is not a new implementation and it is not affiliated with those projects.

The pinned upstream commit, the audit, and how to build are in [SECURITY_AUDIT.md](SECURITY_AUDIT.md), [RED_TEAM.md](RED_TEAM.md), and [BUILD.md](BUILD.md).

The listener is off unless `WDA_ENABLE=1`. It binds only to loopback or a private tunnel address, and every request must carry a fresh HMAC made with a token that changes on every launch. Do not start it from the upstream "open the project and send requests" instructions. Those instructions describe an unauthenticated server.

`package.json` is marked private. `npm run fetch-prebuilt-wda` refuses to download anything. Build the runner yourself in Xcode.
