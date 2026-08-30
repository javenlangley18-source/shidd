# Privacy Shield for iPhone

Privacy Shield is a defensive iOS privacy app for auditing app permissions and
blocking known tracking domains locally. It does not inspect, modify, or break
into third-party apps.

## Planned iOS app

- **Permission dashboard:** show this app's sensitive capability status and open
	Apple's privacy settings. iOS does not let third-party apps enumerate another
	app's permission states.
- **Tracker filter:** a Packet Tunnel or DNS Proxy Network Extension evaluates
	hostnames against a bundled blocklist without sending browsing data to a
	server.
- **Privacy-first defaults:** no account, no remote analytics, and no collection
	of browsing history.

The iOS shell requires Xcode on macOS, an Apple Developer signing identity, and
Network Extension entitlements. The reusable privacy rules and tests in this
repository can be built on Linux with Swift.

## Build the core

```sh
swift test
```

## Xcode integration

Create an iOS SwiftUI app and add the `PrivacyShieldCore` package target. Add a
Network Extension target (`DNS Proxy Provider` or `Packet Tunnel Provider`),
request the appropriate entitlement from Apple, and pass each queried hostname
to `TrackerBlocker.shouldBlock(host:)`. The extension must fail open for
malformed input and keep all decisions local. The user must explicitly approve
the VPN configuration in iOS Settings.