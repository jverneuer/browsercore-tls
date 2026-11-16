# Security Policy

## Reporting a vulnerability

Please **do not report security vulnerabilities through public GitHub issues**.

Use GitHub's private vulnerability reporting instead:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the issue with as much detail as you can: affected package(s), reproduction, impact.

If you can't use the Security tab for some reason, ask in the [browsersmith Discussions](https://github.com/jverneuer/browsersmith/discussions) for a private channel — but the Security tab is always preferred and is monitored first.

## What belongs here

- Anything that leaks the *real* client (fingerprint disclosure of your actual TLS stack, headers, or environment while impersonating), exposes credentials (including proxy credentials), enables request smuggling or desync between layers, or otherwise compromises the security of applications built on this stack
- Vulnerabilities in the published npm packages (`@browsercore/*`, `browsersmith`)

## What does **not** belong here

- Fingerprint *parity* bugs ("our HTTP/2 SETTINGS differ from Chrome 130") — those are the core mission of the project; file a normal bug report
- Problems in sites you visit, proxies you use, or in code built on top of this stack

## Supported versions

Security fixes ship as new **patch releases** of the affected package(s) on npm. Older lines are not backported — please run the latest version.

## Responsible use

BrowserCore is a client-side HTTP/TLS/QUIC stack for legitimate automation, testing and research against systems you own or are authorized to test. Reports about evading protections of systems you have no authorization to test will not be accepted.
