# Changelog

All notable changes to this project will be documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] — 2025-10-23

### Added
- `verifyCodeAndGetTimeSlice()` — returns the matched time-slice for replay protection.
- `generateRecoveryCodes()` — backup 2FA codes (`XXXX-XXXXX`).
- `isValidSecret()` and `normalizeSecret()` — validate/sanitize user input.
- `getTimeSlice()` and `getTimeRemaining()` — for UI countdown.
- 4-tier QR fallback: vietqr.cc → goqr.me → QuickChart → Google Chart.
- `renderQRCodeImg()` with client-side `onerror` chain.
- `VERSION`, `AUTHOR`, `WEBSITE` constants.
- GitHub Actions test matrix (PHP 7.4 – 8.3).

### Changed
- Default secret length: 16 → **32 chars** (160-bit, RFC 6238 recommendation).
- QR provisioning URI now follows Google Key URI Format fully
  (label `issuer:account`, `algorithm`, `digits`, `period`).
- `base32Decode()` is now `public` and throws `InvalidArgumentException`
  on malformed input (still caught internally by `verifyCode()`).
- Discrepancy capped at ±10 blocks (DoS guard).

### Fixed
- `base32Decode()` no longer silently produces garbage keys on invalid chars.
- `hotp()` uses strict int arithmetic (`1000000` instead of `pow(10, 6)` float).
- `verifyCode()` no longer leaks timing through short-circuit `hash_equals`.

## [2.0.0] — 2025-10-23

### Changed
- Rewrote for robustness: strict Base32, single secret decode, constant-time verify.

## [1.0.0] — 2024

### Added
- Initial minimal TOTP implementation.
