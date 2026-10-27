---
version: alpha
name: Vaultwarden Access Direction Study
colors:
  background: "#f0f1f2"
  text: "#232a30"
  muted: "#616a73"
  border: "#d9dde0"
typography:
  body:
    fontFamily: system-ui
    fontSize: 14px
    lineHeight: 1.6
spacing:
  unit: 4px
---

## Overview
The user selected A — Quiet Instrument. App.jsx is a linked, synthetic interaction prototype of the native application family, not a security implementation. The A tokens below are authoritative; B is retained only as historical comparison data. macOS password approval with a Linux execution provider is the working baseline; other companion integrations and native biometrics are proposed implementation work.

## Colors
A / Quiet Instrument: surface #ffffff, text #242d34, secondary #65717b, divider #e5e9ed, accent #305f82, soft #f4f7f9.
B / Clear Ledger: surface #faf9f5, text #30352e, secondary #6a6d64, divider #dcded3, accent #49604c, soft #f0f1e9.
Dark A: surface #232a30, text #e7edf1, secondary #acb8c2, divider #3c454e, accent #557fa2, soft #2a333b.
Dark B: surface #282b26, text #e9eadf, secondary #b6b9ac, divider #44493d, accent #5b7860, soft #32372e.

## Typography
A uses system sans throughout with a 27px semibold operation heading. B uses a 31px regular Georgia heading and compact monospace numbered section labels. Body, controls, and facts remain sans-serif. Preview facts are compact at 12px; these are comparison specimens, not final large-text platform screens.

## Layout
Selected A: desktop sidebar and request master/detail, with content-first stacking at narrow widths. Mobile uses a single navigation stack and four bottom destinations. Shared 4px spacing unit, minimum 44px actions (48px in mobile review), 24–40px internal spacing. Platform selector provides macOS, Windows, Linux, iOS and Android layout/capability previews.

## Shapes
A: 12px window, 7px controls and contextual surface. B: 3px window and controls; ruled details and left-rule consequence summary.

## Components
The original RequestExample comparison is retained as inactive source history. The active App implements linked synthetic journeys with shared request/device records, explicit consequences, expiry messaging and password-next authorization. Approval, denial, pairing and revocation mutate in-memory prototype records only. Appearance switching is functional and keyboard accessible.
For Flutter, translate semantic surface/text/secondary/divider/accent/soft tokens to a ThemeExtension, typography to TextTheme, and shared request facts into a RequestReview component. Keep direction-specific style separate from security semantics.

## Do's and Don'ts
Keep requester, operation, execution host, target, credential reference, consequences, and validity visible. Never display secret values. Pairing, unlocking, and approving are distinct. Approval authorizes this request only. Do not imply Mac hosts protected execution or that integrated biometrics are available. Use selected direction A consistently. Do not reintroduce B into new screens.

## Selected system / Flutter handoff
Semantic tokens: surface #ffffff, text #242d34, secondary #65717b, divider #e5e9ed, accent #305f82, soft #f4f7f9. Dark: surface #232a30, text #e7edf1, secondary #acb8c2, divider #3c454e, accent #557fa2, soft #2a333b. Map to AccessTheme ThemeExtension; do not encode security state as a color alone.
Use system fonts (SF on Apple, Segoe UI on Windows, platform sans on Linux/Android). TextTheme: headline 28/34 semibold, title 20/28 semibold, body 15/24, label 13/20. Respect OS text scaling; never clamp critical facts. Spacing: 4, 8, 12, 16, 24, 32. Radius: controls 7, contextual surface 7, window 12. Minimum targets 44 desktop/iOS, 48 Android. Focus: 3px accent outline, 3px offset.
Stable components: AccessShell, RequestList, RequestReview, FactRow, StatusLabel, ConsequenceSummary, AuthorizationStep, PairingReview, DeviceRow, InstallationStep, ActivityList. All request surfaces consume shared records keyed by request ID; counts and history are derived. Authorization binds an immutable operation snapshot and request ID; unlocking is separate.
Desktop: sidebar plus master/detail, native window controls in production. iOS: navigation stack with bottom tabs, inline review then system authorization. Android: bottom navigation, system back and BiometricPrompt in the proposed integration. Windows Hello and Linux platform authorization require separate capability checks. Unsupported authorization offers the supported password route, not a fake biometric button.
Prototype scope: platform switch adapts layout and capability messaging; security actions and remote-device confirmations are explicit simulations. State is in memory and resets on reload. No secrets, API calls, OS prompts, discovery, or enrollment are implemented. First-launch, terminal repair, request state branches, pairing and revocation are navigable design specimens. Screen-reader status, semantic controls and focus destinations are included; real assistive-technology and native OS testing remain required.
