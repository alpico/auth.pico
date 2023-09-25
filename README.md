# The alpico Authentication Scheme v0.2

#### Using ed25519 signatures for authenticating HTTP requests

![auth.pico logo](.logo.png)

This repo covers the [specification of auth.pico](specification.md) as well as a few reference implementations:

- Python, using `requests`
- Rust
  - Signing
    - [Generic signing code](rust/ap-auth-sign/)
    - [Signing code using `reqwest`](rust/ap-auth-sign-reqwest/)
  - Verification
    - [Generic verification code](rust/ap-auth-verify/)
