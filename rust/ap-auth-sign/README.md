# ap-auth-sign

Provides a library for signing HTTP requests according to the [auth.pico](https://github.com/alpico/auth.pico/blob/main/specification.md) authorization scheme.

The crate features a single function `sign` which accepts parameters of HTTP requests and uses these to generate the value of the `authorization` HTTP header.

If you are using [reqwest](https://crates.io/crates/reqwest) or [ureq](https://crates.io/crates/ureq) consider using our ready middlewares respectively.
