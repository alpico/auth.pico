# ap-auth-sign-reqwest

Middleware implementation of the [auth.pico](https://github.com/alpico/auth.pico/blob/main/specification.md) authorization scheme for [reqwest](https://crates.io/crates/reqwest) using [reqwest-middleware](https://crates.io/crates/reqwest-middleware).

Any sent message is automatically signed.

Included WASM support.

## Quickstart

```toml
# Cargo.toml

# ...

[dependencies]
ap-auth-sign-reqwest = { git = "https://github.com/alpico/auth.pico.git" }
ed25519-dalek = "2.0"
reqwest-middleware = "0.2"
```

```rust
use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Signature;
use reqwest_middleware::ClientBuilder;
use ap_auth_sign_reqwest::Signer;

let mut csprng = OsRng;
let signing_key = SigningKey::generate(&mut csprng);

let client = reqwest::Client::new();
let signer = Signer::new(signing_key, 60);
let client = ClientBuilder::new(client).with(signer).build();

// Use client like normal reqwest client
let res = client.get(RESOURCE_URL).send().await;
println!("{text:?}");
```
