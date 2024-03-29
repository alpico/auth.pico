use reqwest::{header::HeaderValue, Request, Response};
use reqwest_middleware::{Middleware, Next};
use task_local_extensions::Extensions;

/// Simple struture for saving configuration options on how to sign the messages.
pub struct Signer {
    /// The private key with which each message is signed
    privkey: ed25519_dalek::SigningKey,

    /// The key to use for verification.
    key: u32,

    /// The duration in seconds for how long each message should be valid for.
    duration: u64,

    /// A tolerance in seconds which accounts for mismatches between client and sever time.
    time_tolerance: u64,

    /// Whether to hash over the body as well. This should be turned off for file uploads.
    body: bool,
}

impl Signer {
    /// Construct a new signer. Sets [Self::time_tolerance] to `duration / 10`.
    pub fn new(privkey: ed25519_dalek::SigningKey, key: u32, duration: u64, body: bool) -> Self {
        Self {
            privkey,
            duration,
            key,
            time_tolerance: duration.div_ceil(10),
            body,
        }
    }

    /// Construct a new signer.
    pub fn new_with_tolerance(
        privkey: ed25519_dalek::SigningKey,
        key: u32,
        duration: u64,
        time_tolerance: u64,
        body: bool,
    ) -> Self {
        Self {
            privkey,
            key,
            duration,
            time_tolerance,
            body,
        }
    }


}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for Signer {
    async fn handle(
        &self,
        mut req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let headers = req
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_bytes()));
        let body = if self.body {
            req.body().and_then(|b| b.as_bytes())
        } else {
            None
        };
        let auth = ap_auth_sign::sign(
            headers,
            req.method().as_str(),
            req.url().path(),
            body,
            self.key,
            self.duration,
            self.time_tolerance,
            &self.privkey,
        )
        .map_err(|e| reqwest_middleware::Error::Middleware(anyhow::Error::new(e)))?;

        // Errors if there isn't only ASCII in the value
        // If the user inserts an invalid header name into the request, it will error then
        // and all headers are valid when we get here.
        // The sig header is URL safe base64 so there is no issue there
        req.headers_mut()
            .insert("authorization", HeaderValue::from_str(&auth).unwrap());

        next.run(req, extensions).await
    }
}
