use base64::engine::general_purpose as b64;
use base64::Engine;
use ed25519_dalek::Signer;

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// Communicates errors which arise while signing a message.
#[derive(Debug)]
pub enum Error {
    Time,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Time => write!(f, "Invalid timestamp"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// Taken from https://github.com/rust-lang/rust/issues/48564#issuecomment-505114709
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

#[cfg(target_arch = "wasm32")]
fn now() -> Result<u64> {
    Ok((date_now() / 1000.0) as u64)
}

#[cfg(not(target_arch = "wasm32"))]
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Error::Time)
        .map(|ms| ms.as_secs())
}

/// Generates the `authorization` header for an HTTP request according to the [auth.pico](https://github.com/alpico/auth.pico) authorization scheme.
///
/// The `headers` are passed as an iterator over tuples of key-value pairs.
/// `method`, `path` and `body` are of the HTTP request.
///
/// `duration`, `time_tolerance` and `privkey` are according to `[auth.pico](https://github.com/alpico/auth.pico).
///
/// The resulting [String] should be used as the `authorization` header in the request.
pub fn sign<'a>(
    headers: impl Iterator<Item = (&'a str, &'a [u8])>,
    method: &'a str,
    path: &'a str,
    body: Option<&'a [u8]>,
    duration: u64,
    time_tolerance: u64,
    privkey: &'a ed25519_dalek::SigningKey,
) -> Result<String> {
    // TODO UTC time
    let start = now()? - time_tolerance;
    let time = format!("{start}+{}", duration + time_tolerance);

    let mut headers_str = String::new();
    let mut header_vals: Vec<u8> = format!("{method}\n{path}\n").bytes().collect();

    // Add further headers and their values
    for (key, value) in headers {
        headers_str.push_str(&format!("+{key}"));
        header_vals.extend(value);
        header_vals.push(b'\n');
    }
    let mut auth = format!("alpico time={time}");
    if !headers_str.is_empty() {
        auth.push_str(&format!(", add=-method+-path{headers_str}"))
    }
    let mut message: Vec<u8> = auth.bytes().collect();
    message.push(b'\n');
    message.extend(header_vals);
    if let Some(b) = body {
        message.extend(b)
    };

    let signature = privkey.sign(&message);
    let signature = b64::URL_SAFE_NO_PAD.encode(signature.to_bytes());
    auth.push_str(&format!(", sig={signature}"));
    Ok(auth)
}
