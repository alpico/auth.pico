# The alpico Authentication Scheme v0.2
#### Using ed25519 signatures for authenticating HTTP requests

![auth.pico logo](.logo.png)

Every request to the alpico backend needs to be authenticated by the client.  Traditional password-based schemes like
HTTP [Basic](//tools.ietf.org/html/rfc7617) or [Digest](//tools.ietf.org/html/rfc7616) Authentication are too weak for a
modern API.  Cryptographically stronger approaches like [HMAC](//en.wikipedia.org/wiki/HMAC) require a shared secret,
that must be kept secure on both ends, while still be usable frequently.  This seems to be a problem hard to solve for a
distributed backend system.

We therefore employ a public-key signature scheme, where the private key never leaves the device it was generated on.
With a previous registered public key, the backend can still verify, that a certain request comes from a particular user
and that the request parameters were not tampered with.

We have chosen to build upon ed25519 signatures, since they are:

- [fast to calculate](//ed25519.cr.yp.to),
- easier to implement securely than [RSA](//blog.trailofbits.com/2019/07/08/fuck-rsa/), and
- [widely supported](//ianix.com/pub/ed25519-deployment.html).


A good description of ed25519 can be found in [RFC 8032](//tools.ietf.org/html/rfc8032).  This document even includes
example code and test vectors.  It is, however, strongly advised to reuse an existing library like
[libsodium](//libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures), as subtle bugs can easily
undermine the whole security of the system.


## 2. Authorization Header

We define a new HTTP authorization method with the following format:

    alpico time=START+DURATION, key=NAME, add=FIELDS, sig=SIGNATURE


The `alpico` part distinguish it from other authorization methods like Basic authentication. This is followed by
comma-separated list of parameters.

According to [RFC735](//tools.ietf.org/html/rfc7235#appendix-C), there can be white-space around the comma, but there
must be none between the key-value pairs.


### 2.1 Limiting the validity: `time`

The mandatory `time` parameter defines the duration the signature is valid.  The value `START` is given as a Unix
timestamp.  These are seconds since 1970 in the UTC time zone.  The `DURATION` is indicated in seconds as well.  An
example would be:

    time=1700000000+60

This means this signature is not valid before `Tue Nov 14 23:13:20 2023` and not valid after `Tue Nov 14 23:14:19 2023`.

The duration should be carefully chosen by the client according to the use case.  Sometimes ten seconds might be fine to
do a single API call.  Days or even weeks might be needed, if the signature gives the right to download a file, for
instance.

Individual signatures cannot be invalidated, even if a security incident occurred.  Instead, all existing signatures
must be revoked in this case by installing a new public key.


### 2.2 Supporting multiple keys: `key`

The backend supports multiple public keys per bucket to enable multi-device access to the same account.  The optional
`key` parameter selects one of these keys. An example would be:

    key=2

If this parameter is not given, the default key is used instead.  This would currently be the key inside entity `0`, which is
created together with the bucket.


### 2.3 Including other headers: `add`

The client chooses additional header fields that are covered in the signature by including them in the optional `add`
parameter.  Header fields that are mentioned but not found in the request are assumed to be empty strings.

Names are separated by a plus sign.  This avoids quoting the values.  The colon in the HTTP/2 [request pseudo header
fields](//tools.ietf.org/html/rfc7540#section-8.1.2.3) will be replaced by a dash.

If the parameter is not given, the following value is assumed:

    add=-method+-path

This means, that only the request method and request path are normally included in a signature.  This is enough for all
read-only requests.  Omitting the `add` parameter is also a secure choice for all requests that require a JSON body, as
the content type is explicitly verified by the backend.

Neither the method nor the path of a request have to be included in the signature.  This enables wild-card signatures
that cover a whole service or all methods on a certain resource.


### 2.4 The resulting signature: `sig`

The mandatory `sig` parameter defines the message signature encoded as base64 in the [URL-safe
version](//tools.ietf.org/html/rfc3548.html#section-4). This includes the 62 alphanumeric characters plus *underscore*
and *dash*.  Any padding with `equal` signs has to be removed from this value.  The whole parameter is therefore 90 characters
long.

A valid example would be:

    sig=e9FThuTIVBILqKBQeVCrsKcUJ-ADi1SNkju3zf3Sh7-cMzoNTIPtAt_hPyln4myNlRvFePGxNyntJqZjAXm_CA

The `sig` header must not be the first parameter in the authorization, to simplify the server-side implementation.


## 3. Calculating the Signature

The signature is calculated using the authorization header, additional request headers and the body of the message.  All
of these parts are joined together with newlines.  There is no extra newline at the end of the body.

A minimal message to sign consists of the following 29 characters:

    alpico time=1700000000+10\nGET\n/\n

Since there is no body, the empty string is assumed and the message to sign therefore ends with a newline.  The
resulting authorization header might look like this:

    Authorization: alpico time=1700000000+10, sig=e9FThuTIVBILqKBQeVCrsKcUJ-ADi1SNkju3zf3Sh7-cMzoNTIPtAt_hPyln4myNlRvFePGxNyntJqZjAXm_CA


### 3.1 Including a body

If the HTTP request has a body, it must be added to the end of the message.

    alpico time=1700000000+10\nPOST\n/endpoint\nHello World

The authorization header will be the same as above, except for a different signature.


### 3.2 Protecting header fields

If one wants to upload a file, the content-type should be included in the signature.  Assume the following request:

        POST /endpoint
        Content-Type: text/plain
        Content-Length: 11

        Hello World

If the non-default key `5` is used as well, the message to sign will look like this:

    alpico time=1700000000+10, key=5, add=-method+-path+content-type\nPOST\n/endpoint\ntext/plain\nHello World

The additional header names are not included in the message.  They are already part of the `add` parameter.  A
corresponding `Authorization` header would be:

    Authorization: alpico time=1700000000+10, key=5, add=-method+-path+content-type,
      sig=ArdHvxXj-xmnk2WTuKGCQMwg6h1Q8G3PXrKHJYiqKEwyrDp-CvOdx2C9bEA-YbcxBT0yDLVycAOj0TMn6kT4AQ

Neither the `key` nor the `add` parameter are usually required.


### 3.3 Security considerations

The authorization header is always included in the signature.  This ensures that the header names can be safely omitted
and that changes of this specification will not lead to security risks for older implementations.

Including the body in the signature is mandatory.  To avoid various corner cases, it is added after all the headers.  In
requests like `GET`, that do not need a body, an empty entry is still added.

There might be an extension to this specification in the future, that introduces an `omit-body` parameter to relax this
requirement.



## 4. Example code

Implementing the code that generates digital signatures can be a hard task, as the smallest bug leads to a `signature
invalid` response without any further indication where the bug might be.  In this section we therefore show a
step-by-step calculation that should make this programming task easier.

The following example utilizes the [PyNaCl](//pypi.org/project/PyNaCl/) library in version 1.5.0 on top of
[Python](//python.org) v3.11.


### 4.1 Generating the keys

```
from nacl.signing import SigningKey
from nacl.encoding import URLSafeBase64Encoder

# change this to 1 to generate a novel key
if 0:
       privkey = SigningKey.generate()
else:
       # use an example key for reproducable results
       privkey = SigningKey("0XExclimMcQUTuPb93HU5vCxi-WFYfJ0R0-74_kz6ds=", encoder=URLSafeBase64Encoder)

print("priv:", privkey.encode(URLSafeBase64Encoder).decode())
print("pub:", privkey.verify_key.encode(URLSafeBase64Encoder).decode())
```

### 4.2 Defining the message

```
# message
method = "GET"
path = "/"
body = "{}"
headers = {"content-type": "application/json"}

# the authentication parameters
start = 1700000000
duration = 10
add = "-method+-path+content-type"
key = "2"

# combine into a preliminary authorization header
authorization = f"alpico time={start}+{duration}, key={key}, add={add}"
print(authorization)
```

### 4.3 Calculating the signature

```
# add all items together
items = (authorization, method, path, headers.get("content-type"), body)

# convert the list into multi-line bytes
message = "\n".join(items).encode()
print(message)

# Calculate the signature
signature = privkey.sign(message, encoder=URLSafeBase64Encoder).signature.decode()

# Add the signature to the authorization header.
authorization += ", sig=" + signature.rstrip("=")
print("Authorization:", authorization)
```


### 4.4 Full output

The example code generates the following output:

```
priv: 0XExclimMcQUTuPb93HU5vCxi-WFYfJ0R0-74_kz6ds=
pub: ugx7f8f2JIqXjlxyhZcPk_Tgkc1reR_YBrKijRzAaHg=
alpico time=1700000000+10, key=2, add=-method+-path+content-type
b'alpico time=1700000000+10, key=2, add=-method+-path+content-type\nGET\n/\napplication/json\n{}'
Authorization: alpico time=1700000000+10, key=2, add=-method+-path+content-type, sig=YnFDJpA4SaveWyM9Lgf4TYqdaCV2yk5eZzhq8TLFb043it9CDV-6mnca5A3iYYN87lovb5yuVKh3NhhFV_mkAg
```


## 5. Python example code

We use the following function to calculate our signatures.  The example utilizes the PyNaCl library in version 1.5.0 on
top of Python v3.11, as well.


```
import time
from nacl.encoding import URLSafeBase64Encoder

def calc(signkey, method, path, keyname, body=b'', *, other_headers={}, header_to_sign=[], timestamp=0, duration=60):
    authorization = b'alpico time=%d+%d'%(timestamp or time.time(), duration)
    if keyname:
	authorization += b',key=' + keyname
    if header_to_sign:
	authorization += b',add=%s'%(b'+'.join(header_to_sign))
    header_to_sign = header_to_sign or (b'-method', b'-path')
    message = [authorization]
    for header in header_to_sign:
	if header == b'-method':
	    message.append(method)
	elif header == b'-path':
	    message.append(path)
	else:
	    message.append(other_headers.get(header, b''))
    message.append(body)
    signature = signkey.sign(b'\n'.join(message), encoder=URLSafeBase64Encoder).signature
    res = other_headers.copy()
    res[b'authorization'] = authorization + b',sig=' + signature.rstrip(b'=')
    return res
```


## 6. Related work

This is based on the [puzzle authentication scheme](https://puzzle2pay.com/de-en/docs/api/puzzle-authentication/).

### 6.1 HTTP signatures

The most similar approach we have found in our research are HTTP signatures.  These are documented in an [internet
draft](//tools.ietf.org/html/draft-cavage-http-signatures-12).  Originally published in 2013, this document is still
work in progress, even after the 12th iteration.

There are many syntactical differences to our approach:

- we do not include the header names, but hash all signature parameters
- we do not lowercase the method
- we encode the signatures in the URL-safe variant of base64
- we use `time=START+DURATION` instead of the `created` and `expires` parameters
- we reuse the HTTP/2 pseudo-headers `:method` and `:path` instead of `(request-target)`

We have made a few things compulsory:

- all signature parameters must be hashed
- the body is always included
- a validity range must always be specified

On the other hand, the key name is optional, as we can often easily derive it from the request path.


### 6.2 AWS signature

AWS defines its own [authentication
scheme](//docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html).  They construct the
authorization header from the key URL, a list of headers, and the signature.

Compared to us, they:

- only support HMAC style authentication,
- include the algorithm in the method - we derive them from the key,
- encode the signature in hex - we use URL-safe base64, and
- use the semicolon as separator which seems to violate [RFC7235](//tools.ietf.org/html/rfc7235).
