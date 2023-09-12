"""Alpico Authentication Scheme.

Python code usable with h2.
"""

import time, base64, re
from nacl.encoding import URLSafeBase64Encoder
from nacl import exceptions

def calc(signkey, method, path, keyname, body=b'', *, other_headers={}, header_to_sign=[], timestamp=0, duration=60, prefix=b'alpico'):
    authorization = prefix + b' time=%d+%d'%(timestamp or time.time(), duration)
    if keyname:
        authorization += b',key=' + keyname
    if header_to_sign:
        authorization += b',add=%s'%(b'+'.join(header_to_sign))
    header_to_sign = header_to_sign or [b'-method', b'-path']
    message = [authorization]
    for header in header_to_sign:
        if header == b'-method':
            message.append(method)
        elif header == b'-path':
            message.append(path)
        else:
            message.append(other_headers.get(header, b""))
    message.append(body)
    message = b'\n'.join(message)
    signature = signkey.sign(message=message, encoder=URLSafeBase64Encoder).signature
    res = other_headers.copy()
    res[b'authorization'] = authorization + b',sig=' + signature.rstrip(b"=")
    return res

def parse(headers, exception=ValueError, prefix=b'alpico'):
    "Parse the authorization header and return a dict."
    if not b'authorization' in headers:
        raise exception("authorization missing")
    method, _, auth = headers[b'authorization'].strip().partition(b" ")
    if method.lower() != prefix:
        raise exception("unsupported authorization method")
    auths = {}
    for x in auth.split(b","):
        key,_,value = x.strip().partition(b'=')
        auths[key] = value
    auths[b""] = headers[b'authorization']
    return auths


def verify(headers, path, body, verifykeys, *, auths=None, date=0, exception=ValueError, prefix=b'alpico'):
    "Verify the authorization header."
    auths = auths or parse(headers, exception=exception, prefix=prefix)
    sig = auths.get(b'sig', b'')
    if len(sig) % 4:
        # fix the padding
        sig += b"A=="[-4 + len(sig) % 4:]

    sig = base64.b64decode(sig, altchars="-_", validate=True)
    try:
        start, _, duration = auths.get(b"time", b"0+0").partition(b"+")
        start = int(start)
        duration = int(duration)
    except ValueError:
        raise exception("invalid time")
    now = int(date) if date else time.time()
    if now < start - 1:
        raise exception("early")
    if now >= start + duration:
        raise exception("expired")

    auth = re.sub(b",?\s*sig=[^ ,]+", b"", auths[b""]).strip()
    message = [auth]
    for name in auths.get(b"add", b"-method+-path").split(b"+"):
        if name == b"-method":
            message.append(path[0])
        elif name == b"-path":
            message.append(b"/" + b"/".join(path[1:]))
        else:
            # support pseudo headers like :authority or :scheme
            name = name[:1].replace(b'-', b":") + name[1:]
            message.append(headers.get(name.lower(), b""))
    message.append(body or b"")
    message = b"\n".join(message)
    for key in verifykeys:
        if not key:
            continue
        try:
            key.verify(message, sig)
            break
        except exceptions.BadSignatureError:
            pass
    else:
        raise exception("invalid signature")
    return now
