"""HTTPS for every ksm download: the default TLS context, plus the system CA
bundle when the interpreter ships without one (uv/python-build-standalone on
NixOS, minimal containers), so `ksm update`, `ksm setup` and `ksm deps` work
wherever curl does."""

import os
import ssl
import urllib.request

# First existing file wins. SSL_CERT_FILE is honoured by OpenSSL already; it is
# listed so an explicit setting also covers interpreters that ignore it.
CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu, Alpine, NixOS
    "/etc/pki/tls/certs/ca-bundle.crt",    # Fedora, RHEL
    "/etc/ssl/ca-bundle.pem",              # openSUSE
    "/etc/ssl/cert.pem",                   # macOS, BSD
)

_context = None


def ssl_context():
    """Default context; when it holds no CA certificates, load a system bundle."""
    global _context
    if _context is None:
        ctx = ssl.create_default_context()
        if ctx.cert_store_stats().get("x509_ca", 0) == 0:
            env = os.environ.get("SSL_CERT_FILE")
            for path in ((env,) if env else ()) + CA_BUNDLES:
                if path and os.path.isfile(path):
                    ctx.load_verify_locations(cafile=path)
                    break
        _context = ctx
    return _context


def urlopen(request, timeout):
    """urllib.request.urlopen with ssl_context() for https URLs."""
    url = request.full_url if isinstance(request, urllib.request.Request) else str(request)
    if url.startswith("https://"):
        return urllib.request.urlopen(request, timeout=timeout, context=ssl_context())
    return urllib.request.urlopen(request, timeout=timeout)
