"""ksm.net: system CA bundle fallback and https-only TLS context."""
import os
import ssl
import unittest
import urllib.request
from unittest import mock

import ksm.net as net

SYSTEM_BUNDLE = next((p for p in net.CA_BUNDLES if os.path.isfile(p)), None)


class TestNet(unittest.TestCase):
    def setUp(self):
        net._context = None

    def tearDown(self):
        net._context = None

    @unittest.skipUnless(SYSTEM_BUNDLE, "no system CA bundle on this host")
    def test_empty_default_context_loads_a_bundle(self):
        empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with mock.patch.object(net.ssl, "create_default_context", return_value=empty), \
                mock.patch.dict(os.environ, {"SSL_CERT_FILE": SYSTEM_BUNDLE}):
            ctx = net.ssl_context()
        self.assertGreater(ctx.cert_store_stats()["x509_ca"], 0)

    def test_context_only_for_https(self):
        with mock.patch.object(net.urllib.request, "urlopen") as op:
            net.urlopen(urllib.request.Request("file:///tmp/x"), timeout=5)
            self.assertNotIn("context", op.call_args.kwargs)
            net.urlopen(urllib.request.Request("https://example.org/"), timeout=5)
            self.assertIn("context", op.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
