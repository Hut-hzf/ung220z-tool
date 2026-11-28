import unittest
from unittest.mock import patch

import ung220z


class EnableTelnetTimeoutTests(unittest.TestCase):
    def test_enable_telnet_accepts_and_forwards_timeout(self):
        seen_timeouts = []

        def fake_http_get(url, timeout=8):
            seen_timeouts.append(timeout)
            return "TelnetSet Success!"

        with patch.object(ung220z, "http_get", side_effect=fake_http_get):
            ok = ung220z.enable_telnet(
                "192.0.2.1", "user", "pass", open_browser=False, timeout=12.5
            )

        self.assertTrue(ok)
        self.assertEqual(seen_timeouts, [12.5])

    def test_enable_telnet_default_timeout(self):
        seen_timeouts = []

        def fake_http_get(url, timeout=8):
            seen_timeouts.append(timeout)
            return "TelnetSet Success!"

        with patch.object(ung220z, "http_get", side_effect=fake_http_get):
            ok = ung220z.enable_telnet(
                "192.0.2.1", "user", "pass", open_browser=False
            )

        self.assertTrue(ok)
        self.assertEqual(seen_timeouts, [8])


if __name__ == "__main__":
    unittest.main()
