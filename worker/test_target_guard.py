import unittest

from target_guard import UnsafeTargetError, guard_target, is_blocked_host


class TargetGuardTests(unittest.TestCase):
    def test_blocks_private_literals(self):
        blocked = [
            "127.0.0.1",
            "localhost",
            "10.1.2.3",
            "192.168.0.5",
            "172.16.0.1",
            "169.254.169.254",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "2130706433",
            "::1",
            "::ffff:127.0.0.1",
            "fd00::1",
            "metadata.google.internal",
            "app.internal",
            "printer.local",
        ]
        for host in blocked:
            self.assertTrue(is_blocked_host(host), host)

    def test_allows_public_names(self):
        for host in ["example.com", "scan.example.co.uk", "1.1.1.1", "8.8.8.8"]:
            self.assertFalse(is_blocked_host(host), host)

    def test_guard_rejects_metadata_before_connect(self):
        with self.assertRaises(UnsafeTargetError):
            guard_target("http://169.254.169.254/latest/meta-data/")

    def test_guard_rejects_non_http(self):
        with self.assertRaises(UnsafeTargetError):
            guard_target("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
