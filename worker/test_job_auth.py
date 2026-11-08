import os
import unittest

from job_auth import verify_qstash


class JobAuthTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("ALLOW_UNSIGNED_JOBS", None)

    def test_unsigned_rejected_by_default(self):
        os.environ.pop("ALLOW_UNSIGNED_JOBS", None)
        self.assertFalse(verify_qstash(b"{}", None))

    def test_unsigned_allowed_only_with_explicit_flag(self):
        os.environ["ALLOW_UNSIGNED_JOBS"] = "1"
        self.assertTrue(verify_qstash(b"{}", None))
        os.environ["ALLOW_UNSIGNED_JOBS"] = "0"
        self.assertFalse(verify_qstash(b"{}", None))

    def test_bad_signature_rejected(self):
        self.assertFalse(verify_qstash(b"{}", "not-a-real-signature"))


if __name__ == "__main__":
    unittest.main()
