
import unittest

from datetime import datetime, timezone

from scanner_policy import evaluate_scan_policy


def utc_timestamp(hour):
    return datetime(
        2026, 10, 13, hour, 0,
        tzinfo=timezone.utc,
    ).timestamp()


class TestScannerPolicy(unittest.TestCase):

    def test_approved_scanner(self):
        result = evaluate_scan_policy(
            "192.168.56.10",
            "192.168.56.50",
            utc_timestamp(12),
        )

        self.assertTrue(result["approved"])

    def test_unknown_scanner(self):
        result = evaluate_scan_policy(
            "192.168.56.99",
            "192.168.56.50",
            utc_timestamp(12),
        )

        self.assertFalse(result["approved"])
        self.assertEqual(
            result["reason"],
            "unknown_scanner",
        )

    def test_out_of_scope_target(self):
        result = evaluate_scan_policy(
            "192.168.56.10",
            "192.168.56.100",
            utc_timestamp(12),
        )

        self.assertFalse(result["approved"])
        self.assertEqual(
            result["reason"],
            "target_out_of_scope",
        )

    def test_outside_schedule(self):
        result = evaluate_scan_policy(
            "192.168.56.10",
            "192.168.56.50",
            utc_timestamp(22),
        )

        self.assertFalse(result["approved"])
        self.assertEqual(
            result["reason"],
            "outside_approved_schedule",
        )


if __name__ == "__main__":
    unittest.main()
