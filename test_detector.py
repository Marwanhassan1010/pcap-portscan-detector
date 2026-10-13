
import unittest

from detector import (
    detect_port_scan,
    split_into_episodes,
    find_detections,
    generate_alerts,
    generate_findings,
    RULES,
)


SOURCE = "192.168.56.10"
DESTINATION = "192.168.56.50"


class TestPortScanDetector(unittest.TestCase):

    def setUp(self):
        self.fast_scan = [
            (i * 0.1, 20 + i)
            for i in range(21)
        ]

        self.slow_scan = [
            (i * 15, 20 + i)
            for i in range(21)
        ]

        self.single_port = [
            (i * 0.1, 80)
            for i in range(100)
        ]

    def test_fast_scan(self):
        result = detect_port_scan(
            self.fast_scan, 10, 10
        )
        self.assertTrue(result["detected"])

    def test_slow_scan(self):
        result = detect_port_scan(
            self.slow_scan, 20, 600
        )
        self.assertTrue(result["detected"])

    def test_single_port(self):
        result = detect_port_scan(
            self.single_port, 10, 10
        )
        self.assertFalse(result["detected"])

    def test_empty_capture(self):
        result = detect_port_scan([], 10, 10)
        self.assertFalse(result["detected"])

    def test_one_episode(self):
        episodes = split_into_episodes(
            self.fast_scan
        )
        self.assertEqual(len(episodes), 1)

    def test_two_episodes(self):
        packets = [
            (0, 20),
            (1, 21),
            (420, 22),
            (421, 23),
        ]

        episodes = split_into_episodes(packets)
        self.assertEqual(len(episodes), 2)

    def test_inactivity_boundary(self):
        episodes = split_into_episodes([
            (0, 20),
            (300, 21),
        ])
        self.assertEqual(len(episodes), 2)

    def test_three_fast_bursts(self):
        bursts = []

        for start_time, start_port in [
            (0, 20),
            (60, 50),
            (120, 80),
        ]:
            bursts.extend([
                (start_time + i * 0.1, start_port + i)
                for i in range(15)
            ])

        detections = find_detections(
            bursts, RULES[0]
        )

        self.assertEqual(len(detections), 3)

    def test_cooldown_merges_close_bursts(self):
        bursts = []

        for start_time, start_port in [
            (0, 20),
            (5, 50),
            (60, 80),
        ]:
            bursts.extend([
                (start_time + i * 0.1, start_port + i)
                for i in range(15)
            ])

        detections = find_detections(
            bursts, RULES[0]
        )

        self.assertEqual(len(detections), 2)

    def test_two_alerts_in_one_episode(self):
        first_burst = [
            (i * 0.1, 20 + i)
            for i in range(15)
        ]

        second_burst = [
            (60 + i * 0.1, 50 + i)
            for i in range(15)
        ]

        connections = {
            (SOURCE, DESTINATION):
                first_burst + second_burst
        }

        alerts = generate_alerts(connections)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            alerts[0]["episode_number"],
            1,
        )
        self.assertEqual(
            alerts[1]["episode_number"],
            1,
        )

    def test_two_alerts_in_two_episodes(self):
        first_burst = [
            (i * 0.1, 20 + i)
            for i in range(15)
        ]

        second_burst = [
            (420 + i * 0.1, 50 + i)
            for i in range(15)
        ]

        connections = {
            (SOURCE, DESTINATION):
                first_burst + second_burst
        }

        alerts = generate_alerts(connections)

        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            [a["episode_number"] for a in alerts],
            [1, 2],
        )

    def test_no_alert_for_single_port(self):
        connections = {
            (SOURCE, DESTINATION):
                self.single_port
        }

        alerts = generate_alerts(connections)
        self.assertEqual(len(alerts), 0)

    def test_long_window_scan(self):
        connections = {
            (SOURCE, DESTINATION):
                self.slow_scan
        }

        alerts = generate_alerts(connections)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["rule_id"],
            "LONG_WINDOW_PORT_SCAN",
        )

   
    def test_approved_scan_creates_audit_record(self):
        from datetime import datetime, timezone

        start = datetime(
            2026, 10, 13, 12, 0,
            tzinfo=timezone.utc,
        ).timestamp()

        packets = [
            (start + i * 0.1, 20 + i)
            for i in range(15)
        ]

        connections = {
            ("192.168.56.10", "192.168.56.50"): packets
        }

        alerts, audit = generate_findings(connections)

        self.assertEqual(len(alerts), 0)
        self.assertEqual(len(audit), 1)
        self.assertEqual(
            audit[0]["policy_reason"],
            "approved_scanning_activity",
        )

    def test_outside_schedule_creates_alert(self):
        from datetime import datetime, timezone

        start = datetime(
            2026, 10, 13, 22, 0,
            tzinfo=timezone.utc,
        ).timestamp()

        packets = [
            (start + i * 0.1, 20 + i)
            for i in range(15)
        ]

        connections = {
            ("192.168.56.10", "192.168.56.50"): packets
        }

        alerts, audit = generate_findings(connections)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(audit), 0)
        self.assertEqual(
            alerts[0]["policy_reason"],
            "outside_approved_schedule",
        )

    def test_fast_and_slow_scans_both_preserved(self):
        fast_burst = [
            (i * 0.1, 20 + i)
            for i in range(15)
        ]

        slow_burst = [
            (60 + i * 15, 100 + i)
            for i in range(21)
        ]

        connections = {
            ("192.168.56.99", "192.168.56.50"):
                fast_burst + slow_burst
        }

        alerts = generate_alerts(connections)

        rule_ids = {alert["rule_id"] for alert in alerts}

        self.assertIn("FAST_PORT_SCAN", rule_ids)
        self.assertIn("LONG_WINDOW_PORT_SCAN", rule_ids)



if __name__ == "__main__":
    unittest.main()

