
import csv
import io
import json
import subprocess

from collections import defaultdict
from datetime import datetime, timezone

from scanner_policy import evaluate_scan_policy

PCAP_FILE = "soc001-portscan.pcap"
OUTPUT_FILE = "alerts.json"
AUDIT_FILE = "audit.json"

INACTIVITY_GAP = 300

RULES = [
    {
        "name": "FAST_PORT_SCAN",
        "threshold": 10,
        "window": 10,
        "cooldown": 10,
    },
    {
        "name": "LONG_WINDOW_PORT_SCAN",
        "threshold": 20,
        "window": 600,
        "cooldown": 600,
    },
]


def detect_port_scan(packets, threshold, window_seconds):
    packets = sorted(packets)

    for start_index, (start_time, _) in enumerate(packets):
        unique_ports = set()

        for timestamp, port in packets[start_index:]:
            if timestamp - start_time > window_seconds:
                break

            unique_ports.add(port)

        if len(unique_ports) >= threshold:
            return {
                "detected": True,
                "unique_ports": len(unique_ports),
                "ports": sorted(unique_ports),
                "window_seconds": window_seconds,
            }

    return {"detected": False}


def split_into_episodes(packets, inactivity_gap=INACTIVITY_GAP):
    if not packets:
        return []

    packets = sorted(packets)

    episodes = []
    current_episode = [packets[0]]

    for packet in packets[1:]:
        timestamp = packet[0]
        previous_timestamp = current_episode[-1][0]

        if timestamp - previous_timestamp >= inactivity_gap:
            episodes.append(current_episode)
            current_episode = [packet]
        else:
            current_episode.append(packet)

    episodes.append(current_episode)

    return episodes


def extract_connections(pcap_file):
    command = [
        "tshark",
        "-r", pcap_file,
        "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    connections = defaultdict(list)

    reader = csv.reader(
        io.StringIO(result.stdout),
        delimiter="\t",
    )

    for row in reader:
        if len(row) != 4:
            continue

        timestamp, source, destination, port = row

        connections[(source, destination)].append(
            (float(timestamp), int(port))
        )

    return connections


def find_detections(packets, rule):
    packets = sorted(packets)
    detections = []

    recent_packets = []
    last_alert_time = float("-inf")

    for timestamp, port in packets:
        recent_packets.append((timestamp, port))

        recent_packets = [
            (t, p)
            for t, p in recent_packets
            if timestamp - t <= rule["window"]
        ]

        unique_ports = sorted({
            p for _, p in recent_packets
        })

        if len(unique_ports) < rule["threshold"]:
            continue

        if timestamp - last_alert_time < rule["cooldown"]:
            continue

        detections.append({
            "rule_id": rule["name"],
            "detected_at": timestamp,
            "evidence_start": recent_packets[0][0],
            "evidence_end": timestamp,
            "unique_ports": len(unique_ports),
            "destination_ports": unique_ports,
            "window_seconds": rule["window"],
            "evidence_packets": list(recent_packets),
        })

        last_alert_time = timestamp

        # Start collecting fresh evidence for the next alert.
        recent_packets = []

    return detections


def correlate_detections(detections, episode):
    fast_detections = [
        d for d in detections
        if d["rule_id"] == "FAST_PORT_SCAN"
    ]

    if not fast_detections:
        return detections

    fast_evidence = set()

    for detection in fast_detections:
        fast_evidence.update(detection["evidence_packets"])

    remaining_packets = [
        packet
        for packet in episode
        if packet not in fast_evidence
    ]

    independent_long_detections = find_detections(
        remaining_packets,
        RULES[1],
    )

    return fast_detections + independent_long_detections


def generate_findings(connections):
    alerts = []
    audit_records = []

    for (source, destination), packets in connections.items():
        episodes = split_into_episodes(packets)

        for episode_number, episode in enumerate(episodes, start=1):
            episode_detections = []

            for rule in RULES:
                episode_detections.extend(
                    find_detections(episode, rule)
                )


            episode_detections = correlate_detections(
    		 episode_detections,
   		 episode,
		)

            for detection in episode_detections:
                policy = evaluate_scan_policy(
                    source,
                    destination,
                    detection["detected_at"],
                )

                finding = {
                    "rule_id": detection["rule_id"],
                    "source_ip": source,
                    "destination_ip": destination,
                    "episode_number": episode_number,
                    "detected_at": datetime.fromtimestamp(
                        detection["detected_at"],
                        tz=timezone.utc,
                    ).isoformat(),
                    "episode_start": datetime.fromtimestamp(
                        episode[0][0],
                        tz=timezone.utc,
                    ).isoformat(),
                    "episode_end": datetime.fromtimestamp(
                        episode[-1][0],
                        tz=timezone.utc,
                    ).isoformat(),
                    "unique_ports": detection["unique_ports"],
                    "destination_ports": detection["destination_ports"],
                    "window_seconds": detection["window_seconds"],
                    "severity": "medium",
                    "classification": "potential_reconnaissance",
                    "scanner_name": policy["scanner_name"],
                    "policy_reason": policy["reason"],
                }

                if policy["approved"]:
                    finding["status"] = "approved_activity"
                    audit_records.append(finding)
                else:
                    finding["status"] = "new"
                    alerts.append(finding)

    alerts.sort(key=lambda a: a["detected_at"])
    audit_records.sort(key=lambda a: a["detected_at"])

    return alerts, audit_records


def generate_alerts(connections):
    alerts, _ = generate_findings(connections)
    return alerts




def main():
    print("[*] Starting Port Scan Detector...")

    connections = extract_connections(PCAP_FILE)

    print(
        f"[*] Analyzing {len(connections)} "
        "source/destination pairs..."
    )

    episode_count = sum(
        len(split_into_episodes(packets))
        for packets in connections.values()
    )

    print(f"[*] Identified {episode_count} traffic episodes.")

    alerts, audit_records = generate_findings(connections)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=4)

    with open(AUDIT_FILE, "w", encoding="utf-8") as file:
        json.dump(audit_records, file, indent=4)

    print(f"[+] Generated {len(alerts)} security alerts.")
    print(f"[+] Recorded {len(audit_records)} approved findings.")
    print(f"[+] Saved alerts to {OUTPUT_FILE}")
    print(f"[+] Saved audit records to {AUDIT_FILE}")


if __name__ == "__main__":
    main()

