
from datetime import datetime, time, timezone
from ipaddress import ip_address, ip_network


APPROVED_SCANNERS = {
    "192.168.56.10": {
        "name": "Authorized Lab Scanner",
        "allowed_targets": [
            "192.168.56.50/32",
        ],
        "start_hour_utc": 8,
        "end_hour_utc": 18,
    }
}


def evaluate_scan_policy(source_ip, destination_ip, timestamp):
    scanner = APPROVED_SCANNERS.get(source_ip)

    if scanner is None:
        return {
            "approved": False,
            "reason": "unknown_scanner",
            "scanner_name": None,
        }

    target = ip_address(destination_ip)

    target_approved = any(
        target in ip_network(network)
        for network in scanner["allowed_targets"]
    )

    if not target_approved:
        return {
            "approved": False,
            "reason": "target_out_of_scope",
            "scanner_name": scanner["name"],
        }

    event_time = datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc,
    ).time()

    start = time(scanner["start_hour_utc"], 0)
    end = time(scanner["end_hour_utc"], 0)

    schedule_approved = start <= event_time < end

    if not schedule_approved:
        return {
            "approved": False,
            "reason": "outside_approved_schedule",
            "scanner_name": scanner["name"],
        }

    return {
        "approved": True,
        "reason": "approved_scanning_activity",
        "scanner_name": scanner["name"],
    }
