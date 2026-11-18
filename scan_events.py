import argparse
import json
from pathlib import Path

from detections import (
    detect_access_key_creation,
    detect_admin_policy_attachment,
    detect_role_trust_change,
)

RULES = (
    detect_access_key_creation,
    detect_admin_policy_attachment,
    detect_role_trust_change,
)


def read_events(path):
    data = json.loads(path.read_bytes())

    # Our synthetic sample is a list of event objects.
    if isinstance(data, list):
        return data

    # AWS CLI lookup-events stores each event as a JSON string.
    return [json.loads(record["CloudTrailEvent"]) for record in data["Events"]]


def main():
    parser = argparse.ArgumentParser(description="Check CloudTrail events for IAM changes.")
    parser.add_argument("file", type=Path, help="Path to a sample or AWS CLI JSON export")
    args = parser.parse_args()

    events = read_events(args.file)
    findings = 0

    for event in events:
        for rule in RULES:
            finding = rule(event)
            if finding:
                print(f"[{event.get('eventID', 'unknown')}] {finding}")
                findings += 1

    print(f"Events scanned: {len(events)} | Findings: {findings}")


if __name__ == "__main__":
    main()