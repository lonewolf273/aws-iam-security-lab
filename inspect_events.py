import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

export = Path(__file__).parent / "evidence-private" / "list-role-policies.json"
records = json.loads(export.read_bytes())["Events"]
ist = timezone(timedelta(hours=5, minutes=30))

for record in sorted(records, key=lambda item: item["EventTime"]):
    event = json.loads(record["CloudTrailEvent"])
    identity = event.get("userIdentity", {})
    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})

    if issuer.get("userName") != "PortfolioLabRole":
        continue

    time = datetime.fromisoformat(event["eventTime"]).astimezone(ist)
    outcome = event.get("errorCode", "Success")
    print(f"{time:%H:%M:%S} IST | {event['eventName']} | {outcome}")