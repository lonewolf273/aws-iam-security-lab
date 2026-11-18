def detect_access_key_creation(event):
    if (
        event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") == "CreateAccessKey"
        and not event.get("errorCode")
    ):
        return "IAM-001: Access key created; review whether it was expected."
    return None
def detect_admin_policy_attachment(event):
    attachment_actions = {"AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy"}
    parameters = event.get("requestParameters") or {}

    if (
        event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") in attachment_actions
        and parameters.get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess"
        and not event.get("errorCode")
    ):
        return "IAM-002: AdministratorAccess attached; review who approved the change."
    return None
def detect_role_trust_change(event):
    if (
        event.get("eventSource") == "iam.amazonaws.com"
        and event.get("eventName") == "UpdateAssumeRolePolicy"
        and not event.get("errorCode")
    ):
        role = (event.get("requestParameters") or {}).get("roleName") or "unknown role"
        return f"IAM-003: Trust policy updated for {role}. Review who can assume it."
    return None