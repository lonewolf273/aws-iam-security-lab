from detections import detect_role_trust_change
import pytest
from detections import detect_admin_policy_attachment
from detections import detect_access_key_creation


def test_successful_creation_is_flagged():
    event = {"eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"}
    assert detect_access_key_creation(event) is not None


def test_denied_creation_is_not_reported_as_successful():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "errorCode": "AccessDenied",
    }
    assert detect_access_key_creation(event) is None


def test_routine_read_is_ignored():
    event = {"eventSource": "iam.amazonaws.com", "eventName": "ListRolePolicies"}
    assert detect_access_key_creation(event) is None
    
@pytest.mark.parametrize("action", ["AttachUserPolicy", "AttachGroupPolicy", "AttachRolePolicy"])
def test_admin_policy_attachment_is_flagged(action):
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": action,
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
    }
    assert detect_admin_policy_attachment(event) is not None


def test_read_only_policy_attachment_is_ignored():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachRolePolicy",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
    }
    assert detect_admin_policy_attachment(event) is None


def test_denied_admin_attachment_is_ignored():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachRolePolicy",
        "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        "errorCode": "AccessDenied",
    }
    assert detect_admin_policy_attachment(event) is None
    
def test_successful_trust_change_identifies_role():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "UpdateAssumeRolePolicy",
        "requestParameters": {"roleName": "PortfolioLabRole"},
    }
    finding = detect_role_trust_change(event)
    assert finding is not None
    assert "IAM-003" in finding
    assert "PortfolioLabRole" in finding


def test_denied_trust_change_is_ignored():
    event = {
        "eventSource": "iam.amazonaws.com",
        "eventName": "UpdateAssumeRolePolicy",
        "errorCode": "AccessDenied",
    }
    assert detect_role_trust_change(event) is None


def test_assuming_a_role_is_ignored():
    event = {"eventSource": "sts.amazonaws.com", "eventName": "AssumeRole"}
    assert detect_role_trust_change(event) is None