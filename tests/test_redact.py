import pytest

from anvil import redact
from tests import samples


@pytest.mark.parametrize(
    "kind, secret",
    [
        ("aws-access-key-id", samples.AWS_KEY_ID),
        ("github-token", samples.GITHUB_TOKEN),
        ("github-token", samples.GITHUB_PAT),
        ("stripe-key", samples.STRIPE_KEY),
        ("slack-token", samples.SLACK_TOKEN),
        ("google-api-key", samples.GOOGLE_KEY),
        ("api-key", samples.API_KEY),
        ("jwt", samples.JWT),
        ("private-key", samples.PRIVATE_KEY),
    ],
)
def test_each_credential_shape_is_replaced(kind, secret):
    cleaned, findings = redact.redact(f"before {secret} after")
    assert cleaned == f"before [REDACTED:{kind}] after"
    assert [f.kind for f in findings] == [kind]


def test_text_without_secrets_comes_back_identical():
    text = "Deploy finished in 41s. 3 services healthy, commit 9f8e7d6c5b4a."
    assert redact.redact(text) == (text, [])


def test_high_entropy_assignment_is_redacted_but_the_key_stays():
    cleaned, findings = redact.redact("DB_PASSWORD=t7Qx!9vLm2Rz#4Wk")
    assert cleaned == "DB_PASSWORD=[REDACTED:assigned-secret]"
    assert findings[0].kind == "assigned-secret"


def test_json_style_assignment_is_redacted():
    cleaned, _ = redact.redact('{"client_secret": "Zk48sLq0PmXv71Bd"}')
    assert cleaned == '{"client_secret": "[REDACTED:assigned-secret]"}'


@pytest.mark.parametrize(
    "text",
    [
        "password=changeme",
        "token=${GITHUB_TOKEN}",
        "api_key=xxxxxxxxxxxx",
        "password=<your-password>",
        "secret=aaaaaaaaaaaa",
        "access_key: null",
        "password=short",
    ],
)
def test_placeholders_and_low_entropy_values_are_left_alone(text):
    assert redact.redact(text) == (text, [])


def test_credentials_inside_a_url_are_redacted():
    cleaned, findings = redact.redact("postgres://app:hunter2pass@db.internal:5432/app")
    assert cleaned == "postgres://[REDACTED:url-credentials]@db.internal:5432/app"
    assert findings[0].kind == "url-credentials"


def test_bearer_token_is_redacted_and_the_scheme_stays():
    cleaned, _ = redact.redact("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
    assert cleaned == "Authorization: Bearer [REDACTED:bearer-token]"


def test_several_secrets_in_one_text():
    text = f"key {samples.AWS_KEY_ID} and token {samples.GITHUB_TOKEN} end"
    cleaned, findings = redact.redact(text)
    assert cleaned == "key [REDACTED:aws-access-key-id] and token [REDACTED:github-token] end"
    assert [f.kind for f in findings] == ["aws-access-key-id", "github-token"]
    assert findings[0].start < findings[1].start


def test_overlapping_matches_produce_one_finding():
    # The assignment detector and the shape detector both see this value.
    cleaned, findings = redact.redact(f"aws_access_key_id={samples.AWS_KEY_ID}")
    assert len(findings) == 1
    assert cleaned.startswith("aws_access_key_id=[REDACTED:")


def test_private_key_block_is_one_finding():
    cleaned, findings = redact.redact(f"cert follows\n{samples.PRIVATE_KEY}\ndone")
    assert cleaned == "cert follows\n[REDACTED:private-key]\ndone"
    assert len(findings) == 1


def test_redacting_twice_changes_nothing():
    once, _ = redact.redact(f"token={samples.GITHUB_TOKEN} password=t7Qx!9vLm2Rz#4Wk")
    assert redact.redact(once) == (once, [])


def test_redact_value_walks_nested_json_and_counts_by_kind():
    value = {
        "content": [
            {"type": "text", "text": f"id {samples.AWS_KEY_ID}"},
            {"type": "text", "text": f"again {samples.AWS_KEY_ID} and {samples.STRIPE_KEY}"},
        ],
        "meta": {"note": "nothing here", "count": 3, "ok": True, "none": None},
    }
    cleaned, counts = redact.redact_value(value)
    assert cleaned["content"][0]["text"] == "id [REDACTED:aws-access-key-id]"
    assert samples.STRIPE_KEY not in cleaned["content"][1]["text"]
    assert cleaned["meta"] == value["meta"]
    assert counts == {"aws-access-key-id": 2, "stripe-key": 1}


def test_redact_value_does_not_modify_its_input():
    value = {"text": f"id {samples.AWS_KEY_ID}"}
    redact.redact_value(value)
    assert samples.AWS_KEY_ID in value["text"]


def test_entropy_matches_known_values():
    assert redact.entropy("") == 0.0
    assert redact.entropy("aaaa") == 0.0
    assert redact.entropy("abcd") == 2.0
    assert redact.entropy("aabb") == 1.0
