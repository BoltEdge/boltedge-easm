from app.models import ApiKey


def test_api_key_has_kind_column_with_default_customer():
    """ApiKey rows must have a `kind` column defaulting to 'customer'.
    Agent platform tags new keys as kind='agent' to keep them out of
    customer-facing listings."""
    key = ApiKey(
        organization_id=1,
        user_id=1,
        name="test",
        key_hash="abc",
        key_prefix="nk_test",
    )
    assert key.kind == "customer"


def test_api_key_kind_can_be_agent():
    key = ApiKey(
        organization_id=1,
        user_id=1,
        name="test",
        key_hash="abc",
        key_prefix="nk_test",
        kind="agent",
    )
    assert key.kind == "agent"
