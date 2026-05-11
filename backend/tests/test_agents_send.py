from app.agents.send_service import send_digest_email, FakeResendClient


def test_send_digest_uses_correct_from_address():
    fake = FakeResendClient()
    send_digest_email(
        to="founder@example.com",
        subject="Weekly Summary",
        markdown="# Hi\n\nNumbers go here.",
        client=fake,
    )
    assert len(fake.sent) == 1
    msg = fake.sent[0]
    assert msg["to"] == "founder@example.com"
    assert msg["subject"] == "Weekly Summary"
    assert "from" in msg
    assert "<h1>Hi</h1>" in msg["html"]
