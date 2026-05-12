from unittest.mock import patch, MagicMock
from app.agents.tools.web import web_fetch_handler


def test_web_fetch_rejects_non_http_urls():
    assert "rejected" in web_fetch_handler(url="file:///etc/passwd").lower()
    assert "rejected" in web_fetch_handler(url="ftp://example.com/").lower()
    assert "rejected" in web_fetch_handler(url="javascript:alert(1)").lower()


def test_web_fetch_rejects_private_ips():
    for url in [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
    ]:
        result = web_fetch_handler(url=url)
        assert "rejected" in result.lower() or "private" in result.lower()


def test_web_fetch_strips_html_to_text():
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = (
        "<html><body><h1>Hello</h1>"
        "<p>This is a <strong>test</strong>.</p>"
        "<script>alert('xss')</script>"
        "</body></html>"
    )
    fake_response.headers = {"content-type": "text/html; charset=utf-8"}
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.web.requests.get",
                return_value=fake_response), \
         patch("app.agents.tools.web._is_private_host", return_value=False):
        result = web_fetch_handler(url="https://example.com/article")
        assert "Hello" in result
        assert "test" in result
        # Script content should not appear
        assert "alert" not in result
        # HTML tags should be stripped
        assert "<h1>" not in result
        assert "<script>" not in result


def test_web_fetch_truncates_large_responses():
    huge = "x" * 200_000  # 200 KB of x's
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.text = f"<html><body>{huge}</body></html>"
    fake_response.headers = {"content-type": "text/html"}
    fake_response.raise_for_status = MagicMock()

    with patch("app.agents.tools.web.requests.get",
                return_value=fake_response), \
         patch("app.agents.tools.web._is_private_host", return_value=False):
        result = web_fetch_handler(url="https://example.com/")
        assert len(result.encode("utf-8")) <= 50_000 + 200
        assert "truncated" in result.lower()
