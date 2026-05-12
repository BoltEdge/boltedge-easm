import os
from unittest.mock import patch
from app.agents.tools.repo import read_repo_file_handler


def test_read_repo_file_returns_contents(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("Hello, world!\n")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="hello.txt")
        assert "Hello, world!" in result


def test_read_repo_file_blocks_dotgit(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path=".git/config")
        assert "rejected" in result.lower() or "denied" in result.lower()


def test_read_repo_file_blocks_env_files(tmp_path):
    (tmp_path / ".env").write_text("SECRET=foo\n")
    (tmp_path / ".env.local").write_text("KEY=bar\n")
    (tmp_path / ".env.production").write_text("DB=baz\n")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        for path in [".env", ".env.local", ".env.production"]:
            result = read_repo_file_handler(path=path)
            assert ("rejected" in result.lower()
                    or "denied" in result.lower())


def test_read_repo_file_blocks_key_files(tmp_path):
    (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----\n")
    (tmp_path / "cert.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    (tmp_path / "bundle.p12").write_bytes(b"\x30\x82")

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        for path in ["server.key", "cert.pem", "bundle.p12"]:
            result = read_repo_file_handler(path=path)
            assert ("rejected" in result.lower()
                    or "denied" in result.lower())


def test_read_repo_file_blocks_path_traversal(tmp_path):
    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        for bad in ["../etc/passwd", "../../home",
                     "subdir/../../../etc/passwd"]:
            result = read_repo_file_handler(path=bad)
            assert ("rejected" in result.lower()
                    or "outside" in result.lower())


def test_read_repo_file_blocks_absolute_paths(tmp_path):
    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="/etc/passwd")
        assert ("rejected" in result.lower()
                or "absolute" in result.lower())


def test_read_repo_file_truncates_huge_files(tmp_path):
    huge = "x" * 200_000
    f = tmp_path / "big.txt"
    f.write_text(huge)

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="big.txt")
        assert len(result.encode("utf-8")) <= 100_000 + 300
        assert "truncated" in result.lower() or "too large" in result.lower()


def test_read_repo_file_handles_missing_file(tmp_path):
    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="nonexistent.txt")
        assert "not found" in result.lower() or "no such file" in result.lower()


def test_read_repo_file_rejects_symlinks(tmp_path):
    real = tmp_path / "real.txt"
    real.write_text("contents")
    link = tmp_path / "link.txt"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        return  # Windows without symlink permission; skip silently

    with patch("app.agents.tools.repo.REPO_PATH", str(tmp_path)):
        result = read_repo_file_handler(path="link.txt")
        assert ("rejected" in result.lower()
                or "symlink" in result.lower())
