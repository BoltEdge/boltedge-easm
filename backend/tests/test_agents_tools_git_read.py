import subprocess
from unittest.mock import patch, MagicMock
from app.agents.tools.repo import git_read_handler


def test_git_read_rejects_unknown_subcommand():
    result = git_read_handler(command="push")
    assert "rejected" in result.lower() or "not allowed" in result.lower()
    result = git_read_handler(command="commit")
    assert "rejected" in result.lower() or "not allowed" in result.lower()


def test_git_read_accepts_allowed_subcommands():
    fake = MagicMock()
    fake.stdout = "fake stdout"
    fake.stderr = ""
    fake.returncode = 0

    with patch("app.agents.tools.repo.subprocess.run",
                return_value=fake) as mock_run:
        for cmd in ["log", "show", "diff", "blame", "status", "ls-tree", "branch"]:
            result = git_read_handler(command=cmd)
            assert "fake stdout" in result
            args_called = mock_run.call_args[0][0]
            assert args_called[0] == "git"
            assert "-C" in args_called
            assert "/repo" in args_called
            assert cmd in args_called


def test_git_read_passes_args_safely():
    fake = MagicMock()
    fake.stdout = "log output here"
    fake.stderr = ""
    fake.returncode = 0
    with patch("app.agents.tools.repo.subprocess.run",
                return_value=fake) as mock_run:
        git_read_handler(command="log", args=["-5", "--oneline"])
        args_called = mock_run.call_args[0][0]
        assert "-5" in args_called
        assert "--oneline" in args_called
        # List, not shell string
        assert isinstance(args_called, list)


def test_git_read_rejects_shell_metachars_in_args():
    for bad in [";rm -rf /", "&&whoami", "|cat", "`echo`"]:
        result = git_read_handler(command="log", args=[bad])
        assert "rejected" in result.lower()


def test_git_read_truncates_large_output():
    huge = "x" * 100_000
    fake = MagicMock()
    fake.stdout = huge
    fake.stderr = ""
    fake.returncode = 0
    with patch("app.agents.tools.repo.subprocess.run", return_value=fake):
        result = git_read_handler(command="log")
        assert len(result.encode("utf-8")) <= 50_000 + 200


def test_git_read_returns_stderr_on_nonzero_exit():
    fake = MagicMock()
    fake.stdout = ""
    fake.stderr = "fatal: not a git repository"
    fake.returncode = 128
    with patch("app.agents.tools.repo.subprocess.run", return_value=fake):
        result = git_read_handler(command="log")
        assert "not a git repository" in result
        assert "128" in result
