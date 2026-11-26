"""ops/lib/pg-tune.sh 多内存档位自适应调优脚本单测。"""

from pathlib import Path
import subprocess
import tempfile
import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PG_TUNE = REPO_ROOT / "ops" / "lib" / "pg-tune.sh"


def run_tune(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(PG_TUNE), *args],
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    "mem_mb,want_profile,want_shared,want_work_mem,want_max_conn,want_vac_scale",
    [
        ("3800", "4g", "768MB", "4MB", "120", "0.05"),
        ("7600", "8g", "1536MB", "8MB", "150", "0.02"),
        ("15500", "16g", "3GB", "16MB", "200", "0.02"),
        ("31800", "32g", "6GB", "32MB", "250", "0.01"),
        ("63200", "64g", "12GB", "64MB", "300", "0.01"),
    ],
)
def test_auto_profile_detection_and_conf_output(
    mem_mb: str,
    want_profile: str,
    want_shared: str,
    want_work_mem: str,
    want_max_conn: str,
    want_vac_scale: str,
) -> None:
    res = run_tune("--format", "conf", "--profile", "auto", "--mem-mb", mem_mb)
    assert res.returncode == 0, res.stderr
    out = res.stdout
    assert f"档位：{want_profile}" in out
    assert f"shared_buffers = '{want_shared}'" in out
    assert f"work_mem = '{want_work_mem}'" in out
    assert f"max_connections = {want_max_conn}" in out
    assert f"autovacuum_vacuum_scale_factor = {want_vac_scale}" in out
    assert "random_page_cost = 1.1" in out
    assert "jit = off" in out
    assert "checkpoint_completion_target = 0.9" in out
    assert "shared_preload_libraries" not in out


def test_env_format_and_explicit_profile() -> None:
    res = run_tune("--format", "env", "--profile", "64g")
    assert res.returncode == 0, res.stderr
    lines = dict(
        line.split("=", 1)
        for line in res.stdout.splitlines()
        if line and not line.startswith("#")
    )
    assert lines["PG_MEMORY_PROFILE"] == "64g"
    assert lines["POSTGRES_SHM_SIZE"] == "4gb"
    assert lines["POSTGRES_SHARED_BUFFERS"] == "12GB"
    assert lines["POSTGRES_WORK_MEM"] == "64MB"
    assert lines["DB_MAX_CONNS"] == "64"
    assert lines["DB_BG_MAX_CONNS"] == "32"


def test_pg_stat_statements_enabled_only_when_so_exists() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        res_missing = run_tune("--format", "conf", "--profile", "32g", "--pg-lib", tmp)
        assert res_missing.returncode == 0, res_missing.stderr
        assert "shared_preload_libraries" not in res_missing.stdout

        (Path(tmp) / "pg_stat_statements.so").write_bytes(b"")
        res_present = run_tune("--format", "conf", "--profile", "32g", "--pg-lib", tmp)
        assert res_present.returncode == 0, res_present.stderr
        assert "shared_preload_libraries = 'pg_stat_statements'" in res_present.stdout


def test_rejects_invalid_profile_and_format() -> None:
    assert run_tune("--profile", "128g").returncode == 2
    assert run_tune("--format", "yaml").returncode == 2


@pytest.mark.parametrize("bad_mem_mb", ["0", "-1", "abc", "", "08", "12.5"])
def test_rejects_invalid_mem_mb_exits_2_with_empty_stdout(bad_mem_mb: str) -> None:
    res = run_tune("--format", "conf", "--profile", "auto", "--mem-mb", bad_mem_mb)
    assert res.returncode == 2, f"mem-mb={bad_mem_mb!r}: rc={res.returncode}, stderr={res.stderr}"
    assert res.stdout == ""
    assert "无效的 --mem-mb" in res.stderr

    res_explicit = run_tune("--format", "env", "--profile", "4g", "--mem-mb", bad_mem_mb)
    assert res_explicit.returncode == 2
    assert res_explicit.stdout == ""
