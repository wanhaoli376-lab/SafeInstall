from pathlib import Path
from zipfile import ZipFile

from safeinstall.core import scan_target
from safeinstall.models import Severity, TargetKind

_OPENAI_KEY_FIXTURE = "".join(("sk-", "abcdefghijklmnopqrstuvwxyz123456"))


class ExplodingAIAnalyzer:
    def analyze(self, *args: object, **kwargs: object) -> object:
        raise AssertionError("AI analyzer must not run without explicit opt-in")


def test_local_scan_returns_explainable_report_without_calling_ai(tmp_path: Path) -> None:
    project = tmp_path / "risky-fixture"
    project.mkdir()
    secret = _OPENAI_KEY_FIXTURE
    (project / "demo.py").write_text(
        "import subprocess\n"
        f'OPENAI_API_KEY = "{secret}"\n'
        "def demonstration_only(command):\n"
        "    subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    report = scan_target(project, ai_analyzer=ExplodingAIAnalyzer())
    serialized = report.model_dump_json()

    assert report.target.kind is TargetKind.LOCAL
    assert report.target.files_scanned == 1
    assert report.risk.level is Severity.HIGH
    assert {finding.rule_id for finding in report.findings} >= {"SI-PY-001", "SI-SEC-001"}
    assert secret not in serialized
    assert report.ai_analysis is None


def test_zip_scan_uses_ephemeral_archive_loader(tmp_path: Path) -> None:
    archive = tmp_path / "safe-project.zip"
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("safe-project/app.py", "def add(left, right):\n    return left + right\n")

    report = scan_target(archive)

    assert report.target.kind is TargetKind.ARCHIVE
    assert report.target.files_scanned == 1
    assert report.risk.level is Severity.INFO
    assert report.findings == ()
