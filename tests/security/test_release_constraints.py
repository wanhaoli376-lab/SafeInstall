from pathlib import Path


def test_release_constraints_pin_critical_build_and_runtime_dependencies() -> None:
    path = Path(__file__).parents[2] / "constraints" / "release-python311.txt"
    requirements = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    pins = {line.split("==", maxsplit=1)[0].casefold() for line in requirements}

    assert all("==" in line for line in requirements)
    assert {
        "cyclonedx-bom",
        "hatchling",
        "httpx",
        "pydantic",
        "pyinstaller",
        "pyside6",
        "pyyaml",
        "rich",
        "shiboken6",
        "typer",
    } <= pins
    assert "openai" not in pins
