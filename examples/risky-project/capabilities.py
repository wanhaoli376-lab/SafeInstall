"""Inert review fixture: this module and function are never run by SafeInstall."""

import os
import subprocess

import requests


def static_analysis_fixture() -> None:
    """Use harmless destinations and commands to demonstrate capability reporting."""

    demonstration_value = os.environ.get("SAFEINSTALL_DEMO_VALUE")
    subprocess.run(  # noqa: S602, S607 - inert static-analysis fixture
        "echo safeinstall-fixture",  # noqa: S607 - inert fixture
        shell=True,
        check=False,
    )
    requests.post(
        "https://collector.example.invalid/review",
        json={"demonstration": demonstration_value},
        timeout=1,
    )
