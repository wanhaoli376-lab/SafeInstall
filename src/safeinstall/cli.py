"""Command-line interface for SafeInstall."""

import sys
from enum import StrEnum
from typing import Annotated

import typer

from safeinstall import __version__
from safeinstall.core import scan_target
from safeinstall.exceptions import SafeInstallError
from safeinstall.redaction import redact_text
from safeinstall.report import render_json, render_markdown, render_terminal


class ReportFormat(StrEnum):
    """Output formats supported by the public CLI."""

    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"


app = typer.Typer(
    name="safeinstall",
    help="Understand software before you run it with local-first static analysis.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(help="Local directory, archive, or public GitHub repository URL."),
    ],
    report_format: Annotated[
        ReportFormat,
        typer.Option(
            "--format",
            "-f",
            help="Report format: terminal, json, or markdown.",
            case_sensitive=False,
        ),
    ] = ReportFormat.TERMINAL,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai/--no-ai",
            help="Opt in to bounded OpenAI analysis of redacted findings.",
        ),
    ] = False,
    ai_model: Annotated[
        str | None,
        typer.Option(
            "--ai-model",
            help="OpenAI model used only when --ai is enabled.",
        ),
    ] = None,
) -> None:
    """Analyze a target without executing its code."""

    _configure_utf8_output()
    try:
        report = scan_target(target, ai=ai, ai_model=ai_model)
    except SafeInstallError as exc:
        typer.echo(f"SafeInstall error: {redact_text(str(exc))}", err=True)
        raise typer.Exit(code=2) from exc

    if report_format is ReportFormat.JSON:
        typer.echo(render_json(report))
    elif report_format is ReportFormat.MARKDOWN:
        typer.echo(render_markdown(report))
    else:
        render_terminal(report)


def _configure_utf8_output() -> None:
    """Keep Unicode reports usable when Windows inherited a legacy code page."""

    for stream in (sys.stdout, sys.stderr):
        encoding = getattr(stream, "encoding", None)
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure) and encoding and encoding.casefold() != "utf-8":
            reconfigure(encoding="utf-8")


@app.command()
def version() -> None:
    """Show the installed SafeInstall version."""

    typer.echo(f"SafeInstall {__version__}")


if __name__ == "__main__":  # pragma: no cover
    app()
