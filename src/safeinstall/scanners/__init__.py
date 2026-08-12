"""Built-in static scanners."""

from safeinstall.scanners.ai_components import AIComponentScanner
from safeinstall.scanners.batch import BatchScanner
from safeinstall.scanners.github_actions import GitHubActionsScanner
from safeinstall.scanners.javascript import JavaScriptScanner
from safeinstall.scanners.powershell import PowerShellScanner
from safeinstall.scanners.prompt_injection import PromptInjectionScanner
from safeinstall.scanners.python import PythonScanner
from safeinstall.scanners.secrets import SecretScanner
from safeinstall.scanners.shell import ShellScanner
from safeinstall.scanners.supply_chain import SupplyChainScanner

__all__ = [
    "AIComponentScanner",
    "BatchScanner",
    "GitHubActionsScanner",
    "JavaScriptScanner",
    "PowerShellScanner",
    "PromptInjectionScanner",
    "PythonScanner",
    "SecretScanner",
    "ShellScanner",
    "SupplyChainScanner",
]
