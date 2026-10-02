"""Domain-specific errors exposed by SafeInstall modules."""


class SafeInstallError(Exception):
    """Base class for errors that can be shown to CLI users."""


class RuleLoadError(SafeInstallError):
    """Raised when a declarative rule file is unsafe or invalid."""


class InputError(SafeInstallError):
    """Raised when a scan target cannot be loaded safely."""


class NoScannableFilesError(InputError):
    """Raised when discovery cannot provide any supported text to the scanners."""


class UnsafeArchiveError(InputError):
    """Raised when an archive violates extraction safety limits."""


class RepositoryLoadError(InputError):
    """Raised when a remote repository cannot be cloned safely."""


class ParseLimitError(SafeInstallError):
    """Raised when untrusted structured input exceeds safe parser limits."""


class PluginError(SafeInstallError):
    """Raised when explicit plugin registration or execution is invalid."""


class AIAnalysisError(SafeInstallError):
    """Raised when explicitly requested AI analysis cannot complete safely."""


class AIUnavailableError(AIAnalysisError):
    """Raised when optional AI configuration or dependencies are unavailable."""
