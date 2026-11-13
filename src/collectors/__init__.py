"""
Log Collectors Module
Importing a collector pulls in its cloud SDK, so it is done on first use.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .aws_collector import AWSCollector
    from .azure_collector import AzureCollector


def __getattr__(name: str):
    if name == "AWSCollector":
        from .aws_collector import AWSCollector

        return AWSCollector
    if name == "AzureCollector":
        from .azure_collector import AzureCollector

        return AzureCollector
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["AWSCollector", "AzureCollector"]
