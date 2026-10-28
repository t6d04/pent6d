"""User-facing branding for the local Pent6d distribution.

The Python import namespace and legacy environment/artifact names remain
``strix`` for backwards compatibility with existing runs and integrations.
Keep user-visible strings in one place so the local fork can be branded
without accidentally changing those compatibility contracts.
"""

PRODUCT_NAME = "pent6d"
PRODUCT_DISPLAY_NAME = "Pent6d"
LEGACY_PRODUCT_NAME = "strix"
LEGACY_DISTRIBUTION_NAME = "strix-agent"


def display_finding_id(number: int) -> str:
    """Return the stable, locally branded finding identifier."""

    return f"PENT6D-{number}"
