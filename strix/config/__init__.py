"""Strix application settings.

Public surface:

- :class:`Settings` — composite model. Get via :func:`load_settings`.
- :class:`LlmSettings`, :class:`RuntimeSettings`, :class:`TelemetrySettings`,
  :class:`IntegrationSettings` — sub-models, attribute-accessed off
  ``Settings``.
- :func:`load_settings` — memoized resolve (env > JSON file > defaults).
- :func:`apply_config_override` — switch the JSON source to a custom path.
- :func:`persist_current` — write currently-set env vars to the active file.
- :func:`save_llm_connection` — update the persisted local LLM connection.
"""

from strix.config.loader import (
    apply_config_override,
    load_settings,
    persist_current,
    save_llm_connection,
    save_web_search_settings,
)
from strix.config.settings import (
    ContextSettings,
    DedupeSettings,
    IntegrationSettings,
    LlmSettings,
    RuntimeSettings,
    RateLimitUnit,
    Settings,
    TelemetrySettings,
    native_web_search_supported,
)


__all__ = [
    "ContextSettings",
    "DedupeSettings",
    "IntegrationSettings",
    "LlmSettings",
    "RuntimeSettings",
    "RateLimitUnit",
    "Settings",
    "TelemetrySettings",
    "apply_config_override",
    "load_settings",
    "native_web_search_supported",
    "persist_current",
    "save_llm_connection",
    "save_web_search_settings",
]
