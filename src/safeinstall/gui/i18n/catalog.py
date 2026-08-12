"""Centralized English and Simplified Chinese GUI strings."""

from __future__ import annotations

from dataclasses import dataclass

from safeinstall.gui.i18n.en import STRINGS as ENGLISH
from safeinstall.gui.i18n.zh_cn import STRINGS as CHINESE

_CATALOGS = {"en": ENGLISH, "zh_CN": CHINESE}


def normalize_locale(locale: str | None) -> str:
    if locale and locale.replace("-", "_").casefold().startswith("zh"):
        return "zh_CN"
    return "en"


@dataclass(slots=True)
class Catalog:
    """Lookup GUI strings without coupling widgets to translation storage."""

    locale: str = "en"

    def __post_init__(self) -> None:
        self.locale = normalize_locale(self.locale)

    def text(self, key: str, **values: object) -> str:
        template = _CATALOGS[self.locale].get(key, ENGLISH.get(key, key))
        return template.format(**values)

    def has(self, key: str) -> bool:
        return key in _CATALOGS[self.locale] or key in ENGLISH

    def switch(self, locale: str) -> None:
        self.locale = normalize_locale(locale)
