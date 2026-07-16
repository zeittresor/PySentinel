from __future__ import annotations

import json
from pathlib import Path


class Translator:
    def __init__(self, language: str = "en") -> None:
        self._base = Path(__file__).parent / "resources" / "lang"
        self.language = language
        self._data: dict[str, str] = {}
        self.load(language)

    def load(self, language: str) -> None:
        path = self._base / f"{language}.json"
        if not path.exists():
            path = self._base / "en.json"
            language = "en"
        self._data = json.loads(path.read_text(encoding="utf-8"))
        self.language = language

    def tr(self, key: str, default: str | None = None, **kwargs) -> str:
        text = self._data.get(key, default if default is not None else key)
        try:
            return text.format(**kwargs)
        except (KeyError, ValueError):
            return text
