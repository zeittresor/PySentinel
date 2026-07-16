from __future__ import annotations

from PyQt6.QtCore import QSettings


class AppSettings:
    def __init__(self) -> None:
        self._settings = QSettings("zeittresor", "PySentinel")

    def get(self, key: str, default=None):
        return self._settings.value(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"1", "true", "yes", "on"}

    def get_int(self, key: str, default: int) -> int:
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value) -> None:
        self._settings.setValue(key, value)

    def sync(self) -> None:
        self._settings.sync()
