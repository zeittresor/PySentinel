from __future__ import annotations

from pathlib import Path


THEMES = {
    "light": "Light",
    "dark": "Dark",
    "sepia": "Sepia",
    "ocean": "Ocean",
    "matrix": "Matrix",
    "hellfire": "Hellfire",
    "purple": "Purple",
    "aurora": "Aurora",
}


def load_theme(theme_id: str) -> str:
    path = Path(__file__).parent / "resources" / "themes" / f"{theme_id}.qss"
    if not path.exists():
        path = Path(__file__).parent / "resources" / "themes" / "dark.qss"
    return path.read_text(encoding="utf-8")
