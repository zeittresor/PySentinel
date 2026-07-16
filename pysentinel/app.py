from __future__ import annotations

import logging
import sys

from PyQt6.QtCore import QCoreApplication, QTimer
from PyQt6.QtWidgets import QApplication

from . import __version__
from .logging_utils import (
    APP_LOGGER_NAME,
    initialize_logging,
    install_exception_hooks,
)
from .main_window import MainWindow


def main() -> int:
    paths = initialize_logging()
    logger = logging.getLogger(APP_LOGGER_NAME)
    logger.info("Starting PySentinel %s", __version__)

    QCoreApplication.setOrganizationName("zeittresor")
    QCoreApplication.setApplicationName("PySentinel")
    install_exception_hooks()
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    try:
        window = MainWindow(runtime_paths=paths)
    except Exception:
        logger.exception("Main window initialization failed")
        raise

    def show_unhandled(title: str, details: str) -> None:
        QTimer.singleShot(0, lambda: window.show_unhandled_exception(title, details))

    install_exception_hooks(show_unhandled)
    window.show()
    exit_code = app.exec()
    logger.info("Qt event loop exited with code %s", exit_code)
    return exit_code
