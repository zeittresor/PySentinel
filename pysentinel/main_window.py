from __future__ import annotations

import logging
import os
import time
import traceback
import zipfile
from pathlib import Path

from PyQt6.QtCore import QTimer, Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import __version__
from .i18n import Translator
from .logging_utils import APP_LOGGER_NAME, RuntimePaths, ScanLogSession, utc_now
from .models import Finding, ScanOptions, ScanResult, Severity
from .reporting import write_html, write_json, write_markdown
from .scan_engine import ScanWorker
from .settings import AppSettings
from .themes import THEMES, load_theme


class MainWindow(QMainWindow):
    MAX_INVENTORY_UI_ROWS = 25000
    MAX_FINDINGS_UI_ROWS = 25000

    def __init__(self, runtime_paths: RuntimePaths) -> None:
        super().__init__()
        self.runtime_paths = runtime_paths
        self.logger = logging.getLogger(APP_LOGGER_NAME)
        self.scan_session: ScanLogSession | None = None
        self._high_count = 0
        self._displayed_findings = 0
        self._inventory_records: list[dict] = []
        self._inventory_index = 0
        self._inventory_population_token = 0
        self.settings = AppSettings()
        self.translator = Translator(str(self.settings.get("language", "en")))
        self.worker: ScanWorker | None = None
        self.last_result: ScanResult | None = None
        self.started_monotonic = 0.0
        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.timeout.connect(self._update_elapsed)

        self._build_ui()
        self._restore_settings()
        self._apply_theme()
        self._retranslate()
        self._fit_to_screen()

    def _build_ui(self) -> None:
        self.setMinimumSize(960, 640)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.scan_tab = QWidget()
        self.results_tab = QWidget()
        self.inventory_tab = QWidget()
        self.log_tab = QWidget()
        self.settings_tab = QWidget()
        self.help_tab = QWidget()
        self.about_tab = QWidget()

        for tab in (
            self.scan_tab, self.results_tab, self.inventory_tab, self.log_tab,
            self.settings_tab, self.help_tab, self.about_tab,
        ):
            pass

        self.tabs.addTab(self.scan_tab, "")
        self.tabs.addTab(self.results_tab, "")
        self.tabs.addTab(self.inventory_tab, "")
        self.tabs.addTab(self.log_tab, "")
        self.tabs.addTab(self.settings_tab, "")
        self.tabs.addTab(self.help_tab, "")
        self.tabs.addTab(self.about_tab, "")

        self._build_scan_tab()
        self._build_results_tab()
        self._build_inventory_tab()
        self._build_log_tab()
        self._build_settings_tab()
        self._build_help_tab()
        self._build_about_tab()

        self.setStatusBar(QStatusBar())
        self.status_label = QLabel()
        self.statusBar().addWidget(self.status_label, 1)
        self.elapsed_label = QLabel("00:00:00")
        self.statusBar().addPermanentWidget(self.elapsed_label)

    def _build_scan_tab(self) -> None:
        outer = QVBoxLayout(self.scan_tab)

        target_group = QGroupBox()
        self.target_group = target_group
        target_layout = QGridLayout(target_group)
        self.target_edit = QLineEdit()
        self.target_edit.setClearButtonEnabled(True)
        self.browse_button = QPushButton()
        self.browse_button.clicked.connect(self._browse_target)
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Quick", "quick")
        self.profile_combo.addItem("Standard", "standard")
        self.profile_combo.addItem("Deep", "deep")
        self.profile_combo.addItem("Custom", "custom")
        self.profile_combo.currentIndexChanged.connect(self._profile_changed)
        target_layout.addWidget(self.target_edit, 0, 0, 1, 4)
        target_layout.addWidget(self.browse_button, 0, 4)
        self.profile_label = QLabel()
        target_layout.addWidget(self.profile_label, 1, 0)
        target_layout.addWidget(self.profile_combo, 1, 1, 1, 2)

        self.options_group = QGroupBox()
        options_layout = QGridLayout(self.options_group)
        self.checks: dict[str, QCheckBox] = {}
        option_specs = [
            ("inventory", True), ("hashes", True), ("source_scan", True),
            ("dependency_scan", True), ("pickle_scan", True), ("archive_scan", True),
            ("external_bandit", True), ("external_pip_audit", True),
            ("external_modelscan", True), ("external_fickling", True),
            ("defender_scan", False), ("follow_symlinks", False),
        ]
        for idx, (name, checked) in enumerate(option_specs):
            box = QCheckBox()
            box.setChecked(checked)
            self.checks[name] = box
            options_layout.addWidget(box, idx // 3, idx % 3)

        progress_group = QGroupBox()
        self.progress_group = progress_group
        progress_layout = QGridLayout(progress_group)
        self.overall_label = QLabel()
        self.overall_progress = QProgressBar()
        self.overall_progress.setRange(0, 100)
        self.phase_label = QLabel()
        self.phase_progress = QProgressBar()
        self.phase_progress.setRange(0, 100)
        self.current_item_label = QLabel()
        self.current_item_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.current_item_label.setWordWrap(True)
        progress_layout.addWidget(self.overall_label, 0, 0)
        progress_layout.addWidget(self.overall_progress, 0, 1)
        progress_layout.addWidget(self.phase_label, 1, 0)
        progress_layout.addWidget(self.phase_progress, 1, 1)
        progress_layout.addWidget(self.current_item_label, 2, 0, 1, 2)

        buttons = QHBoxLayout()
        self.start_button = QPushButton()
        self.start_button.clicked.connect(self._start_scan)
        self.pause_button = QPushButton()
        self.pause_button.clicked.connect(self._toggle_pause)
        self.pause_button.setEnabled(False)
        self.cancel_button = QPushButton()
        self.cancel_button.clicked.connect(self._cancel_scan)
        self.cancel_button.setEnabled(False)
        self.open_report_button = QPushButton()
        self.open_report_button.clicked.connect(self._open_report_folder)
        self.open_report_button.setEnabled(False)
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.pause_button)
        buttons.addWidget(self.cancel_button)
        buttons.addStretch(1)
        buttons.addWidget(self.open_report_button)

        summary_group = QGroupBox()
        self.summary_group = summary_group
        summary_layout = QGridLayout(summary_group)
        self.summary_files = QLabel("0")
        self.summary_findings = QLabel("0")
        self.summary_high = QLabel("0")
        self.summary_models = QLabel("0")
        self.summary_labels = [QLabel() for _ in range(4)]
        values = [self.summary_files, self.summary_findings, self.summary_high, self.summary_models]
        for index, (label, value) in enumerate(zip(self.summary_labels, values)):
            summary_layout.addWidget(label, 0, index)
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            value.setObjectName("summaryValue")
            summary_layout.addWidget(value, 1, index)

        outer.addWidget(target_group)
        outer.addWidget(self.options_group)
        outer.addWidget(progress_group)
        outer.addLayout(buttons)
        outer.addWidget(summary_group)
        outer.addStretch(1)

    def _build_results_tab(self) -> None:
        layout = QVBoxLayout(self.results_tab)
        filters = QHBoxLayout()
        self.severity_filter = QComboBox()
        self.severity_filter.currentIndexChanged.connect(self._apply_result_filter)
        self.search_filter = QLineEdit()
        self.search_filter.setClearButtonEnabled(True)
        self.search_filter.textChanged.connect(self._apply_result_filter)
        self.export_json_button = QPushButton()
        self.export_json_button.clicked.connect(lambda: self._export_report("json"))
        self.export_md_button = QPushButton()
        self.export_md_button.clicked.connect(lambda: self._export_report("md"))
        self.export_html_button = QPushButton()
        self.export_html_button.clicked.connect(lambda: self._export_report("html"))
        filters.addWidget(self.severity_filter)
        filters.addWidget(self.search_filter, 1)
        filters.addWidget(self.export_json_button)
        filters.addWidget(self.export_md_button)
        filters.addWidget(self.export_html_button)

        self.findings_table = QTableWidget(0, 7)
        self.findings_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.findings_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.findings_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.itemSelectionChanged.connect(self._show_selected_finding)

        self.finding_details = QPlainTextEdit()
        self.finding_details.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.findings_table)
        splitter.addWidget(self.finding_details)
        splitter.setSizes([500, 180])

        layout.addLayout(filters)
        layout.addWidget(splitter)

    def _build_inventory_tab(self) -> None:
        layout = QVBoxLayout(self.inventory_tab)
        self.inventory_search = QLineEdit()
        self.inventory_search.setClearButtonEnabled(True)
        self.inventory_search.textChanged.connect(self._apply_inventory_filter)
        self.inventory_table = QTableWidget(0, 5)
        self.inventory_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.inventory_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.inventory_table.verticalHeader().setVisible(False)
        self.inventory_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.inventory_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.inventory_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.inventory_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.inventory_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.inventory_search)
        layout.addWidget(self.inventory_table)

    def _build_log_tab(self) -> None:
        layout = QVBoxLayout(self.log_tab)
        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)

        buttons = QHBoxLayout()
        self.copy_log_button = QPushButton()
        self.copy_log_button.clicked.connect(
            lambda: QApplication.clipboard().setText(self.log_edit.toPlainText())
        )
        self.open_logs_button = QPushButton()
        self.open_logs_button.clicked.connect(self._open_logs_folder)
        self.open_scan_folder_button = QPushButton()
        self.open_scan_folder_button.clicked.connect(self._open_current_scan_folder)
        self.open_scan_folder_button.setEnabled(False)
        self.support_bundle_button = QPushButton()
        self.support_bundle_button.clicked.connect(self._create_support_bundle)
        self.support_bundle_button.setEnabled(False)

        buttons.addWidget(self.copy_log_button)
        buttons.addWidget(self.open_logs_button)
        buttons.addWidget(self.open_scan_folder_button)
        buttons.addWidget(self.support_bundle_button)
        buttons.addStretch(1)

        layout.addWidget(self.log_edit)
        layout.addLayout(buttons)

    def _scrollable_form(self) -> tuple[QScrollArea, QWidget, QFormLayout]:
        area = QScrollArea()
        area.setWidgetResizable(True)
        content = QWidget()
        form = QFormLayout(content)
        area.setWidget(content)
        return area, content, form

    def _build_settings_tab(self) -> None:
        layout = QVBoxLayout(self.settings_tab)
        area, _, form = self._scrollable_form()
        self.language_combo = QComboBox()
        self.language_combo.addItem("English", "en")
        self.language_combo.addItem("Deutsch", "de")
        self.language_combo.addItem("Français", "fr")
        self.language_combo.addItem("Русский", "ru")
        self.language_combo.currentIndexChanged.connect(self._language_changed)
        self.theme_combo = QComboBox()
        for theme_id, name in THEMES.items():
            self.theme_combo.addItem(name, theme_id)
        self.theme_combo.currentIndexChanged.connect(self._theme_changed)
        self.max_size_spin = QSpinBox()
        self.max_size_spin.setRange(1, 32768)
        self.max_size_spin.setValue(256)
        self.max_entries_spin = QSpinBox()
        self.max_entries_spin.setRange(100, 1_000_000)
        self.max_entries_spin.setValue(10000)
        self.output_edit = QLineEdit()
        self.output_browse = QPushButton("...")
        self.output_browse.clicked.connect(self._browse_output)
        output_row = QWidget()
        output_layout = QHBoxLayout(output_row)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.addWidget(self.output_edit)
        output_layout.addWidget(self.output_browse)
        self.tooltips_check = QCheckBox()
        self.tooltips_check.setChecked(True)
        self.tooltips_check.toggled.connect(self._apply_tooltips)
        self.confirm_active_check = QCheckBox()
        self.confirm_active_check.setChecked(True)
        self.settings_form = form
        self.setting_labels = [QLabel() for _ in range(7)]
        form.addRow(self.setting_labels[0], self.language_combo)
        form.addRow(self.setting_labels[1], self.theme_combo)
        form.addRow(self.setting_labels[2], self.max_size_spin)
        form.addRow(self.setting_labels[3], self.max_entries_spin)
        form.addRow(self.setting_labels[4], output_row)
        form.addRow(self.setting_labels[5], self.tooltips_check)
        form.addRow(self.setting_labels[6], self.confirm_active_check)
        layout.addWidget(area)

    def _build_help_tab(self) -> None:
        layout = QVBoxLayout(self.help_tab)
        self.help_edit = QPlainTextEdit()
        self.help_edit.setReadOnly(True)
        layout.addWidget(self.help_edit)

    def _build_about_tab(self) -> None:
        layout = QVBoxLayout(self.about_tab)
        self.about_label = QLabel()
        self.about_label.setWordWrap(True)
        self.about_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
        self.about_label.setOpenExternalLinks(True)
        layout.addWidget(self.about_label)
        layout.addStretch(1)

    def _fit_to_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if not screen:
            self.resize(1280, 820)
            return
        available = screen.availableGeometry()
        width = min(1320, max(960, int(available.width() * 0.88)))
        height = min(840, max(640, int(available.height() * 0.88)))
        self.resize(width, height)
        self.move(
            available.x() + (available.width() - width) // 2,
            available.y() + (available.height() - height) // 2,
        )

    def _restore_settings(self) -> None:
        language = str(self.settings.get("language", "en"))
        index = self.language_combo.findData(language)
        self.language_combo.setCurrentIndex(max(index, 0))
        theme = str(self.settings.get("theme", "dark"))
        index = self.theme_combo.findData(theme)
        self.theme_combo.setCurrentIndex(max(index, 0))
        self.max_size_spin.setValue(self.settings.get_int("max_file_mib", 256))
        self.max_entries_spin.setValue(self.settings.get_int("max_archive_entries", 10000))
        self.output_edit.setText(str(self.settings.get("output_dir", "")))
        self.target_edit.setText(str(self.settings.get("last_target", "")))
        self.tooltips_check.setChecked(self.settings.get_bool("tooltips", True))
        self.confirm_active_check.setChecked(self.settings.get_bool("confirm_active", True))
        self._apply_tooltips(self.tooltips_check.isChecked())

    def _save_settings(self) -> None:
        self.settings.set("language", self.language_combo.currentData())
        self.settings.set("theme", self.theme_combo.currentData())
        self.settings.set("max_file_mib", self.max_size_spin.value())
        self.settings.set("max_archive_entries", self.max_entries_spin.value())
        self.settings.set("output_dir", self.output_edit.text())
        self.settings.set("last_target", self.target_edit.text())
        self.settings.set("tooltips", self.tooltips_check.isChecked())
        self.settings.set("confirm_active", self.confirm_active_check.isChecked())
        self.settings.sync()

    def closeEvent(self, event) -> None:
        self._save_settings()
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)
        super().closeEvent(event)

    def _apply_theme(self) -> None:
        QApplication.instance().setStyleSheet(load_theme(str(self.theme_combo.currentData() or "dark")))

    def _language_changed(self) -> None:
        self.translator.load(str(self.language_combo.currentData() or "en"))
        self._retranslate()
        self._save_settings()

    def _theme_changed(self) -> None:
        self._apply_theme()
        self._save_settings()

    def _retranslate(self) -> None:
        tr = self.translator.tr
        self.setWindowTitle(f"PySentinel {__version__} — {tr('window_title')}")
        for index, key in enumerate(("tab_scan", "tab_findings", "tab_inventory", "tab_log", "tab_settings", "tab_help", "tab_about")):
            self.tabs.setTabText(index, tr(key))
        self.target_group.setTitle(tr("target"))
        self.browse_button.setText(tr("browse"))
        self.profile_label.setText(tr("profile"))
        current_profile = self.profile_combo.currentData()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItem(tr("profile_quick"), "quick")
        self.profile_combo.addItem(tr("profile_standard"), "standard")
        self.profile_combo.addItem(tr("profile_deep"), "deep")
        self.profile_combo.addItem(tr("profile_custom"), "custom")
        profile_index = self.profile_combo.findData(current_profile)
        self.profile_combo.setCurrentIndex(max(profile_index, 1))
        self.profile_combo.blockSignals(False)
        for label, key in zip(
            self.setting_labels,
            ("language", "theme", "maximum_file_size", "maximum_archive_entries",
             "report_directory", "tooltips", "confirm_active_checks"),
        ):
            label.setText(tr(key))
        self.options_group.setTitle(tr("scan_modules"))
        for key, box in self.checks.items():
            box.setText(tr(f"opt_{key}"))
        self.progress_group.setTitle(tr("progress"))
        self.overall_label.setText(tr("overall_progress"))
        self.phase_label.setText(tr("phase_progress"))
        self.start_button.setText(tr("start_scan"))
        self.pause_button.setText(tr("pause"))
        self.cancel_button.setText(tr("cancel"))
        self.open_report_button.setText(tr("open_report_folder"))
        self.summary_group.setTitle(tr("summary"))
        for label, key in zip(self.summary_labels, ("files", "findings", "high_findings", "model_files")):
            label.setText(tr(key))
        self.search_filter.setPlaceholderText(tr("filter_findings"))
        self.inventory_search.setPlaceholderText(tr("filter_inventory"))
        self.export_json_button.setText(tr("export_json"))
        self.export_md_button.setText(tr("export_markdown"))
        self.export_html_button.setText(tr("export_html"))
        self.copy_log_button.setText(tr("copy_log"))
        self.open_logs_button.setText(tr("open_logs_folder"))
        self.open_scan_folder_button.setText(tr("open_scan_folder"))
        self.support_bundle_button.setText(tr("create_support_bundle"))
        self.tooltips_check.setText(tr("enabled"))
        self.confirm_active_check.setText(tr("enabled"))
        self.status_label.setText(tr("ready"))
        self.findings_table.setHorizontalHeaderLabels([
            tr("severity"), tr("scanner"), tr("rule"), tr("title"),
            tr("description"), tr("path"), tr("line"),
        ])
        self.inventory_table.setHorizontalHeaderLabels([
            tr("path"), tr("size"), tr("type"), "SHA-256", tr("model_candidate"),
        ])
        current = self.severity_filter.currentData()
        self.severity_filter.blockSignals(True)
        self.severity_filter.clear()
        self.severity_filter.addItem(tr("all_severities"), 0)
        for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            self.severity_filter.addItem(severity.label, int(severity))
        index = self.severity_filter.findData(current)
        self.severity_filter.setCurrentIndex(max(index, 0))
        self.severity_filter.blockSignals(False)
        self.help_edit.setPlainText(tr("help_text"))
        self.about_label.setText(tr("about_text", version=__version__))
        self._apply_tooltips(self.tooltips_check.isChecked())

    def _apply_tooltips(self, enabled: bool) -> None:
        tr = self.translator.tr
        tooltip_map = {
            self.target_edit: tr("tip_target"),
            self.profile_combo: tr("tip_profile"),
            self.start_button: tr("tip_start"),
            self.pause_button: tr("tip_pause"),
            self.cancel_button: tr("tip_cancel"),
            self.overall_progress: tr("tip_overall_progress"),
            self.phase_progress: tr("tip_phase_progress"),
            self.max_size_spin: tr("tip_max_size"),
            self.max_entries_spin: tr("tip_max_entries"),
        }
        for widget, tooltip in tooltip_map.items():
            widget.setToolTip(tooltip if enabled else "")
        for name, box in self.checks.items():
            box.setToolTip(tr(f"tip_{name}", tr(f"opt_{name}")) if enabled else "")

    def _browse_target(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self.translator.tr("target"))
        if path:
            self.target_edit.setText(path)

    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, self.translator.tr("report_directory"))
        if path:
            self.output_edit.setText(path)

    def _profile_changed(self) -> None:
        profile = self.profile_combo.currentData()
        if profile == "quick":
            values = {
                "inventory": True, "hashes": False, "source_scan": True,
                "dependency_scan": True, "pickle_scan": True, "archive_scan": True,
                "external_bandit": False, "external_pip_audit": False,
                "external_modelscan": False, "external_fickling": False,
                "defender_scan": False,
            }
        elif profile == "deep":
            values = {key: True for key in self.checks}
            values["follow_symlinks"] = False
        elif profile == "standard":
            values = {
                "inventory": True, "hashes": True, "source_scan": True,
                "dependency_scan": True, "pickle_scan": True, "archive_scan": True,
                "external_bandit": True, "external_pip_audit": True,
                "external_modelscan": True, "external_fickling": True,
                "defender_scan": False, "follow_symlinks": False,
            }
        else:
            return
        for key, value in values.items():
            if key in self.checks:
                self.checks[key].setChecked(value)

    def _start_scan(self) -> None:
        target = self.target_edit.text().strip()
        if not target or not Path(target).exists():
            QMessageBox.warning(self, self.translator.tr("invalid_target"), self.translator.tr("choose_valid_target"))
            return

        active = any(self.checks[name].isChecked() for name in ("external_bandit", "external_pip_audit", "external_modelscan", "external_fickling", "defender_scan"))
        if active and self.confirm_active_check.isChecked():
            answer = QMessageBox.question(
                self,
                self.translator.tr("active_checks"),
                self.translator.tr("active_checks_warning"),
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        self.findings_table.setRowCount(0)
        self.inventory_table.setRowCount(0)
        self.finding_details.clear()
        self.log_edit.clear()
        self.last_result = None
        self._high_count = 0
        self._displayed_findings = 0
        self._inventory_population_token += 1
        self.open_scan_folder_button.setEnabled(False)
        self.support_bundle_button.setEnabled(False)
        self.summary_files.setText("0")
        self.summary_findings.setText("0")
        self.summary_high.setText("0")
        self.summary_models.setText("0")
        self.overall_progress.setValue(0)
        self.phase_progress.setRange(0, 100)
        self.phase_progress.setValue(0)

        options = ScanOptions(
            target=target,
            profile=str(self.profile_combo.currentData()),
            max_file_mib=self.max_size_spin.value(),
            max_archive_entries=self.max_entries_spin.value(),
            output_dir=self.output_edit.text().strip(),
            **{name: box.isChecked() for name, box in self.checks.items()},
        )
        try:
            self.scan_session = ScanLogSession.create(
                self.runtime_paths.scans_dir,
                target,
                options,
            )
            options.scan_dir = str(self.scan_session.directory)
            options.scan_log_path = str(self.scan_session.log_path)
            from .logging_utils import write_json_atomic
            write_json_atomic(self.scan_session.options_path, options)
            self.scan_session.append(f"PySentinel version: {__version__}")
            self.scan_session.append(f"Selected profile: {options.profile}")
            self._append_log(
                f"{utc_now()} | INFO | Scan log: {self.scan_session.log_path}"
            )
        except Exception as exc:
            self.logger.exception("Could not create scan log session")
            QMessageBox.critical(
                self,
                self.translator.tr("scan_failed"),
                f"{self.translator.tr('log_directory_error')}\n\n{exc}",
            )
            return

        self.worker = ScanWorker(options)
        self.worker.overall_progress.connect(self.overall_progress.setValue)
        self.worker.phase_progress.connect(self.phase_progress.setValue)
        self.worker.phase_indeterminate.connect(self._set_phase_indeterminate)
        self.worker.phase_changed.connect(self._phase_changed)
        self.worker.current_item.connect(self.current_item_label.setText)
        self.worker.log_message.connect(self._append_log)
        self.worker.finding_found.connect(self._add_finding)
        self.worker.result_ready.connect(self._scan_finished)
        self.worker.failed.connect(self._scan_failed)
        self.worker.finished.connect(self._worker_stopped)
        self.worker.start()

        self.started_monotonic = time.monotonic()
        self.elapsed_timer.start(1000)
        self.start_button.setEnabled(False)
        self.pause_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.status_label.setText(self.translator.tr("scanning"))
        self._save_settings()

    def _set_phase_indeterminate(self, enabled: bool) -> None:
        self.phase_progress.setRange(0, 0 if enabled else 100)
        if not enabled:
            self.phase_progress.setValue(0)

    def _phase_changed(self, text: str) -> None:
        self.phase_label.setText(f"{self.translator.tr('phase_progress')}: {text}")

    def _append_log(self, text: str) -> None:
        try:
            self.log_edit.appendPlainText(text)
        except RuntimeError:
            self.logger.exception("Could not append to GUI log")

    def _add_finding(self, finding: Finding) -> None:
        try:
            total_findings = int(self.summary_findings.text() or "0") + 1
        except ValueError:
            total_findings = 1
        self.summary_findings.setText(str(total_findings))

        if finding.severity >= Severity.HIGH:
            self._high_count += 1
            self.summary_high.setText(str(self._high_count))

        if self._displayed_findings >= self.MAX_FINDINGS_UI_ROWS:
            return

        row = self.findings_table.rowCount()
        self.findings_table.insertRow(row)
        values = [
            finding.severity.label,
            finding.scanner,
            finding.rule_id,
            finding.title,
            finding.description,
            finding.path,
            "" if finding.line is None else str(finding.line),
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setData(Qt.ItemDataRole.UserRole, finding)
            self.findings_table.setItem(row, column, item)
        self._displayed_findings += 1

        if row % 100 == 0:
            QTimer.singleShot(0, self._apply_result_filter)

    def _scan_finished(self, result: ScanResult) -> None:
        try:
            self.last_result = result
            self.summary_files.setText(str(result.files_seen))
            self.summary_findings.setText(str(len(result.findings)))
            self.summary_high.setText(
                str(sum(1 for item in result.findings if item.severity >= Severity.HIGH))
            )
            model_count = sum(
                1 for record in result.inventory if record.get("model_candidate")
            )
            self.summary_models.setText(str(model_count))

            self._begin_inventory_population(result.inventory)

            scan_dir = result.artifacts.get("scan_dir")
            report_dir = result.artifacts.get("report_dir")
            if scan_dir:
                self.settings.set("last_scan_dir", scan_dir)
                self.open_scan_folder_button.setEnabled(True)
                self.support_bundle_button.setEnabled(True)
            if report_dir:
                self.settings.set("last_report_dir", report_dir)
                self.open_report_button.setEnabled(True)

            if len(result.findings) > self.MAX_FINDINGS_UI_ROWS:
                self._append_log(
                    f"{utc_now()} | WARNING | GUI finding display limited to "
                    f"{self.MAX_FINDINGS_UI_ROWS}; full findings remain in reports."
                )

            self.status_label.setText(
                self.translator.tr("scan_cancelled")
                if result.cancelled
                else self.translator.tr("scan_complete")
            )
            self.tabs.setCurrentWidget(self.results_tab)

            if self.scan_session:
                self.scan_session.append(
                    f"GUI received result: files={result.files_seen}; "
                    f"findings={len(result.findings)}; cancelled={result.cancelled}"
                )
        except Exception as exc:
            self._handle_ui_exception("Finishing scan results", exc)

    def _begin_inventory_population(self, inventory: list[dict]) -> None:
        self._inventory_population_token += 1
        token = self._inventory_population_token
        self._inventory_records = inventory[: self.MAX_INVENTORY_UI_ROWS]
        self._inventory_index = 0
        self.inventory_table.setUpdatesEnabled(False)
        self.inventory_table.setRowCount(len(self._inventory_records))
        self.inventory_table.setUpdatesEnabled(True)
        QTimer.singleShot(0, lambda: self._populate_inventory_chunk(token))

        if len(inventory) > self.MAX_INVENTORY_UI_ROWS:
            self._append_log(
                f"{utc_now()} | WARNING | GUI inventory display limited to "
                f"{self.MAX_INVENTORY_UI_ROWS}; complete inventory remains in JSON."
            )

    def _populate_inventory_chunk(self, token: int) -> None:
        if token != self._inventory_population_token:
            return

        end = min(self._inventory_index + 300, len(self._inventory_records))
        self.inventory_table.setUpdatesEnabled(False)
        try:
            for row in range(self._inventory_index, end):
                record = self._inventory_records[row]
                values = [
                    record.get("path", ""),
                    str(record.get("size", "")),
                    record.get("suffix", ""),
                    record.get("sha256", ""),
                    "Yes" if record.get("model_candidate") else "",
                ]
                for column, value in enumerate(values):
                    self.inventory_table.setItem(row, column, QTableWidgetItem(value))
        finally:
            self.inventory_table.setUpdatesEnabled(True)

        self._inventory_index = end
        if end < len(self._inventory_records):
            QTimer.singleShot(0, lambda: self._populate_inventory_chunk(token))

    def _scan_failed(self, message: str) -> None:
        self.status_label.setText(self.translator.tr("scan_failed"))
        self.logger.error("Scan failed: %s", message)
        if self.scan_session:
            self.scan_session.write_error("Scan worker failed", message)
            self.settings.set("last_scan_dir", str(self.scan_session.directory))
            self.open_scan_folder_button.setEnabled(True)
            self.support_bundle_button.setEnabled(True)
        QMessageBox.critical(self, self.translator.tr("scan_failed"), message)

    def _worker_stopped(self) -> None:
        self.elapsed_timer.stop()
        self.start_button.setEnabled(True)
        self.pause_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.pause_button.setProperty("paused", False)
        self.pause_button.setText(self.translator.tr("pause"))
        self.phase_progress.setRange(0, 100)

    def _toggle_pause(self) -> None:
        if not self.worker:
            return
        paused = bool(self.pause_button.property("paused"))
        if paused:
            self.worker.resume()
            self.pause_button.setProperty("paused", False)
            self.pause_button.setText(self.translator.tr("pause"))
            self.status_label.setText(self.translator.tr("scanning"))
        else:
            self.worker.pause()
            self.pause_button.setProperty("paused", True)
            self.pause_button.setText(self.translator.tr("resume"))
            self.status_label.setText(self.translator.tr("paused"))

    def _cancel_scan(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.status_label.setText(self.translator.tr("cancelling"))

    def _update_elapsed(self) -> None:
        elapsed = max(0, int(time.monotonic() - self.started_monotonic))
        hours, rem = divmod(elapsed, 3600)
        minutes, seconds = divmod(rem, 60)
        self.elapsed_label.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

    def _show_selected_finding(self) -> None:
        items = self.findings_table.selectedItems()
        if not items:
            return
        finding = items[0].data(Qt.ItemDataRole.UserRole)
        if not isinstance(finding, Finding):
            return
        self.finding_details.setPlainText(
            f"Severity: {finding.severity.label}\n"
            f"Scanner: {finding.scanner}\n"
            f"Rule: {finding.rule_id}\n"
            f"Path: {finding.path}\n"
            f"Line: {finding.line or ''}\n\n"
            f"{finding.description}\n\n"
            f"Evidence:\n{finding.evidence}\n\n"
            f"Recommendation:\n{finding.recommendation}"
        )

    def _apply_result_filter(self) -> None:
        minimum = int(self.severity_filter.currentData() or 0)
        query = self.search_filter.text().strip().lower()

        for row in range(self.findings_table.rowCount()):
            severity_item = self.findings_table.item(row, 0)
            if severity_item is None:
                # A row may briefly be incomplete while many live findings are inserted.
                self.findings_table.setRowHidden(row, False)
                continue

            finding = severity_item.data(Qt.ItemDataRole.UserRole)
            if not isinstance(finding, Finding):
                self.findings_table.setRowHidden(row, False)
                continue

            haystack = " ".join(
                item.text().lower()
                for column in range(self.findings_table.columnCount())
                if (item := self.findings_table.item(row, column)) is not None
            )

            severity_hidden = int(finding.severity) < minimum
            text_hidden = bool(query) and query not in haystack
            self.findings_table.setRowHidden(
                row,
                bool(severity_hidden or text_hidden),
            )

    def _apply_inventory_filter(self) -> None:
        query = self.inventory_search.text().strip().lower()
        for row in range(self.inventory_table.rowCount()):
            haystack = " ".join(
                self.inventory_table.item(row, col).text().lower()
                for col in range(self.inventory_table.columnCount())
                if self.inventory_table.item(row, col)
            )
            self.inventory_table.setRowHidden(row, bool(query and query not in haystack))

    def _handle_ui_exception(self, context: str, exc: BaseException) -> None:
        details = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        self.logger.critical("UI exception during %s\n%s", context, details)
        if self.scan_session:
            self.scan_session.write_error(f"UI exception during {context}", exc)
            self.settings.set("last_scan_dir", str(self.scan_session.directory))
            self.open_scan_folder_button.setEnabled(True)
            self.support_bundle_button.setEnabled(True)
        self.status_label.setText(self.translator.tr("scan_failed"))
        QMessageBox.critical(
            self,
            self.translator.tr("scan_failed"),
            f"{context}\n\n{exc}\n\n"
            f"{self.translator.tr('error_logged_to')}\n"
            f"{self.scan_session.directory if self.scan_session else self.runtime_paths.logs_dir}",
        )

    def show_unhandled_exception(self, title: str, details: str) -> None:
        try:
            if self.scan_session:
                self.scan_session.write_error(title, details)
                directory = self.scan_session.directory
            else:
                directory = self.runtime_paths.app_logs_dir
            QMessageBox.critical(
                self,
                self.translator.tr("unexpected_error"),
                f"{self.translator.tr('unexpected_error_text')}\n\n"
                f"{details.splitlines()[-1] if details else title}\n\n"
                f"{self.translator.tr('error_logged_to')}\n{directory}",
            )
        except Exception:
            self.logger.exception("Could not show unhandled exception dialog")

    def _open_logs_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.runtime_paths.logs_dir)))

    def _open_current_scan_folder(self) -> None:
        directory = ""
        if self.scan_session:
            directory = str(self.scan_session.directory)
        if not directory:
            directory = str(self.settings.get("last_scan_dir", ""))
        if directory and Path(directory).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(directory))

    def _create_support_bundle(self) -> None:
        if self.scan_session:
            source_dir = self.scan_session.directory
        else:
            stored_directory = str(self.settings.get("last_scan_dir", "")).strip()
            if not stored_directory:
                return
            source_dir = Path(stored_directory)

        if not source_dir.exists():
            return
        bundle = source_dir / f"pysentinel_support_{time.strftime('%Y%m%d_%H%M%S')}.zip"
        try:
            with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in source_dir.rglob("*"):
                    if (
                        not path.is_file()
                        or path == bundle
                        or path.name.startswith("pysentinel_support_")
                    ):
                        continue
                    archive.write(path, path.relative_to(source_dir))

                for app_log in self.runtime_paths.app_logs_dir.glob("*.log"):
                    archive.write(app_log, Path("application_logs") / app_log.name)

            self._append_log(f"{utc_now()} | INFO | Support bundle created: {bundle}")
            QMessageBox.information(
                self,
                self.translator.tr("support_bundle_created"),
                str(bundle),
            )
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(source_dir)))
        except Exception as exc:
            self._handle_ui_exception("Creating support bundle", exc)

    def _export_report(self, format_name: str) -> None:
        if not self.last_result:
            return
        filters = {
            "json": "JSON (*.json)",
            "md": "Markdown (*.md)",
            "html": "HTML (*.html)",
        }
        path, _ = QFileDialog.getSaveFileName(self, self.translator.tr("export_report"), "", filters[format_name])
        if not path:
            return
        output = Path(path)
        try:
            if format_name == "json":
                write_json(self.last_result, output)
            elif format_name == "md":
                write_markdown(self.last_result, output)
            else:
                write_html(self.last_result, output)
        except Exception as exc:
            self._handle_ui_exception("Exporting report", exc)

    def _open_report_folder(self) -> None:
        directory = str(self.settings.get("last_report_dir", ""))
        if directory and Path(directory).exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(directory))

    def _scan_module_enabled(self, name: str) -> bool:
        return self.checks[name].isChecked()

