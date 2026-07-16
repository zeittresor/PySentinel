# Changelog

## 0.9.2
- Fixed the post-scan findings-filter crash reported by the Qt TypeError log
- Ensured `QTableWidget.setRowHidden()` always receives a real Boolean value
- Hardened filtering against temporarily incomplete rows during live result insertion
- Added a regression test for empty and non-empty filter queries

## 0.9.1
- Fixed a probable post-scan crash caused by writing reports beside protected target folders
- Added persistent rotating application logs and Python faulthandler crash logs
- Added a dedicated diagnostic directory for every scan
- Added scan options, environment snapshot, completion metadata and error files
- Moved report generation into the worker thread and made all writes atomic
- Added safe fallback behavior for inaccessible additional report directories
- Added Open Logs, Open Scan Folder and Create Support Bundle actions
- Added chunked/capped GUI population for very large inventories and finding sets
- Added a debug launcher for failures before the GUI can initialize

## 0.9.0
- Initial application skeleton and functional passive scan engine
- Threaded scan execution with pause, resume and cancel
- Overall and phase progress indicators
- Source, dependency, archive, Pickle and tensor/model inspection
- Optional external scanner integration
- Multilingual responsive PyQt6 GUI and eight themes
- JSON, Markdown and HTML reports
- Windows installer, local virtual environment and wheelhouse workflow
