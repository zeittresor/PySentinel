# PySentinel 0.9.2

PySentinel is a passive-first security scanner for already installed or unpacked
Python applications. It inventories files and dependencies, inspects Python
source code, analyzes Pickle opcodes without deserializing the object, recognizes
common tensor/model containers and optionally orchestrates external scanners.

## Safety model

PySentinel does **not** import the target project and does not execute its Python
interpreter during the default scan. Active or external checks are clearly
separated. A clean result is not proof that software is safe.

## Main features

- Responsive PyQt6 GUI with English, German, French and Russian UI
- Light, Dark, Sepia, Ocean, Matrix, Hellfire, Purple and Aurora themes
- Dedicated scan worker thread; the GUI remains responsive
- Overall and current-phase progress bars
- Pause, resume and cancel
- Live findings, current file, elapsed time and log output
- Passive dependency inventory from `*.dist-info/METADATA`
- SHA-256 inventory
- AST/text heuristics for suspicious Python behavior
- Pickle opcode inspection without `pickle.load`
- PyTorch ZIP checkpoint and NPZ/NPY container inspection
- Keras ZIP config inspection for Lambda layers
- Native binary and script inventory
- Optional Bandit, pip-audit, ModelScan, Fickling and Microsoft Defender checks
- JSON, Markdown and standalone HTML reports
- Persistent settings and configurable file-size limits
- Full-HD-friendly default dimensions and scrollable settings/help pages

## Windows installation

Run:

```bat
install_windows.bat
```

The installer creates a project-local `.venv`, installs the GUI and scanner
tools, writes a log and offers an automatic start after a 10-second countdown.

For offline preparation on an online PC:

```bat
build_wheelhouse.bat
```

Copy the complete folder to the offline PC and run `install_windows.bat`.

## Start manually

```bat
run_app.bat
```

Original source / updates: github.com/zeittresor


## Diagnostic logs

PySentinel writes persistent diagnostics under:

```text
%LOCALAPPDATA%\PySentinel\logs
```

Every scan receives its own directory containing:

- `scan.log`
- `scan_options.json`
- `environment.json`
- `completion.json`
- `error.txt` when an error occurs
- `reports\` with JSON, Markdown and HTML reports

The Log tab can open the current scan directory or create a ZIP support bundle.
For failures before the GUI appears, run `run_debug.bat`.


## 0.9.2 filter crash fix

Version 0.9.2 fixes a Qt type error after scans when the findings search box is
empty. The filter result is now explicitly converted to `bool`, and incomplete
rows are ignored safely while live results are being inserted.
