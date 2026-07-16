# Diagnostics and support bundles

PySentinel 0.9.1 stores diagnostics in the user's writable application data
directory instead of writing beside the scanned target.

On Windows:

```text
%LOCALAPPDATA%\PySentinel\logs
```

## Application logs

`logs\app\pysentinel_app.log` is a rotating application log. Additional
`faulthandler_*.log` files capture low-level Python faults and thread traces.

## Per-scan folders

Each scan gets a timestamped folder below `logs\scans` containing:

- `scan.log`: phases, external-tool output, warnings and completion messages
- `scan_options.json`: exact enabled modules and limits
- `environment.json`: Python, platform, executable and process information
- `completion.json`: final status, counters, artifacts and scanner status
- `error.txt`: worker, UI or report exceptions when they occur
- `reports\`: JSON, Markdown and HTML results

Reports are always created inside this writable scan folder. A configured report
directory is treated as an optional additional copy destination. Failure to
write that additional destination is logged but no longer closes the app.

## Support bundle

The Log tab offers **Create support bundle**. It creates a ZIP containing the
current scan diagnostics and application logs. The bundle contains file paths
and scanner findings, so review it before sharing when privacy matters.

## Early-start failures

Use `run_debug.bat` when the application closes before the GUI appears. It
redirects stdout, stderr and Python faulthandler output to:

```text
%LOCALAPPDATA%\PySentinel\logs\launcher
```
