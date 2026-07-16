# Architecture

The GUI runs on the Qt main thread. `ScanWorker`, a dedicated `QThread`, owns the
sequential scan pipeline. It emits Qt signals for:

- overall progress
- phase progress
- indeterminate phase state
- current file
- live log output
- incremental findings
- completion or failure

Pause and cancellation are implemented with `threading.Event`. External scanner
processes are launched from the worker and polled so cancellation can terminate
them without freezing the GUI.

The passive engine never imports the target package. Dependency versions are
read from distribution metadata. Pickle inspection uses `pickletools.genops`
rather than deserialization.
