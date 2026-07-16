# Security model and limitations

PySentinel is designed to reduce exposure while inspecting untrusted Python
applications, but it is not a sandbox and not a proof system.

- Do not scan highly untrusted files on a production workstation.
- Prefer a disposable VM or Windows Sandbox.
- External tools may contain parser vulnerabilities.
- Antivirus results and static analysis are advisory.
- A malicious installer may already have executed before a post-install scan.
- Never call `pickle.load`, `torch.load`, `joblib.load`, `dill.load` or equivalent
  on untrusted data merely to inspect it.
