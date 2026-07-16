@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Virtual environment not found. Run install_windows.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -X faulthandler -m pysentinel
