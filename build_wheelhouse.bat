@echo off
setlocal EnableExtensions
cd /d "%~dp0"
if not exist wheelhouse mkdir wheelhouse
py -3 -m pip download --dest wheelhouse -r requirements.txt -r requirements-tools.txt
if errorlevel 1 (
  echo [ERROR] Wheelhouse build failed.
  pause
  exit /b 1
)
echo [OK] Wheelhouse is ready in "%CD%\wheelhouse".
pause
