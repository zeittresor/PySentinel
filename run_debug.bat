@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Virtual environment not found. Run install_windows.bat first.
  pause
  exit /b 1
)

set "LOGROOT=%LOCALAPPDATA%\PySentinel\logs\launcher"
if not exist "%LOGROOT%" mkdir "%LOGROOT%"

for /f "tokens=1-4 delims=/:. " %%a in ("%date% %time%") do (
  set "STAMP=%%d%%b%%c_%%a"
)
set "LOGFILE=%LOGROOT%\launcher_%RANDOM%_%STAMP%.log"

echo PySentinel debug launcher
echo Output: "%LOGFILE%"
echo.

".venv\Scripts\python.exe" -X faulthandler -m pysentinel >>"%LOGFILE%" 2>&1
set "EXITCODE=%ERRORLEVEL%"

echo.
echo PySentinel exited with code %EXITCODE%.
echo Diagnostic output: "%LOGFILE%"
pause
exit /b %EXITCODE%
