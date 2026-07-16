@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
set "VERSION=0.9.2"
set "LOG=%CD%\install_pysentinel_%VERSION%.log"

for /F "delims=" %%e in ('echo prompt $E^| cmd') do set "ESC=%%e"
set "C_RESET=!ESC![0m"
set "C_HEAD=!ESC![96m"
set "C_STEP=!ESC![94m"
set "C_WARN=!ESC![38;5;208m"
set "C_ERR=!ESC![91m"
set "C_OK=!ESC![92m"

echo !C_HEAD!============================================================!C_RESET!
echo !C_HEAD! PySentinel Security Scanner - Installer v%VERSION%!C_RESET!
echo !C_HEAD!============================================================!C_RESET!
echo Installation log: "%LOG%"
echo.

call :log "Starting installation"

where py >nul 2>nul
if errorlevel 1 (
  echo !C_ERR![ERROR] Python launcher "py" was not found.!C_RESET!
  call :log "ERROR: Python launcher not found"
  pause
  exit /b 1
)

py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 (
  echo !C_ERR![ERROR] Python 3.11 or newer is required.!C_RESET!
  call :log "ERROR: Python version below 3.11"
  pause
  exit /b 1
)

echo !C_STEP![1/5] Creating project-local virtual environment...!C_RESET!
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv >>"%LOG%" 2>&1
  if errorlevel 1 goto :fail
) else (
  echo !C_WARN![WARN] Existing .venv will be reused.!C_RESET!
)

set "PY=%CD%\.venv\Scripts\python.exe"

echo !C_STEP![2/5] Updating packaging tools...!C_RESET!
if exist "wheelhouse" (
  "%PY%" -m pip install --no-index --find-links wheelhouse --upgrade pip setuptools wheel >>"%LOG%" 2>&1
) else (
  "%PY%" -m pip install --upgrade pip setuptools wheel >>"%LOG%" 2>&1
)
if errorlevel 1 goto :fail

echo !C_STEP![3/5] Installing PySentinel...!C_RESET!
if exist "wheelhouse" (
  "%PY%" -m pip install --no-index --find-links wheelhouse -r requirements.txt >>"%LOG%" 2>&1
) else (
  "%PY%" -m pip install -r requirements.txt >>"%LOG%" 2>&1
)
if errorlevel 1 goto :fail
"%PY%" -m pip install -e . >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo !C_STEP![4/5] Installing security scanner integrations...!C_RESET!
if exist "wheelhouse" (
  "%PY%" -m pip install --no-index --find-links wheelhouse -r requirements-tools.txt >>"%LOG%" 2>&1
) else (
  "%PY%" -m pip install -r requirements-tools.txt >>"%LOG%" 2>&1
)
if errorlevel 1 (
  echo !C_WARN![WARN] One or more optional scanner tools failed to install.!C_RESET!
  echo !C_WARN!       PySentinel itself is installed and passive scans remain available.!C_RESET!
  call :log "WARNING: Optional tools installation failed"
)

echo !C_STEP![5/5] Verifying application...!C_RESET!
"%PY%" -m compileall -q pysentinel >>"%LOG%" 2>&1
if errorlevel 1 goto :fail

echo.
echo !C_OK![OK] PySentinel v%VERSION% installed successfully.!C_RESET!
call :log "Installation completed successfully"
echo.
choice /C YN /N /T 10 /D Y /M "Start PySentinel now? [Y/N] Auto-start in 10 seconds: "
if errorlevel 2 exit /b 0
start "" "%PY%" -m pysentinel
exit /b 0

:fail
echo.
echo !C_ERR![ERROR] Installation failed. See log: "%LOG%"!C_RESET!
call :log "ERROR: Installation failed"
pause
exit /b 1

:log
echo [%date% %time%] %~1>>"%LOG%"
exit /b 0
