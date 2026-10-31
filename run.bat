@echo off
setlocal
cd /d "%~dp0"
if "%ACCUM_DASHBOARD_PORT%"=="" set ACCUM_DASHBOARD_PORT=8555
echo Building ACCUM (release)...
cargo build --release
if errorlevel 1 goto :error
set BIN=target\release\accum-node.exe
if not exist "%BIN%" (
  echo Could not find %BIN%
  goto :error
)
echo Starting node with dashboard on http://127.0.0.1:%ACCUM_DASHBOARD_PORT%
"%BIN%" node --dashboard --dashboard-port %ACCUM_DASHBOARD_PORT%
goto :eof
:error
echo Build or launch failed.
exit /b 1