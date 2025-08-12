@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Change to the directory of this script
cd /d "%~dp0"

echo -----------------------------------------
echo   Launching unchained node for Windows
echo   Working dir: %CD%
echo   Config:      %CD%\config.toml
echo -----------------------------------------
echo.

REM Start the node. With no args it will mine if mining.enabled=true in config.toml
"%CD%\unchained.exe" %*

set ERR=%ERRORLEVEL%
if %ERR% NEQ 0 (
  echo.
  echo The node exited with error code %ERR%.
  echo Press any key to close this window...
  pause >nul
  exit /b %ERR%
)

endlocal

