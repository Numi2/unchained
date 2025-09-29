@echo off
setlocal ENABLEDELAYEDEXPANSION

REM Change to the directory of this script
cd /d "%~dp0"

REM Ensure the executable exists next to this launcher
if not exist "%CD%\unchained.exe" (
echo ERROR: unchained.exe not found in %CD%
exit /b 9009
)

REM Prefer a co-located config.toml if present; otherwise rely on embedded defaults
set CFG_ARG=
if exist "%CD%\config.toml" (
set CFG_ARG=--config "%CD%\config.toml"
set CFG_MSG=%CD%\config.toml
) else (
set CFG_MSG=embedded default (no config.toml found)
)

echo -----------------------------------------
echo   Launching unchained node for Windows
echo   Working dir: %CD%
echo   Config:      %CFG_MSG%
echo -----------------------------------------
echo.

REM Start the node. With no args it will mine if mining.enabled=true in config.toml
"%CD%\unchained.exe" %CFG_ARG% %*

set ERR=%ERRORLEVEL%
if %ERR% NEQ 0 (
  echo.
  echo The node exited with error code %ERR%.
  echo Press any key to close this window...
  pause >nul
  exit /b %ERR%
)

endlocal

