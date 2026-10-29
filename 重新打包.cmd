@echo off
title NodeDesk Build
cd /d "%~dp0"

set "PYEXE="
if not defined PYEXE call :try "py -3.12"
if not defined PYEXE call :try "py -3"
if not defined PYEXE call :try "python"
if not defined PYEXE goto nopython

echo NodeDesk: building, please keep this window open (about 1-3 minutes)...
echo.
%PYEXE% scripts\build_windows.py
if errorlevel 1 goto failed
echo.
echo NodeDesk: build finished. See the dist folder for the new version.
goto end

:try
%~1 --version >nul 2>nul
if not errorlevel 1 set "PYEXE=%~1"
goto :eof

:nopython
echo [ERROR] Python was not found. Install Python 3.12 and enable
echo "Add python.exe to PATH" during installation.
goto end

:failed
echo.
echo [ERROR] The build did not finish. Please send the output above for help.

:end
echo.
pause
