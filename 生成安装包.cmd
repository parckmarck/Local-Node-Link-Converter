@echo off
title NodeDesk Installer Build
cd /d "%~dp0"

set "PYEXE="
if not defined PYEXE call :try "py -3.12"
if not defined PYEXE call :try "py -3"
if not defined PYEXE call :try "python"
if not defined PYEXE goto nopython

%PYEXE% scripts\build_windows.py --installer-only
if errorlevel 1 goto failed
echo.
echo NodeDesk: setup file is ready in the dist folder.
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
echo [ERROR] The installer was not generated. See the output above.

:end
echo.
pause
