@echo off
setlocal
if not exist "%~dp0dist\NodeDesk\NodeDesk.exe" (
    echo NodeDesk.exe was not found. Build the project first.
    pause
    exit /b 1
)
start "" "%~dp0dist\NodeDesk\NodeDesk.exe"
