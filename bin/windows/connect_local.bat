@echo off
cd /d "%~dp0"
if not exist "CoD2MP_s.exe" (
    echo CoD2MP_s.exe not found in "%~dp0"
    echo Copy this folder next to your CoD2 install or place CoD2MP_s.exe here.
    pause
    exit /b 1
)
start "" "%~dp0CoD2MP_s.exe" +connect 127.0.0.1
