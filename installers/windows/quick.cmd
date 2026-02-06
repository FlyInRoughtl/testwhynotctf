@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wizard.ps1" -Quick
endlocal
