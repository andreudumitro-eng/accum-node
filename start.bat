@echo off
cd /d "%~dp0"
start "" "target\release\accum-node.exe" node
timeout /t 3 >nul
start "" "http://127.0.0.1:8555"
