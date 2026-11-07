@echo off
title ACCUM Node - Mining Active
color 0A

REM --- Change to script directory ---
cd /d "%~dp0"

REM --- Start Wallet (hidden) ---
start "" "%~dp0accum-wallet.exe" gui

REM --- Open Dashboard ---
timeout /t 5 >nul
start "" "http://127.0.0.1:8555"

echo ===================================================
echo               ACCUM (PoCI) IS RUNNING
echo ===================================================
echo.
echo  - Node is loading blocks... (see logs below)
echo  - Dashboard: http://127.0.0.1:8555
echo  - Wallet:    http://127.0.0.1:8556
echo.
echo  HOW TO STOP:
echo  1. Easiest: Just close this window (click X).
echo  2. Or run stop.bat in the same folder.
echo  3. Or press Ctrl+C on your keyboard.
echo ===================================================
echo.

REM --- Start Node (logs will appear below) ---
"%~dp0accum-node.exe" node
