@echo off
title ACCUM Node — Mining Active
color 0A

REM --- Start Wallet (hidden) ---
start "" "accum-wallet.exe" gui

REM --- Open Dashboard ---
timeout /t 3 >nul
start "" "http://127.0.0.1:8555"

echo ===================================================
echo               ACCUM (PoCI) IS RUNNING
echo ===================================================
echo.
echo  - Node is loading blocks... (see logs below)
echo  - Dashboard is open at: http://127.0.0.1:8555
echo  - Wallet is open at:    http://127.0.0.1:8556
echo.
echo  To STOP safely, double-click stop.bat
echo ===================================================
echo.

REM --- Start Node (in this window, logs will appear below) ---
accum-node.exe node