@echo off
title ACCUM Node — Mining Active
color 0A
echo ===================================================
echo               ACCUM NODE IS RUNNING
echo ===================================================
echo.
echo  Do NOT close this window. If you close it, 
echo  the node will stop and you will lose sync.
echo.
echo  To stop safely:  Press Ctrl+C  OR  Double-click stop.bat
echo ===================================================
echo.

start "" "http://127.0.0.1:8555"
accum-node.exe node