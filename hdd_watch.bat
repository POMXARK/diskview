@echo off
chcp 65001 >nul
title HDD Watch
cd /d "%~dp0"
if not "%~1"=="" (
    python "%~dp0hdd_watch.py" %*
    goto :done
)
set "DRV="
set /p "DRV=Буква диска (например S, Enter = все): "
if "%DRV%"=="" (
    python "%~dp0hdd_watch.py"
) else (
    python "%~dp0hdd_watch.py" %DRV%
)
:done
pause
