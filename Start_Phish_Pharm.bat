@echo off
setlocal

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo Python was not found.
    echo Install Python, then run Start_Phish_Pharm.bat again.
    pause
    exit /b 1
)

set "DESKTOP_PATH="
if defined OneDriveCommercial if exist "%OneDriveCommercial%\Desktop" set "DESKTOP_PATH=%OneDriveCommercial%\Desktop"
if not defined DESKTOP_PATH if defined OneDrive if exist "%OneDrive%\Desktop" set "DESKTOP_PATH=%OneDrive%\Desktop"
if not defined DESKTOP_PATH set "DESKTOP_PATH=%USERPROFILE%\Desktop"

set "INBOX_PATH=%DESKTOP_PATH%\Inbox"
set "REPORTS_PATH=%DESKTOP_PATH%\Reports"

python "%~dp0src\bootstrap.py" --watch "%INBOX_PATH%" --output "%REPORTS_PATH%" --format html

echo.
echo Phish Pharm has stopped.
pause
