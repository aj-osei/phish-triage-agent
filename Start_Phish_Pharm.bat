@echo off
setlocal

cd /d "%~dp0"

set "DESKTOP_PATH="
if defined OneDriveCommercial if exist "%OneDriveCommercial%\Desktop" set "DESKTOP_PATH=%OneDriveCommercial%\Desktop"
if not defined DESKTOP_PATH if defined OneDrive if exist "%OneDrive%\Desktop" set "DESKTOP_PATH=%OneDrive%\Desktop"
if not defined DESKTOP_PATH set "DESKTOP_PATH=%USERPROFILE%\Desktop"

set "INBOX_PATH=%DESKTOP_PATH%\Inbox"
set "REPORTS_PATH=%DESKTOP_PATH%\Reports"

python src\main.py --watch "%INBOX_PATH%" --output "%REPORTS_PATH%" --format html

echo.
echo Phish Pharm has stopped.
pause
