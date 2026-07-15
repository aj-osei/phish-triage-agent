@echo off
setlocal

cd /d "%~dp0"

set "DESKTOP_PATH="
if defined OneDriveCommercial if exist "%OneDriveCommercial%\Desktop" set "DESKTOP_PATH=%OneDriveCommercial%\Desktop"
if not defined DESKTOP_PATH if defined OneDrive if exist "%OneDrive%\Desktop" set "DESKTOP_PATH=%OneDrive%\Desktop"
if not defined DESKTOP_PATH set "DESKTOP_PATH=%USERPROFILE%\Desktop"

set "INBOX_PATH=%DESKTOP_PATH%\Inbox"
set "REPORTS_PATH=%DESKTOP_PATH%\Reports"

echo.
echo Desktop path: %DESKTOP_PATH%
echo Inbox path: %INBOX_PATH%
echo Reports path: %REPORTS_PATH%
echo.

if not exist "%INBOX_PATH%" mkdir "%INBOX_PATH%"
if not exist "%INBOX_PATH%" (
    echo ERROR: Could not create the Inbox folder.
    echo Expected path: %INBOX_PATH%
    pause
    exit /b 1
)

if not exist "%REPORTS_PATH%" mkdir "%REPORTS_PATH%"
if not exist "%REPORTS_PATH%" (
    echo ERROR: Could not create the Reports folder.
    echo Expected path: %REPORTS_PATH%
    pause
    exit /b 1
)

echo Phish Pharm is watching the Inbox folder.
echo Drop .eml files into the Inbox path shown above.
echo Reports will appear in the Reports path shown above.
echo Press Ctrl+C to stop.
echo.

python src\main.py --watch "%INBOX_PATH%" --output "%REPORTS_PATH%" --format both

echo.
echo Phish Pharm has stopped.
pause
