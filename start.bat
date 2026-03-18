@echo off
echo.
echo  =============================================
echo   RealVulnScan - Starting server...
echo  =============================================
echo.

where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo  ERROR: Node.js is not installed!
    echo  Download from: https://nodejs.org
    echo.
    pause
    exit /b 1
)

if not exist node_modules (
    echo  Installing dependencies...
    npm install
    echo.
)

echo  Server starting at: http://localhost:3000
echo  Open that URL in your browser to scan.
echo.
echo  Press Ctrl+C to stop.
echo.
node server.js
pause
