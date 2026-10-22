@echo off
rem Double-click to run the whole EMCON demo: server + browser with the extension loaded.
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js 22+ is required: https://nodejs.org & pause & exit /b 1)
node scripts\demo.mjs %*
pause
