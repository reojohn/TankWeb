@echo off
setlocal
cd /d "%~dp0frontend"

where npm >nul 2>nul
if errorlevel 1 (
  echo.
  echo [FortressAuth v3] npm was not found.
  echo Install Node.js, then run this file again.
  echo.
  pause
  exit /b 1
)

echo.
echo [FortressAuth v3] Installing pinned React and Vite packages...
call npm install --no-audit --no-fund
if errorlevel 1 goto :fail

echo.
echo [FortressAuth v3] Building the React application...
call npm run build
if errorlevel 1 goto :fail

echo.
echo [FortressAuth v3] Build complete.
echo React entry: public\app\index.html
echo Login will now enter /app/#/overview automatically.
echo.
pause
exit /b 0

:fail
echo.
echo [FortressAuth v3] The React build failed. The original PHP interface remains usable as a fallback.
echo.
pause
exit /b 1
