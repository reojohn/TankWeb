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
echo [FortressAuth v3] Validating the React source build...
call npm run build
if errorlevel 1 goto :fail

echo.
echo [FortressAuth v3] Source validation build complete.
echo Output: react-build\
echo.
echo NOTE: This intentionally does NOT overwrite public\app\.
echo The deployed runtime there contains the PHP auth gate, vendored libraries,
echo and the tested parity bundle used by local, Render, and Vercel deployments.
echo.
pause
exit /b 0

:fail
echo.
echo [FortressAuth v3] The React source validation build failed.
echo The deployed public\app runtime was not modified.
echo.
pause
exit /b 1
