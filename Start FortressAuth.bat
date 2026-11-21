@echo off
setlocal EnableExtensions
cd /d "%~dp0"
title FortressAuth v3 - Start System

echo =====================================================
echo   FortressAuth v3 - One-Click Launcher
echo =====================================================
rem Local launcher: prefer the private root .env over stale inherited Windows
rem variables. Children of this BAT inherit the cleaned process environment.
rem This is NOT used by cloud deployment, which must use provider secrets.
if exist ".env" (
  for %%V in (DB_HOST DB_PORT DB_NAME DB_USER DB_PASS DB_SSLMODE ML_SERVICE_TOKEN ML_SERVICE_URL ML_SERVICE_ENABLED ML_TIMEOUT_MS IT113_PUBLIC_DEMO_ENABLED IT113_DEMO_PERSISTENCE_ENABLED IT113_DB_CONNECT_TIMEOUT_SECONDS) do set "%%V="
)

if not exist "public\assessment\index.html" (
  echo ERROR: public\assessment\index.html not found.
  echo Place this BAT directly in your existing TankWeb-v3 folder.
  pause
  exit /b 1
)

set "PHP_EXE="
where php.exe >nul 2>nul
if not errorlevel 1 set "PHP_EXE=php.exe"
if not defined PHP_EXE if exist "C:\xampp3\php\php.exe" set "PHP_EXE=C:\xampp3\php\php.exe"
if not defined PHP_EXE if exist "C:\xampp\php\php.exe" set "PHP_EXE=C:\xampp\php\php.exe"
if not defined PHP_EXE (
  echo ERROR: PHP not found. Install PHP or check your XAMPP installation.
  pause
  exit /b 1
)

rem Do not start a second copy if the expected ports are already in use.
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 8082 -State Listen -ErrorAction SilentlyContinue) { exit 1 }" >nul 2>nul
if errorlevel 1 (
  echo Port 8082 is already in use. PHP startup skipped.
  echo IMPORTANT: Stop the older PHP server first if you updated .env or the project files.
) else (
  echo Starting PHP on 127.0.0.1:8082 ...
  start "FortressAuth PHP" /D "%~dp0" cmd /k ""%PHP_EXE%" -S 127.0.0.1:8082 -t public"
)

set "PY_EXE="
if exist "ml-service\.venv\Scripts\python.exe" set "PY_EXE=%~dp0ml-service\.venv\Scripts\python.exe"
if not defined PY_EXE if exist ".venv\Scripts\python.exe" set "PY_EXE=%~dp0.venv\Scripts\python.exe"
if not defined PY_EXE (
  where py.exe >nul 2>nul
  if not errorlevel 1 set "PY_EXE=py -3"
)
if not defined PY_EXE (
  where python.exe >nul 2>nul
  if not errorlevel 1 set "PY_EXE=python"
)
if not exist "ml-service\app.py" goto :OPEN_SITE
if not defined PY_EXE (
  echo Python not found - optional ML service was not started.
  goto :OPEN_SITE
)
%PY_EXE% -c "import uvicorn, fastapi, xgboost, joblib" >nul 2>nul
if errorlevel 1 (
  echo Optional ML service dependencies missing; skipping ML.
  echo Install in the Python environment: pip install -r ml-service\requirements.txt
  goto :OPEN_SITE
)
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 8001 -State Listen -ErrorAction SilentlyContinue) { exit 1 }" >nul 2>nul
if errorlevel 1 (
  echo Port 8001 is already in use. ML startup skipped.
) else (
  echo Starting optional ML service on 127.0.0.1:8001 ...
  rem start_local.py loads the same private root .env as PHP, and requires a strong token.
  start "FortressAuth ML" /D "%~dp0ml-service" cmd /k "%PY_EXE% start_local.py"
)

:OPEN_SITE
echo.
echo Opening FortressAuth: http://127.0.0.1:8082/assessment/
echo Keep the server windows open while using the system.
echo Close them or press Ctrl+C in each to stop the system.
echo Note: Existing .env settings and database availability still matter.
start "" "http://127.0.0.1:8082/assessment/"
echo.
pause
endlocal
