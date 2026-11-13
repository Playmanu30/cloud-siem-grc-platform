@echo off
setlocal
cd /d "%~dp0"

set "PORT=%PORT%"
if "%PORT%"=="" set "PORT=8000"

where python >nul 2>nul
if errorlevel 1 (
  echo [error] Python not found. Install Python 3.12 or newer and retry.
  pause
  exit /b 1
)

if not exist "venv\Scripts\python.exe" (
  echo [1/3] Creating virtual environment...
  python -m venv venv || goto :fail
) else (
  echo [1/3] Virtual environment found.
)

echo [2/3] Installing dependencies...
"venv\Scripts\python.exe" -m pip install --quiet --upgrade pip || goto :fail
"venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || goto :fail

if not exist ".env" (
  echo [3/3] No .env found, copying .env.example
  copy /y ".env.example" ".env" >nul
) else (
  echo [3/3] .env found.
)

REM Refuse to start if the port is already taken (avoids Errno 10048)
netstat -ano | findstr /r /c:":%PORT% .*LISTENING" >nul
if not errorlevel 1 goto :port_busy

echo.
echo Starting Cloud SIEM ^& GRC Platform on http://localhost:%PORT%
echo   Dashboard:  http://localhost:%PORT%/
echo   API docs:   http://localhost:%PORT%/docs
echo   Health:     http://localhost:%PORT%/health
echo Press Ctrl+C to stop.
echo.
"venv\Scripts\python.exe" -m uvicorn src.api.main:app --host 127.0.0.1 --port %PORT%
exit /b %errorlevel%

:port_busy
set "BUSY_PID="
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:":%PORT% .*LISTENING"') do if not defined BUSY_PID set "BUSY_PID=%%p"
echo.
echo [error] Port %PORT% is already in use (PID %BUSY_PID%).
echo         Another instance is probably still running. Stop it with:
echo             taskkill /PID %BUSY_PID% /F
echo         or start on a different port:
echo             set PORT=8001 ^& run.bat
pause
exit /b 1

:fail
echo.
echo [error] Setup failed. See the message above.
pause
exit /b 1
