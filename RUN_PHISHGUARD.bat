@echo off
setlocal
cd /d "%~dp0"
echo ==========================================
echo   PHISHGUARD AI - REAL ML EDITION
echo ==========================================
where py >nul 2>&1
if %errorlevel%==0 (
  set PY=py
) else (
  set PY=python
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PY% -m venv .venv
  if errorlevel 1 goto :err
)
call ".venv\Scripts\activate.bat"
echo Installing/updating dependencies...
if not exist ".env" (
  echo Creating secure local environment file...
  python scripts\init_env.py
  if errorlevel 1 goto :err
)
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 goto :err
if not exist "dataset\phishing_dataset.csv" (
  echo Downloading REAL public dataset feeds...
  python dataset\download_real_dataset.py
  if errorlevel 1 goto :err
)
if not exist "models\phishguard_model.pkl" (
  echo Training ML model and calculating actual metrics...
  python train_model.py
  if errorlevel 1 goto :err
)
echo Starting PhishGuard...
start "" "http://127.0.0.1:5000"
python app.py
goto :eof
:err
echo.
echo Setup failed. Copy the error and share it for help.
pause
