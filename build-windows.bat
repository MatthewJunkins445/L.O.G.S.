@echo off
setlocal
echo ========================================
echo Building L.O.G.S. Security Tool
echo ========================================

echo.
echo Step 1: Building Python backend...
cd python-backend

set "PYTHON_CMD=py -3.12"
%PYTHON_CMD% --version >nul 2>&1
if errorlevel 1 (
    set "PYTHON_CMD=python"
)

if exist venv\pyvenv.cfg if not exist venv\Scripts\python.exe (
    echo Existing venv is not a Windows virtual environment. Recreating it...
    rmdir /s /q venv
)

if not exist venv\Scripts\python.exe (
    %PYTHON_CMD% -m venv venv
    if errorlevel 1 exit /b 1
)

call venv\Scripts\activate.bat
if errorlevel 1 exit /b 1

python -m pip install --upgrade pip setuptools wheel
if errorlevel 1 exit /b 1
python -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
python -m pip install pyinstaller
if errorlevel 1 exit /b 1

if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

python -m PyInstaller ^
    --clean ^
    --noconfirm ^
    --noupx ^
    --onefile ^
    --name secureshield-backend ^
    --add-data "app;app" ^
    --collect-data win10toast ^
    --exclude-module Pythonwin ^
    --exclude-module win32ui ^
    --hidden-import win10toast ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.loops ^
    --hidden-import uvicorn.loops.auto ^
    --hidden-import uvicorn.protocols ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.protocols.websockets ^
    --hidden-import uvicorn.protocols.websockets.auto ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    main.py
if errorlevel 1 exit /b 1
cd ..

echo.
echo Step 2: Copying backend to Tauri...
if not exist src-tauri\binaries mkdir src-tauri\binaries
copy python-backend\dist\secureshield-backend.exe src-tauri\binaries\secureshield-backend-x86_64-pc-windows-msvc.exe
if errorlevel 1 exit /b 1

echo.
echo Step 3: Building Tauri app...
call npm install
if errorlevel 1 exit /b 1
call npm run tauri build
if errorlevel 1 exit /b 1

echo.
echo ========================================
echo Build complete!
echo ========================================
echo.
echo Installers created in:
echo   src-tauri\target\release\bundle\nsis\
echo   src-tauri\target\release\bundle\msi\
echo.
pause
