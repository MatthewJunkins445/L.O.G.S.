#!/bin/bash
set -e

echo "Building Python backend..."

cd python-backend

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install -r requirements.txt
pip install pyinstaller

# Build the backend binary
pyinstaller \
    --onefile \
    --name secureshield-backend \
    --add-data "app:app" \
    --collect-data win10toast \
    --hidden-import win10toast \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops \
    --hidden-import uvicorn.loops.auto \
    --hidden-import uvicorn.protocols \
    --hidden-import uvicorn.protocols.http \
    --hidden-import uvicorn.protocols.http.auto \
    --hidden-import uvicorn.protocols.websockets \
    --hidden-import uvicorn.protocols.websockets.auto \
    --hidden-import uvicorn.lifespan \
    --hidden-import uvicorn.lifespan.on \
    main.py

echo "Backend built: python-backend/dist/secureshield-backend"
