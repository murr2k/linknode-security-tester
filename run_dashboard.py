#!/usr/bin/env python3
"""Run the enhanced security project dashboard."""

import uvicorn
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.web.project_dashboard import app

if __name__ == "__main__":
    print("Starting Security Project Dashboard...")
    print("Access the dashboard at: http://localhost:8000")
    print("Press CTRL+C to stop the server")
    
    # Run the FastAPI application
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )