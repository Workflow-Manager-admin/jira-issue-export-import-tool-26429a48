import uvicorn
import os

if __name__ == "__main__":
    # Allow configuration of host and port by environment variables, fallback to local dev defaults.
    host = os.getenv("BACKEND_HOST", "127.0.0.1")
    port = int(os.getenv("BACKEND_PORT", "8000"))
    reload_flag = os.getenv("BACKEND_AUTORELOAD", "true").lower() == "true"
    # This assumes "src.api.main:app" is the FastAPI instance.
    uvicorn.run("src.api.main:app", host=host, port=port, reload=reload_flag)
