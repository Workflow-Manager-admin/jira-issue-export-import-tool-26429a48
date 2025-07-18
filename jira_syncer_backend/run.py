import uvicorn

if __name__ == "__main__":
    # This assumes "src.api.main:app" is the FastAPI instance.
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
