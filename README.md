# jira-issue-export-import-tool-26429a48

## Running the Backend (FastAPI) Locally

1. Install requirements:
    ```sh
    pip install -r jira_syncer_backend/requirements.txt
    ```

2. Start the backend server:
    ```sh
    cd jira_syncer_backend
    python run.py
    ```

    By default, the backend will be available at [http://localhost:8000](http://localhost:8000).

3. You can customize the host and port via environment variables:

    - `BACKEND_HOST` (default: `127.0.0.1`)
    - `BACKEND_PORT` (default: `8000`)
    - `BACKEND_AUTORELOAD` (`true` or `false`, default: `true`)

    Example:
    ```sh
    BACKEND_HOST=0.0.0.0 BACKEND_PORT=8000 python run.py
    ```

4. Make sure your frontend (React) is configured to send requests to `http://localhost:8000` for local development.

5. For Docker or remote/local network access, set `BACKEND_HOST` to `0.0.0.0`.

### FastAPI docs:
Once running locally, visit: [http://localhost:8000/docs](http://localhost:8000/docs) for interactive API docs.
