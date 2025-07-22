# Repository Guidelines

This project is a Flask-based password manager with REST APIs and a web UI.  It uses SQLAlchemy and stores secrets using Fernet encryption.  The repo contains tests under the `tests/` directory using `pytest`.

## Development Setup

1. Create and activate a virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Generate an encryption key if required:
   ```bash
   python keygen.py
   ```
4. Create a `.env` file with database settings. Example variables and defaults are listed in `README.md`.

## Running the Application

To launch the Flask app locally:
```bash
python app.py
```
It runs on port 5000 by default.

## Testing

- Run the test suite with:
  ```bash
  pytest
  ```
- Always ensure all tests pass before committing changes.
- If new features are added, provide corresponding tests in the `tests/` directory.

## Style

- Follow standard Python conventions (PEP 8). Keep functions small and readable.
- Use uppercase usernames consistently, as shown in the existing code.

