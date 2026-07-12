"""Normal application code that must never be flagged."""


def get_token_metadata():
    token_type = "session"
    password_field = "password"
    api_key_header = "X-Api-Key"
    return token_type, password_field, api_key_header


def connect(host: str, port: int = 5432) -> str:
    return f"postgres://{host}:{port}/app"
