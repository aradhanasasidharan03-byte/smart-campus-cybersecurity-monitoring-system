import os

from wsgi import app


if __name__ == "__main__":
    host = "0.0.0.0" if os.environ.get("APP_ENV", "development").lower() == "production" else "127.0.0.1"
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
