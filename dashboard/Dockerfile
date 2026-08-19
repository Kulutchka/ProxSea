FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/

# SQLite DB lives on its own volume so rule data survives container
# recreation independently of the Squid config volume.
VOLUME ["/data"]

EXPOSE 5000

# Single worker: this is a low-traffic admin panel, not something that
# needs to scale, and a single worker keeps the SQLite access simple
# (no cross-process locking concerns).
CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && gunicorn --bind 0.0.0.0:5000 --workers 1 app:app"]
