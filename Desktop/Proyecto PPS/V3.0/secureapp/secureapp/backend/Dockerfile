FROM python:3.12-slim

# Usuario no-root por seguridad (OWASP A04 — mínimos privilegios)
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Instalar dependencias del sistema necesarias para bcrypt
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5001

# Usar gunicorn en producción en lugar de Flask dev server
CMD ["python", "app.py"]
