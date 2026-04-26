FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
CMD ["gunicorn", \
     "-w", "4", \
     "-k", "gevent", \
     "--worker-connections", "200", \
     "--timeout", "30", \
     "-b", "0.0.0.0:5001", \
     "target_app:app"]
