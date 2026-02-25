FROM python:3.11-slim

WORKDIR /app

COPY server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY server/ /app/

RUN mkdir -p /app/data

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "run.py"]

