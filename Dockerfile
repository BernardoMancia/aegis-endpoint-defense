FROM python:3.11-slim

WORKDIR /app

COPY server/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ .

RUN mkdir -p data

EXPOSE 5000

ENV PYTHONUNBUFFERED=1

CMD ["python", "run.py"]
