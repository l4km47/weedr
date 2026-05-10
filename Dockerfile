FROM python:3.12-slim-bookworm

RUN useradd -r -m -u 10001 weedr

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER weedr

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=5000

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "-w", "2", "--timeout", "120", "app:app"]
