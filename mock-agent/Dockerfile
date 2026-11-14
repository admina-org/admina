FROM python:3.15-slim
WORKDIR /app
RUN pip install --no-cache-dir httpx
COPY main.py .
CMD ["python", "main.py"]
