FROM docker.io/library/python:3.13-slim
RUN pip install --no-cache-dir "uvicorn[standard]"
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
