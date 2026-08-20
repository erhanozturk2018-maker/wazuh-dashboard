FROM python:3.11.9-slim
WORKDIR /app
COPY . .
RUN pip install .
CMD ["python", "main.py"]