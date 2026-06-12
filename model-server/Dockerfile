FROM python:3.11-slim

WORKDIR /app


# Install system dependencies (Nano text editor)
RUN apt-get update && apt-get install -y nano && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy model and server
COPY ids_model/ ./ids_model/
COPY main.py .

# Expose port
EXPOSE 8000

# Run server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]