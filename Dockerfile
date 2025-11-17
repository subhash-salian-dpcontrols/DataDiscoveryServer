# Use official Python runtime
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install system dependencies and Python packages
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    libpq-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove -y gcc python3-dev \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy application code and templates
COPY . .

# Create directories if they don't exist
RUN mkdir -p templates static

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV API_KEY=supersecretkey123
ENV DATABASE_URL=postgresql://postgres:postgres@db:5432/pii_data

# Expose the port
EXPOSE 8000

# Change the CMD to use python -m
CMD ["python", "-m", "uvicorn", "DataDiscoveryServer:app", "--host", "0.0.0.0", "--port", "8000"]
