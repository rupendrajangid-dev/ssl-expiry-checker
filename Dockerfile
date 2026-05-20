# Use a secure, official lightweight Python slim image
FROM python:3.10-slim

# Set system-level settings and prevent Python from writing pyc files or buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the operational directory inside the container
WORKDIR /app

# Copy requirements file first to take advantage of Docker build caching layers
COPY requirements.txt .

# Install minimal application dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files (core script and default JSON configurations)
COPY ssl_monitor.py config.json domains.json ./

# Create a local directory for logging output
RUN mkdir -p logs

# Run the SSL validation monitor on startup
CMD ["python", "ssl_monitor.py"]
