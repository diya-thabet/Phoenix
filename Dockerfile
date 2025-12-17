# Use Python 3.10
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install System Dependencies (libpcap is needed for Scapy sniffing)
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy files
COPY . /app

# Install Python Dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Make the start script executable
RUN chmod +x start.sh

# Expose the Web Dashboard port
EXPOSE 8000

# Run the startup script
CMD ["./start.sh"]