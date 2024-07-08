FROM python:3.9-slim

# Install necessary system packages
RUN apt-get update && apt-get install -y wget && \
    rm -rf /var/lib/apt/lists/*

# Create directory for the application code
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Configure rsyslog to send logs to Filebeat
RUN echo '$ModLoad imfile' > /etc/rsyslog.conf && \
    echo '$InputFileName /var/log/app.log' >> /etc/rsyslog.conf && \
    echo '$InputFileTag tag1:' >> /etc/rsyslog.conf && \
    echo '$InputFileStateFile stat-tag1' >> /etc/rsyslog.conf && \
    echo '$InputFileSeverity info' >> /etc/rsyslog.conf && \
    echo '$InputFileFacility local1' >> /etc/rsyslog.conf && \
    echo '$InputRunFileMonitor' >> /etc/rsyslog.conf && \
    echo 'local1.* @localhost:1514' >> /etc/rsyslog.conf

# Expose the port
EXPOSE 5000

# Start Filebeat and rsyslog services, and then the application
CMD python app.py

