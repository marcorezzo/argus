FROM ubuntu:20.04

# Install SSH server and rsyslog
RUN apt-get update && apt-get install -y openssh-server rsyslog wget && \
    mkdir /var/run/sshd && \
    echo 'root:password' | chpasswd

# Configure SSH server to log to /var/log/auth.log via rsyslog
RUN sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/g' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config && \
    echo 'auth.* /var/log/auth.log' >> /etc/rsyslog.conf

# Determine architecture and download the appropriate Filebeat package
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
        FILEBEAT_URL="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.15.1-amd64.deb"; \
    elif [ "$ARCH" = "arm64" ]; then \
        FILEBEAT_URL="https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.15.1-arm64.deb"; \
    else \
        echo "Unsupported architecture: $ARCH"; \
        exit 1; \
    fi && \
    wget -O /tmp/filebeat.deb $FILEBEAT_URL && \
    dpkg -i /tmp/filebeat.deb

# Copy Filebeat configuration
COPY filebeat.yml /etc/filebeat/filebeat.yml
RUN chmod go-w /etc/filebeat/filebeat.yml

# Expose SSH port
EXPOSE 22

# Start services
CMD service rsyslog start && service filebeat start && /usr/sbin/sshd -D

