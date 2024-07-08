FROM ubuntu:20.04

# Install Postfix and Dovecot
RUN apt-get update && apt-get install -y postfix dovecot-core dovecot-imapd dovecot-pop3d wget && \
    echo "maillog_file = /var/log/mail.log" >> /etc/postfix/main.cf && \
    echo "myhostname = mail.example.com" >> /etc/postfix/main.cf && \
    echo "mydestination = mail.example.com, localhost.localdomain, localhost" >> /etc/postfix/main.cf

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
    dpkg -i /tmp/filebeat.deb && \
    rm /tmp/filebeat.deb

# Copy Filebeat configuration
COPY filebeat.yml /etc/filebeat/filebeat.yml
RUN chmod go-w /etc/filebeat/filebeat.yml

# Expose necessary ports
EXPOSE 25 587 993

# Start services
CMD service postfix start && service dovecot start && service filebeat start && tail -f /dev/null

