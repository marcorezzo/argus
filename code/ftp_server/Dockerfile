FROM ubuntu:20.04

# Install vsftpd, rsyslog, and OpenSSH server
RUN apt-get update && apt-get install -y vsftpd rsyslog openssh-server wget

# Allow password authentication and permit root login for SSH
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Configure vsftpd
RUN echo "write_enable=YES" >> /etc/vsftpd.conf && \
    echo "chroot_local_user=YES" >> /etc/vsftpd.conf && \
    echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf && \
    echo "local_umask=022" >> /etc/vsftpd.conf

# Create a directory for FTP users (replace /srv/ftp with your preferred directory)
RUN mkdir -p /srv/ftp && chown nobody:nogroup /srv/ftp && chmod 777 /srv/ftp

# Add a user 'INTRUDER' with password 'argusIsTheBest123'
RUN useradd -m -d /srv/ftp/INTRUDER -s /bin/bash INTRUDER && \
    echo 'INTRUDER:argusIsTheBest123' | chpasswd && \
    chown -R INTRUDER:INTRUDER /srv/ftp/INTRUDER

# Configure rsyslog to log vsftpd messages
RUN echo "local7.* /var/log/vsftpd.log" >> /etc/rsyslog.conf && \
    sed -i 's/#\$ModLoad imudp/\$ModLoad imudp/g' /etc/rsyslog.conf && \
    sed -i 's/#\$UDPServerRun 514/\$UDPServerRun 514/g' /etc/rsyslog.conf && \
    sed -i 's/#\$ModLoad imtcp/\$ModLoad imtcp/g' /etc/rsyslog.conf && \
    sed -i 's/#\$InputTCPServerRun 514/\$InputTCPServerRun 514/g' /etc/rsyslog.conf

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

# Expose FTP and SSH ports
EXPOSE 20 21 22

# Start services
CMD service rsyslog start && service vsftpd start && service ssh start && /usr/bin/filebeat -c /etc/filebeat/filebeat.yml -e

