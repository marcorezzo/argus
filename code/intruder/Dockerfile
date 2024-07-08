FROM alpine:latest

RUN apk update && \
    apk add --no-cache openssh-client sshpass lftp sshpass nmap netcat-openbsd mysql-client curl

COPY intruder.sh /usr/local/bin/intruder.sh

RUN chmod +x /usr/local/bin/intruder.sh

ENTRYPOINT ["/usr/local/bin/intruder.sh"]

