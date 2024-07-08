#!/bin/bash

# Array of IP addresses
IP_ADDRESSES=("150.249.171.94" "116.114.86.62" "184.168.21.27" "128.1.187.77" "85.159.164.28" "119.237.53.72")

# Loop through each IP address
for ip in "${IP_ADDRESSES[@]}"
do
    # Generate a random timestamp (for variety in logs)
    timestamp=$(date +"%b %d %H:%M:%S")

    # Generate a random username (for variety in logs)
    usernames=("INTRUDER")
    random_index=$(( RANDOM % ${#usernames[@]} ))
    username=${usernames[$random_index]}

    # Write log entry to auth.log
    echo "$timestamp $(hostname) sshd[$$]: Failed password for invalid user $username from $ip port 35210 ssh2" >> /var/log/auth.log
done

