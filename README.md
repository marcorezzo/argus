# Malicious IP-Address Monitor

![Logo](documentation/software/images/Logo.png)


## Deployment

Credentials for all logins:
```
username: elastic
password: argusIsTheBest123
```

Install docker and docker-compose

#### Linux:
```
sudo apt install docker docker-compose
```

#### Mac:
```
https://docs.docker.com/desktop/install/mac-install/
```
Docker Desktop starten:
```
open -a Docker
```
Pfad für /Users/USERNAME/Documents in Docker Desktop unter Preferences -> Resources -> File Sharing angeben.



#### Windows:
```
https://docs.docker.com/desktop/install/windows-install/
```

Pfad für C:/Users/USERNAME/Documents in Docker Desktop unter Preferences -> Resources -> File Sharing angeben.

Clone the Project 

```
git clone https://gitlab.ti.bfh.ch/pellm4/argus
```
Navigate to the folder with the docker-compose.yml file and build the Project
```
cd code && docker-compose build
```

Run the containers. **Please note that this might use a lot of resources. Close all unnecessary programs. 16GB RAM or more is recommended.**
```
docker-compose up -d
```
Import the index pattern and dashboard

-  Go to localhost:5601 in browser
-  Login with username: elastic, password: argusIsTheBest123
-  Go to Stack Management (bottom left of Menu)
-  Go to Saved Objects (under Kibana) 
-  Import the argus/export.ndjson file
-  Choose "Automatically overwrite conflicts"
-  Import

#### *This step will be automated in the future!*

To see the dashboard, navigate to the Analytics/Dashboard secton.

### Sample Data

The intruder container continuosly attacks the monitored servers. Because spoofing IP-Adresses is not an easy task, we created a little script for the ssh_server to simulate malicous traffic. The script simply echo's logs to /var/log/auth.log, which then get forwarded to the elasticsearch container. 

To simulate malicious traffic on the ssh_server, first enter the shell of the container:
```
docker exec -it ssh_server sh
```
Then execute the script simulate_traffic.sh
```
./data/simulate_traffic.sh
```

### Mail alerting

Make sure to change the recipient in the argus.conf file under "email". When the monitroing script fails, it sends an alert to the recipient over gmail.

#### *Alerting will be replaced by SMS in the future!*


### Troubleshooting tips:

Check if all the containers are up and running
```
docker ps -a
```
Pool overlaps with other one on this address space. (Delete custom docker networks)
```
docker network prune
```

Check the logs of a container:
```
docker logs CONTAINERNAME
```

Execute the shell of a container:
```
docker exec -it CONTAINERNAME sh
```

Filebeat should only be writable by owner
```
find . -type f -name 'filebeat.yml' -exec chmod go-w {} +
```




## Description

The Malicious IP-Address Monitor is an open-source project aimed at enhancing internet security through proactive monitoring. The tool is designed to operate as a daemon, providing platform-independent monitoring of Linux (Ubuntu) internet servers. It specializes in detecting unauthorized sysadmin traffic, including in-bound port scans and unauthorized login attempts through SSH, FTP(S), and IMAP(S). Detected unauthorized IP addresses are reported to a public repository (akin to a digital pillory), similar in function to AbuseIPDB, thereby shaming the attackers and deterring future attacks.

Beyond technological measures like IPtables, the project introduces a psychological deterrent by exposing cyber attackers. This dual approach not only fortifies endpoints but also aids cyber law enforcement in their efforts to secure the internet.

The project is committed to clean code principles, emphasizing minimalism, modularity, and self-documentation to ensure ease of use and maintenance.

## Technologies

- **AbuseIPDB**: An online database used to report and track abusive IP addresses. [Visit AbuseIPDB](https://www.abuseipdb.com)
- **DMARC-Demon**: A tool for handling DMARC policies and reports, contributing to the email monitoring aspect of the project. [Check out DMARC-Demon](https://github.com/soracel/dmarc-visualizer)
- **IPtables**: A user-space utility program that allows a system administrator to configure the IP packet filter rules of the Linux kernel firewall. [Learn more about IPtables](https://en.wikipedia.org/wiki/Iptables)

## Literature

- An exploration of cyber security measures and the psychology behind them can be found in the following academic articles:
    - [ACM Digital Library - Article 1](https://doi.org/10.1145/1592451.159245)
    - [ScienceDirect - Article 2](https://doi.org/10.1016/B978-0-12-411597-2.00007-2)
    - [ACM Digital Library - Web-browser technology](https://doi.org/10.1145/3139294)

## Law Enforcement Resources

- The project also aligns with efforts by law enforcement to combat cybercrime. Relevant agencies include:
    - [Swiss E-Police](https://www.suisse-epolice.ch/home)
    - [National Cyber Security Centre of Switzerland (NCSC)](https://www.ncsc.admin.ch/ncsc/de/home.html)

## Advisor

The project is advised by Dr. Simon KRAMER, whose guidance ensures adherence to the best practices in cyber security and project development.


## Authors
Marco Rezzonico - marco.rezzonico@students.bfh.ch, 
Stefani Pernjak - stefani.pernjak@students.bfh.ch, 
Max Pelletier - maxrico.pelletier@students.bfh.ch

## License
GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007