Intrusion Detection System (IDS)
Overview
This project implements an Intrusion Detection System (IDS) in C++ using object-oriented programming concepts. The IDS captures network packets, analyzes them for suspicious activity, and logs network events and alerts into a MySQL database.
Features
•	Packet Capture: Uses the pcap library to capture network packets.
•	Signature-Based Detection: Detects malicious activity based on predefined attack signatures.
•	Anomaly-Based Detection: Detects unusual activity by monitoring packet sizes.
•	Logging: Stores captured packets and detected alerts in a MySQL database.
•	Alert Generation: Triggers alerts for suspicious packets and logs them in the database.
Dependencies
Ensure the following libraries and tools are installed:
•	g++ (C++ compiler)
•	libpcap (for packet capturing)
•	MySQL Connector/C++ 9.0
Installation
1.	Install libpcap: 
2.	sudo apt-get install libpcap-dev
3.	Install MySQL Connector/C++: 
4.	sudo apt-get install libmysqlcppconn-dev
5.	Compile the code using g++: 
6.	g++ -o ids main.cpp -lpcap -lmysqlcppconn
Database Setup
1.	Start MySQL server: 
2.	sudo systemctl start mysql
3.	Create a database and tables: 
4.	CREATE DATABASE ids_database;
5.	USE ids_database;
6.	
7.	CREATE TABLE NetworkEvents (
8.	    id INT AUTO_INCREMENT PRIMARY KEY,
9.	    timestamp BIGINT,
10.	    source_ip VARCHAR(45),
11.	    destination_ip VARCHAR(45),
12.	    protocol VARCHAR(10),
13.	    packet_size INT
14.	);
15.	
16.	CREATE TABLE Alerts (
17.	    id INT AUTO_INCREMENT PRIMARY KEY,
18.	    timestamp BIGINT,
19.	    description TEXT,
20.	    severity_level VARCHAR(10),
21.	    potential_attack_type VARCHAR(50),
22.	    source_ip VARCHAR(45),
23.	    destination_ip VARCHAR(45)
24.	);
25.	Update the database connection details in the code: 
26.	const string DB_HOST = "tcp://127.0.0.1:3306";
27.	const string DB_USER = "root";
28.	const string DB_PASS = "your_password";
29.	const string DB_NAME = "ids_database";
Usage
1.	Run the IDS: 
2.	./ids
3.	The IDS captures network packets and stores data in the database.
4.	Alerts are triggered and logged when suspicious activity is detected.
Notes
•	Ensure you have the necessary permissions to capture packets (sudo may be required).
•	Replace eth0 with the correct network interface in the code if necessary.
•	Modify detection logic and threshold values as needed.
Author
Developed for cybersecurity research and educational purposes.

