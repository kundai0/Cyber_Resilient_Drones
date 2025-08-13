# Cyber_Resilient_Drone (Simulation)
By - Reward Kundai Magama

## Objects used for simulation
1. Mobile phone acts as a Remote control for the drone.
2. Wi-Fi packets from the mobile phone acts as control signals intended for the drone.
3. First laptop acts as an interceptor, catching the signals in between using Wireshark and hashing the packets.
4. Second laptop acts as a drone, which receives the hashed signal packet and further itself authenticates the command packet by again hashing and matching these hashed values.
   

## Overview

This project provides a framework which provides secure communication between a remote control and a drone using hash-based signal authentication.
One mobile phone acts as a remote, sending control signals through Wi-Fi. A laptop captures these signals, appends a secure hash (HMAC) to them, and sends the hashed signal to a second laptop (simulated drone). The receiving system verifies the hash to ensure the signal's authenticity, preventing unauthorized commands from being executed.
Ultimate goal of the project is to maintain integrity of the system.

## Components

The project consists of following Python scripts and files:

---

### 1. `hmac_code.py`

**Description:**  
This script reads a captured Wi-Fi signal(custom packet containing drone commands, mentioned in step 3) from a `.pcapng` file and generates an HMAC-SHA256 hash value using a pre-shared secret key, and saves the hash into a seperate file `hash_value.txt`


### 2. `hash_value.txt`

**Description:** 
This file stores the generated hash value from hmac_code.py. It is used by the append.py script to merge the control signal with its corresponding hash for secure transmission.


### 3. `Create_custom.py`

**Description:**
This script is just used to create a custom packet which consists of drone's command like statements and wifi packet. Since this is a simulation project, we need to create a custom packet like this, but in real life scenario the captured packet itself will have drone's commands and we would not need to use this script.


### 4. `append.py`

**Description:** 
This script reads the control signal and the hash from hash_value.txt, then creates a custom packet by combining both. The merged packet is stored in a new `.pcapng` file ready for transmission.

### 5. `server_udp.py`

**Description:** 
This script acts as a UDP server that sends the `merged_packet.pcapng` file from Laptop 1 (remote) to Laptop 2 (drone).


### 6. `Receiver.py`

**Description:**
The receiver laptop,  with help of receiver.py script, receives the merged_packet.pcapng file which contains hash value and actual command signal which is to be executed on receiving laptop.


### 7. `Extract.py`

**Description:**
This script reads merged_packet.pcapng and extracts the hash value present inside pcapng packet and saves it into new text file `extracted_hash.txt` .

### 8. `Authenticate.py`

**Description:**
This script plays an important role as it authenticates the packet received.
It generates the hash value of command signal present inside the packet , and compares this hash with extracted_hash . If it matches , command is executed , else the command is discarded.

