import socket


UDP_IP = "192.168.169.84"  #receiver ip
UDP_PORT = 5005
FILENAME = "merged_packet.pcap"


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

with open(FILENAME, "rb") as f:
    while True:
        data = f.read(1024)
        if not data:
            break
        sock.sendto(data, (UDP_IP, UDP_PORT))


sock.sendto(b"EOF", (UDP_IP, UDP_PORT))

print("File sent successfully.")

