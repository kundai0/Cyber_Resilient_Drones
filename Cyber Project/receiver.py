import socket

UDP_IP = "0.0.0.0"  # Listen on all interfaces
UDP_PORT = 5005
OUTPUT_FILE = "received_packet.pcapng"

# Create a UDP socket and bind to address
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"Listening on {UDP_IP}:{UDP_PORT}...")

with open(OUTPUT_FILE, "wb") as f:
    while True:
        data, addr = sock.recvfrom(1024)
        if data == b"EOF":
            print("End of file received.")
            break
        f.write(data)

print(f"File received and saved as {OUTPUT_FILE}")

