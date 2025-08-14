from scapy.all import *
import hmac
import hashlib

def generate_hmac_hash(pcap_file, secret_key):
    """Generates HMAC-SHA512 hash of packet data"""
    packets = rdpcap(pcap_file)
    combined_data = b''.join(bytes(pkt) for pkt in packets)
    
    hmac_hash = hmac.new(
        secret_key.encode(),
        combined_data,
        hashlib.sha512
    ).hexdigest()
    
    with open("generated_hash.txt", "w") as f:
        f.write(hmac_hash)
    
    return hmac_hash

if __name__ == "__main__":
    SECRET_KEY = "this is key"  # Must match on both systems
    hash_value = generate_hmac_hash("control_signal.pcapng", SECRET_KEY)
    print(f"HMAC-SHA512 hash generated: {hash_value}")
    print("Hash saved to generated_hash.txt")
