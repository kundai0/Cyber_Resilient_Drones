from scapy.all import *
import os

def extract_hash_and_control(input_file, hash_output_file, control_output_file):
    """
    Extracts the hash value from the final packet and saves:
    - Hash to a text file
    - Control packets to a separate pcapng file
    """
    try:
        # Read all packets from the received file
        packets = rdpcap(input_file)
        
        if len(packets) < 1:
            print("Error: No packets found in input file")
            return False
        
        # Last packet contains the hash (assuming it was appended last)
        hash_packet = packets[-1]
        
        if not hash_packet.haslayer(Raw):
            print("Error: Last packet has no Raw layer containing hash")
            return False
        
        # Extract the hash (SHA512 is 128 hex characters)
        hash_value = hash_packet[Raw].load.decode('utf-8').strip()
        
        # Validate hash format
        if len(hash_value) != 128 or not all(c in '0123456789abcdef' for c in hash_value.lower()):
            print("Error: Extracted data doesn't look like a valid SHA512 hash")
            return False
        
        # Save the hash to text file
        with open(hash_output_file, 'w') as f:
            f.write(hash_value)
        print(f"Hash successfully saved to {hash_output_file}")
        
        # Save all packets except the last one (control signals)
        control_packets = packets[:-1]
        wrpcap(control_output_file, control_packets)
        print(f"Control signals saved to {control_output_file}")
        
        return True
        
    except Exception as e:
        print(f"Error processing files: {e}")
        return False

if __name__ == "__main__":
    # Configuration
    INPUT_FILE = "merged_packet.pcapng"       # Received from Laptop 1
    HASH_OUTPUT = "extracted_hash.txt"       # Where to save the hash
    CONTROL_OUTPUT = "control_signals.pcapng" # Where to save control packets
    
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Input file {INPUT_FILE} not found")
    else:
        success = extract_hash_and_control(INPUT_FILE, HASH_OUTPUT, CONTROL_OUTPUT)
        if success:
            print("Extraction completed successfully!")
            print(f"Hash value: {open(HASH_OUTPUT).read().strip()}")
            print(f"Control packets saved in: {CONTROL_OUTPUT}")
        else:
            print("Extraction failed")
