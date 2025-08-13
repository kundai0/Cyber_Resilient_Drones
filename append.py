from scapy.all import *
from scapy.plist import PacketList

def append_hash_packet(control_file, hash_file, output_file):
    """Creates final packet with control signal + hash"""
    
    control_pkts = rdpcap(control_file)
    
   
    with open(hash_file, "r") as f:
        hash_value = f.read().strip()
    
    # Create hash packet
    hash_pkt = (
        RadioTap() /
        Dot11(type=2, subtype=0,
              addr1="ff:ff:ff:ff:ff:ff",
              addr2="00:11:22:33:44:55",
              addr3="00:11:22:33:44:55") /
        LLC() /
        SNAP() /
        Raw(load=hash_value.encode())
    )
    
    final_pkts = list(control_pkts) + [hash_pkt]
    
    wrpcap(output_file, final_pkts)
    print(f"Combined packets saved to {output_file}")

if __name__ == "__main__":
    append_hash_packet(
        "control_signal.pcapng",
        "generated_hash.txt",
        "merged_packet.pcapng"
    )
