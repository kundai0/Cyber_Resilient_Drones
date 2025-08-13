from scapy.all import *
from scapy.plist import PacketList

def merge_commands_with_capture(capture_file, output_file):
    """Merges drone commands with existing captured packets"""
    drone_commands = """Drone started
Drone taking flight
Drone taking left
Hovering mode on"""
    
    # 1. Read existing captured packets
    try:
        captured_packets = rdpcap(capture_file)
    except FileNotFoundError:
        print(f"Error: {capture_file} not found")
        return False
    
    # 2. Create command packet with same MAC addresses as first captured packet
    if len(captured_packets) == 0:
        print("Error: No packets in capture file")
        return False
    
    # Use addresses from first captured packet
    first_pkt = captured_packets[0]
    addr1 = first_pkt.addr1 if hasattr(first_pkt, 'addr1') else "ff:ff:ff:ff:ff:ff"
    addr2 = first_pkt.addr2 if hasattr(first_pkt, 'addr2') else "00:11:22:33:44:55"
    addr3 = first_pkt.addr3 if hasattr(first_pkt, 'addr3') else "00:11:22:33:44:55"
    
    command_packet = (
        RadioTap() /
        Dot11(type=2, subtype=0,
              addr1=addr1,
              addr2=addr2,
              addr3=addr3) /
        LLC() /
        SNAP() /
        Raw(load=drone_commands.encode())
    )
    
    # 3. Merge command packet with captured packets (PROPER MERGE)
    # Convert PacketList to regular list first
    packets_list = list(captured_packets)
    packets_list.append(command_packet)
    
    # Create new PacketList from the combined list
    merged_packets = PacketList(packets_list, "Merged Packets")
    
    # 4. Save merged packets
    wrpcap(output_file, merged_packets)
    print(f"Merged commands with {capture_file}, saved to {output_file}")
    return True
if __name__ == "__main__":
    merge_commands_with_capture(
        capture_file="/home/kali/Desktop/WIRESHARK/Pocox51.pcapng",
        output_file="merged_packet.pcapng"
    )
