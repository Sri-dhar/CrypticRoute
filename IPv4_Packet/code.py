from dataclasses import dataclass
from typing import List, Optional
import ipaddress

@dataclass
class IPv4Packet:
    """Class representing an IPv4 packet structure"""
    version: int = 4  # 4 bits
    ihl: int = 5  # 4 bits, Internet Header Length
    dscp: int = 0  # 6 bits, Differentiated Services Code Point
    ecn: int = 0  # 2 bits, Explicit Congestion Notification
    total_length: int = 20  # 16 bits, total packet length in bytes
    identification: int = 0  # 16 bits
    flags: int = 0  # 3 bits (Reserved, Don't Fragment, More Fragments)
    fragment_offset: int = 0  # 13 bits
    ttl: int = 64  # 8 bits, Time To Live
    protocol: int = 0  # 8 bits
    header_checksum: int = 0  # 16 bits
    source_address: str = "0.0.0.0"  # 32 bits
    destination_address: str = "0.0.0.0"  # 32 bits
    options: Optional[bytes] = None  # Variable length, must be multiple of 32 bits
    payload: Optional[bytes] = None

    def __post_init__(self):
        # Validate address formats
        ipaddress.IPv4Address(self.source_address)
        ipaddress.IPv4Address(self.destination_address)
        
        # Validate field ranges
        if not 0 <= self.version <= 15:  # 4 bits
            raise ValueError("Version must be between 0 and 15")
        if not 5 <= self.ihl <= 15:  # 4 bits, minimum 5
            raise ValueError("IHL must be between 5 and 15")
        if not 0 <= self.dscp <= 63:  # 6 bits
            raise ValueError("DSCP must be between 0 and 63")
        if not 0 <= self.ecn <= 3:  # 2 bits
            raise ValueError("ECN must be between 0 and 3")
        if not 0 <= self.flags <= 7:  # 3 bits
            raise ValueError("Flags must be between 0 and 7")

@dataclass
class IPv6Packet:
    """Class representing an IPv6 packet structure"""
    version: int = 6  # 4 bits, 6 for IPv6
    traffic_class: int = 0  # 8 bits
    flow_label: int = 0  # 20 bits
    payload_length: int = 0  # 16 bits
    next_header: int = 0  # 8 bits
    hop_limit: int = 64  # 8 bits
    source_address: str = "::"  # 128 bits
    destination_address: str = "::"  # 128 bits
    payload: Optional[bytes] = None

    def __post_init__(self):
        # Validate address formats
        ipaddress.IPv6Address(self.source_address)
        ipaddress.IPv6Address(self.destination_address)
        
        if not 0 <= self.version <= 15:  # 4 bits
            raise ValueError("Version must be between 0 and 15")
        if not 0 <= self.traffic_class <= 255:  # 8 bits
            raise ValueError("Traffic class must be between 0 and 255")
        if not 0 <= self.flow_label <= 1048575:  # 20 bits
            raise ValueError("Flow label must be between 0 and 1048575")
        if not 0 <= self.next_header <= 255:  # 8 bits
            raise ValueError("Next header must be between 0 and 255")
        if not 0 <= self.hop_limit <= 255:  # 8 bits
            raise ValueError("Hop limit must be between 0 and 255")

def create_example_packets():
    #IPv4 packet
    ipv4_packet = IPv4Packet(
        ttl=128,
        protocol=6,  # TCP
        source_address="192.168.1.1",
        destination_address="10.0.0.1",
        payload=b"Hello, IPv4!"
    )

    #IPv6 packet
    ipv6_packet = IPv6Packet(
        traffic_class=0,
        flow_label=0,
        next_header=6,  # TCP
        source_address="2001:db8::1",
        destination_address="2001:db8::2",
        payload=b"Hello, IPv6!"
    )

    return ipv4_packet, ipv6_packet


if __name__ == "__main__":
    ipv4_packet, ipv6_packet = create_example_packets()
    print(ipv4_packet)
    print("\n\n")
    print(ipv6_packet)