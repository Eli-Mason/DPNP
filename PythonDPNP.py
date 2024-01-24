from scapy.all import *

class DPNP(Packet):
    name = "DPNP"
    fields_desc = [
        BitField("dst_address", "", 256),
        BitField("src_address", "", 256),
        BitField("packet_id", 0, 24),
        BitField("duplicate_id", 0, 8),
        BitField("flags", 0, 8),
        IntField("payload_length", 0, 32),
        ByteField("payload", "")
    ]

    def post_build(self, p, pay):
        payload = p[DPNPPacket].payload_length + pay
        return p[:DPNPPacket] + struct.pack("!I", payload) + payload

class DPNPLayer(Packet):
    name = "DPNPLayer"
    fields_desc = [
        BitField("dst_address", "", 256),
        BitField("src_address", "", 256),
        BitField("packet_id", 0, 24),
        BitField("duplicate_id", 0, 8),
        BitField("flags", 0, 8),
        IntField("payload_length", 0, 32)
    ]

    def post_build(self, p, pay):
        payload = p[DPNPLayer].payload_length + pay
        return p[:DPNPLayer] + struct.pack("!I", payload) + payload

    def extract_padding(self, p):
        if self.payload_length == 0:
            return p[:DPNPLayer], ""
        return p[:DPNPLayer], p[DPNPLayer:]

    def answers(self, other):
        return (
            other.name == "DPNPPacket" and
            other.src_address == self.dst_address and
            other.dst_address == self.src_address and
            other.packet_id == self.packet_id and
            other.duplicate_id == self.duplicate_id + 1
        )

bind_layers(DPNPLayer, DPNPPacket)

src_address = "00000000000000000000000000000000"
dst_address = "1111111111111111111111111111111"
packet_id = 1
duplicate_id = 0
flags = 0
payload_length = len("Hello, World!")
payload = "Hello, World!"

packet = Ether() / IP() / UDP() / DPNPLayer(
    dst_address=dst_address,
    src_address=src_address,
    packet_id=packet_id,
    duplicate_id=duplicate_id,
    flags=flags,
    payload_length=payload_length,
    payload=payload
)

print("Sending packet:", packet.show())
sendp(packet, iface="eth0")

def handle_packet(packet):
    if packet[Ether].dst == src_address:
        print("Received packet:", packet.show())

sniff(iface="eth0", prn=handle_packet)
