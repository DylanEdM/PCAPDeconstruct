from datetime import datetime,timezone,timedelta
from definitions import *
class PacketRecord:
    class PacketHeader:
        def __init__(self, header_binary):
            epoch_time = int(header_binary[0:4][::global_header.endianness].hex(), 16)
            self.datetime = datetime.fromtimestamp(epoch_time,timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            if global_header.magic_number == 'a1b2c3d4':
                self.nano_seconds = int(header_binary[4:8][::global_header.endianness].hex(), 16)*1000
            else:
                self.nano_seconds = int(header_binary[0:4][::global_header.endianness].hex(), 16)
            self.timestamp = f'{self.datetime}.{self.nano_seconds}Z GMT'
            self.cap_len = int(header_binary[8:12][::global_header.endianness].hex(), 16)
            self.org_len = int(header_binary[12:16][::global_header.endianness].hex(), 16)

    class PacketData:
        def __init__(self, packet_data):
            self.eth = Ethernet(packet_data)
            self.IP4 = IP4(self.eth.payload)
            self.UDP = UDP(self.IP4.data)
            self.DHCP = DHCP(self.UDP.payload,global_header.endianness)
            pass

    def __init__(self,packet_record):
        self.packet_header = self.PacketHeader(packet_record[0:16])
        self.total_len = self.packet_header.cap_len + 16
        packet_binary = packet_record[16:self.total_len]
        self.packet_data = self.PacketData(packet_binary)
class GlobalHeader:
    def __init__(self,header_binary):
        try:
            self.endianness = 0
            # Figure out if endianness of a file
            # We can do this using the magic number
            if header_binary[0:4].hex() == ('a1b2c3d4' or 'a1b23c4d'):  # if true, we know big endian
                # if we get the magic number we know the endianness matches our system
                self.endianness = 1
            elif header_binary[0:4][::-1].hex() == ('a1b2c3d4' or 'a1b23c4d'):
                self.endianness = -1
            else:
                raise ValueError('Invalid Magic Number, file unreadable')
            self.magic_number = header_binary[0:4][::self.endianness].hex()
            self.major_version = header_binary[4:6].hex().strip('0')
            self.minor_version = header_binary[6:8].hex().strip('0')
            if self.major_version != '2' or self.minor_version != '4':
                raise TypeError(f'Unsupported file version {self.major_version}.{self.minor_version}: Unable to parse file')
            self.snap_len = int(header_binary[16:20][::self.endianness].hex(), 16)
            self.link_type = LinkDef(int(header_binary[20:22][::self.endianness].hex(), 16))
        except ValueError as e:
            print(e)
        except TypeError as e:
            print(e)
    def print_header(self):
        print(f"Global Header Length: 24 Octets\\Bytes")
        print(f"Magic Number: {self.magic_number}")
        print(f"Endianness: {_endianness[self.endianness]}")
        print(f"Major Version: {self.major_version}")
        print(f"Minor Version: {self.minor_version}")
        print(f"Snap Length: {self.snap_len} Bytes")
        print(f"Data Link Type: {self.link_type.short_name}")

if __name__ == "__main__":
    _endianness = {-1:'Little', 1: 'Big'}
    with open("./ExamplePCAPs/CyberSecurity2026.pcap",'rb') as cap:
        binary = cap.read() #read in binary
    global_header = GlobalHeader(binary[0:24])
    global_header.print_header()
    current_pos = 24
    packets = []
    while current_pos < len(binary):
        packets.append(PacketRecord(binary[current_pos:]))
        current_pos += packets[-1].total_len
        break