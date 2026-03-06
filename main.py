import gzip
from datetime import datetime,timezone,timedelta
from definitions import *
import re
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
        def print_header(self):
            print(f"Date & Time of Packet: {self.timestamp}")
            print(f"{self.cap_len} bytes captured of original {self.org_len} bytes")

    class PacketData:
        def __init__(self, packet_data):
            try:
                self.eth = Ethernet(packet_data)
                self.IP4 = IP4(self.eth.payload)
                match self.IP4.proto:
                    case 17:
                        self.UDP = UDP(self.IP4.data)
                        self.DHCP = DHCP(self.UDP.payload, global_header.endianness)
                    case 6:
                        self.TCP = TCP(self.IP4.data)
                        if self.TCP.data.strip(b'\x00') != b'':
                            self.HTTP = HTTP(self.TCP.data)
                        else:
                            self.HTTP = None
                self.remaining = None
                self.raw = packet_data
            except Exception as e:
                if self.UDP:
                    self.remaining = self.UDP.payload
                elif self.TCP:
                    self.remaining = self.TCP.data
                elif self.IP4:
                    self.remaining = self.IP4.data
                elif self.eth:
                    self.remaining = self.eth.payload
                else:
                    self.remaining = packet_data
        def print_information(self):
            print("Ethernet Information:")
            self.eth.print_info()
            print("IP4 Information:")
            self.IP4.print_info()
            print("UDP Information:")
            self.UDP.print_info()
            print("DHCP Information:")
            self.DHCP.print_info()

    def __init__(self,packet_record):
        self.packet_header = self.PacketHeader(packet_record[0:16])
        self.total_len = self.packet_header.cap_len + 16
        packet_binary = packet_record[16:self.total_len]
        self.packet_data = self.PacketData(packet_binary)
    def print_info(self):
        print("Packet Header Information:")
        self.packet_header.print_header()
        print("Packet Data Information:")
        self.packet_data.print_information()
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
    #decode all packets as much as possible
    while current_pos < len(binary):
        packets.append(PacketRecord(binary[current_pos:]))
        current_pos += packets[-1].total_len
        print(f"\nPacket: {len(packets)}")
    packets[0].print_info()
    for op in packets[0].packet_data.DHCP.options:
        if op.code == 81: print(f"Host PC name: {op.info}")
    #find .top
    for packet in packets:
        try:
            encodedDomain = packet.packet_data.UDP.payload[12:len(packet.packet_data.UDP.payload) - 5]
            pointer = 0
            labels = []
            if re.search("top$", encodedDomain.decode('ascii')):
                while pointer < len(encodedDomain):
                    try:
                        length = encodedDomain[pointer] + 1
                        labels.append(str(encodedDomain[pointer + 1:pointer + length])[2::].rstrip("'"))
                        pointer += length
                    except IndexError:
                        pass
                domain = ".".join(labels)
                break
        except Exception:
            pass
    print(f"Suspect Domain: {domain}")
    #find search engine
    payloadInitial = None
    for packet in packets:
        try:
            if packet.packet_data.HTTP.searchRequest is not None:
                print(f'Search Engine used: "{packet.packet_data.HTTP.host}"')
                print(f'Search query: "{packet.packet_data.HTTP.searchRequest}"')
                payloadInitial = packet
            if payloadInitial.packet_data.IP4.src == packet.packet_data.IP4.dst and \
            payloadInitial.packet_data.IP4.dst == packet.packet_data.IP4.src and \
            payloadInitial.packet_data.TCP.srcPort == packet.packet_data.TCP.destPort and \
            payloadInitial.packet_data.TCP.destPort == packet.packet_data.TCP.srcPort:
                payloadStart = packet
                break
        except Exception:
            pass
    chunks = payloadStart.packet_data.TCP.data
    chunkHexs = payloadStart.packet_data.TCP.data.hex()
    pointer = payloadStart.packet_data.TCP.sequenceNumber + payloadStart.packet_data.TCP.length
    counter = 0
    for packet in packets:
        try:
            if packet.packet_data.TCP.sequenceNumber == pointer:
                if packet.packet_data.TCP.length == 0:
                    packetFinal = packet
                    break
                chunks += packet.packet_data.TCP.data
                chunkHexs += packet.packet_data.TCP.data.hex()
                pointer += packet.packet_data.TCP.length
                counter += 1
                pass
        except Exception:
            pass
    reassembledHttp = HTTP(chunks)
    dechunked = b''
    chunkPointer = 0
    for i, section in enumerate(reassembledHttp.sections):
        if section == b'':
            chunkPointer = i+1
            break
    while chunkPointer < len(reassembledHttp.sections):
        if reassembledHttp.sections[chunkPointer] == b'0' or b'':
            break
        dechunked += reassembledHttp.sections[chunkPointer+1]
        chunkPointer+=2
    #turn dechuncked to string by using gzip
    response = str(gzip.decompress(dechunked))
    print(f"First result: {response[response.find("<cite>")+6:response.find("</cite>")]}")

    for packet in packets:
        try:
            if packet.packet_data.HTTP.searchRequest.__contains__(payloadInitial.packet_data.HTTP.host):
                if packet.packet_data.HTTP.host.__contains__(payloadInitial.packet_data.HTTP.host.lstrip("www.").rstrip(".com")):
                    pass
                else:
                    print(f"User navigated to: '{packet.packet_data.HTTP.host}'")
                    break
        except Exception as e:
            pass
    pass