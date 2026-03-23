from datetime import datetime, timezone
_endianness = {-1: 'Little', 1: 'Big'}
class PacketRecord:
    class PacketHeader:
        def __init__(self, header_binary,global_header):
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
        def __init__(self, packet_data,global_header):
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

    def __init__(self,packet_record,gloabal_header):
        self.packet_header = self.PacketHeader(packet_record[0:16],gloabal_header)
        self.total_len = self.packet_header.cap_len + 16
        packet_binary = packet_record[16:self.total_len]
        self.packet_data = self.PacketData(packet_binary,gloabal_header)
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

class TCP:
    def __init__(self,data):
        self.srcPort = int(data[0:2].hex(),16)
        self.destPort = int(data[2:4].hex(),16)
        self.sequenceNumber = int(data[4:8].hex(),16)
        self.acknowledgementNumber = int(data[8:12].hex(),16)
        self.dataOffset = int(''.join(f"{byte:08b}" for byte in data[12:13])[:4],2)
        self.data = data[20+(self.dataOffset-5)*4::]
        self.hexData = self.data.hex()
        self.length= len(self.data)
        pass

class LinkDef:
    def __init__(self,data):
        #<LinkTypeName>, <LinkTypeValue>, <LinkTypeShortName>
        self.link_types = [('LINKTYPE_NULL', 0, 'null'),
                        ('LINKTYPE_ETHERNET', 1, 'Ethernet'),
                        ('LINKTYPE_TOKEN_RING', 6, 'Token Ring'),
                        ('LINKTYPE_ARCNET', 7, 'ARCnet'),
                        ('LINKTYPE_SLIP', 8, 'SLIP')]
        self.short_name = self.short_name(data)
    def get_link_type(self,type):
        out = [lt for lt in self.link_types if lt[1] == type]
        assert len(out) < 2 #double check for duplicates
        if out:
            return out[0]
        else:
            return None

    def lookup(self,type):
        out = (type)
        if out:
            return out[0]
        else:
            return out

    def short_name(self,type):
        out = self.get_link_type(type)
        if out:
            return out[2]
        else:
            return out

class UDP:
    def __init__(self,data):
        self.srcPort = int(data[0:2].hex(),16)
        self.dstPort = int(data[2:4].hex(),16)
        self.length = int(data[4:6].hex(),16)
        self.checksum = data[6:8].hex()
        self.payload = data[8:]
    def print_info(self):
        print(f"Source Port: {self.srcPort}")
        print(f"Destination Port: {self.dstPort}")
        print(f"Length: {self.length} Bytes")

class IP4:
    def __init__(self,data: bytes):
        self.version = data[0:1].hex()[0]
        self.hlen = int(data[0:1].hex()[1],16)
        self.typeOfService = int(data[1:2].hex(),16)
        self.totalLength = int(data[2:4].hex(),16)
        self.id = data[4:6].hex()
        self.flags = data[6:8]
        self.ttl = int(data[8:9].hex(),16)
        self.proto = int(data[9:10].hex(),16)
        self.checksum = data[10:12]
        self.src = [data[12],data[13],data[14],data[15]]
        self.dst = [data[16],data[17],data[18],data[19]]
        if self.hlen != 5:
            self.ops = data[20:self.hlen*4]
            self.data = data[self.hlen*4]
        else:
            self.ops = None
            self.data = data[20:]
    def print_info(self):
        print(f"IP Version: {self.version}")
        print(f"Header Length: {self.hlen} Bytes")
        print(f"Total Length: {self.totalLength} Bytes")
        print(f"Identification: 0x{self.id}")
        print(f"Time to live: {self.ttl} Hops")
        print(f"Source IP Address: {self.src[0]}.{self.src[1]}.{self.src[2]}.{self.src[3]}")
        print(f"Destination IP Address: {self.dst[0]}.{self.dst[1]}.{self.dst[2]}.{self.dst[3]}")

class Ethernet:
    def __init__(self,data):
        self.MACDest = data[0:6].hex()
        self.MACSource = data[6:12].hex()
        self.type = data[12:14]
        self.payload = data[14:]
    def print_info(self):
        print(f"MAC Destination: {self.MACDest[0:2]}:{self.MACDest[2:4]}:{self.MACDest[4:6]}:{self.MACDest[6:8]}:{self.MACDest[8:10]}:{self.MACDest[10:12]}")
        print(f"MAC Source: {self.MACSource[0:2]}:{self.MACSource[2:4]}:{self.MACSource[4:6]}:{self.MACSource[6:8]}:{self.MACSource[8:10]}:{self.MACSource[10:12]}")

class DHCP:
    class __option:
        def __init__(self,data):
                self.code = int(data[0:1].hex(),16)
                match self.code:
                    case 255:
                        self.length = 0
                        self.info = None
                    case 81:
                        self.length = data[1]
                        self.info = str(data[2:data[1] + 2][3::])[2::].rstrip("'")
                    case _:
                        self.length = data[1]
                        self.info = data[2:data[1]+2].hex()
        def print_info(self):
            print(f"Option Code: {self.code}")
            print(f"Length: {self.length}")
            print(f"Info: 0x{self.info}")
    def __init__(self,data: bytes,endianness):
        self.length = len(data)
        self.op = int(data[0:1].hex(),16)
        self.h_type = LinkDef(int(data[1:2].hex(),16)).short_name
        self.h_len = int(data[2:3].hex(),16)
        self.hops = int(data[3:4].hex(),16)
        self.xid = data[4:8].hex()
        self.secs = int(data[8:10][::endianness].hex(),16)
        self.flags = data[10:12].hex()
        self.ciaddr = [data[12],data[13],data[14],data[15]]
        self.yiaddr = [data[16],data[17],data[18],data[19]]
        self.siaddr = [data[20],data[21],data[22],data[23]]
        self.giaddr = [data[24],data[25],data[26],data[27]]
        self.clientMAC = data[28:34].hex()
        self.clientAddrPadding = data[34:44].hex()
        self.sname = data[44:108].hex()
        self.file = data[108:236].hex()
        self.magicCookie = data[236:240].hex()
        self.options = []
        i = 0
        while i < len(data[240::]):
            self.options.append(self.__option(data[240+i::]))
            i += self.options[-1].length+2
    def print_info(self):
        ops = {1:"BOOTREQUEST",2:"BOOTREPLY"}
        print(f"DHCP Length:  {self.length}")
        print(f"Option: {self.op} ({ops[self.op]})")
        print(f"Hardware Type: {self.h_type}")
        print(f"Hardware Address Length: {self.h_len}")
        print(f"Hops taken: {self.hops}")
        print(f"Transaction Identifier: 0x{self.xid}")
        print(f"Seconds Elapsed: {self.secs}")
        print(f"Flags: 0x{self.flags}")
        print(f"Client IP address: {self.ciaddr[0]}.{self.ciaddr[1]}.{self.ciaddr[2]}.{self.ciaddr[3]}")
        print(f"Your (client)  IP address: {self.yiaddr[0]}.{self.yiaddr[1]}.{self.yiaddr[2]}.{self.yiaddr[3]}")
        print(f"Next server IP address: {self.siaddr[0]}.{self.siaddr[1]}.{self.siaddr[2]}.{self.siaddr[3]}")
        print(f"Relay agen IP address: {self.giaddr[0]}.{self.giaddr[1]}.{self.giaddr[2]}.{self.giaddr[3]}")
        print(f"Client MAC address: {self.clientMAC[0:2]}:{self.clientMAC[2:4]}:{self.clientMAC[4:6]}:{self.clientMAC[6:8]}:{self.clientMAC[8:10]}:{self.clientMAC[10:12]}")
        print(f"Client hardware address padding: {self.clientAddrPadding}")
        if self.sname.strip("0") == "":
            print(f"Server host name not given")
        else:
            print(f"Server host name: {self.sname}")
        if self.file.strip("0") == "":
            print("Boot file name not given")
        else:
            print(f"Boot file name: {self.file}")
        print(f"Magic cookie: {self.magicCookie} (DHCP)")
        for op in self.options:
            op.print_info()
            print("\n")

class HTTP:
    def __init__(self,data):
        self.sections = data.split(b"\r\n")
        self.searchRequest = None
        self.host = None
        self.contentType = None
        self.transferEncoding = None
        self.data = None
        self.contentEncoding = None
        self.referer = None
        for sect in self.sections:
            if sect.__contains__(b'Host:'):
                self.host = sect.lstrip(b'Host: ').decode('ascii')
            if sect.__contains__(b'/search?q='):
                self.searchRequest = data[14::].split(b'&qs=')[0].decode('ascii').replace('+',' ')
            if sect.__contains__(b'Content-Type:'):
                self.contentType = sect.lstrip(b'Content-Type:').decode('ascii').strip()
            if sect.__contains__(b'Content-Encoding:'):
                self.contentEncoding = sect.lstrip(b'Content-Encoding:').decode('ascii').strip()
            if sect.__contains__(b'Transfer-Encoding:'):
                self.transferEncoding = sect.lstrip(b'Transfer-Encoding:').decode('utf-8').strip()
            if sect.__contains__(b'Referer: '):
                self.referer = sect.lstrip(b'Referer: ').decode('ascii')
        if self.transferEncoding == "chunked":
            self.data = self.sections[-1]
        pass