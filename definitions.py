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