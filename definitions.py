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
class IP4:
    def __init__(self,data: bytes):
        self.version = data[0:1].hex()[0]
        self.hlen = int(data[0:1].hex()[1],16)
        self.typeOfService = data[1:2]
        self.totalLength = int(data[2:4].hex(),16)
        self.id = data[4:6]
        self.flags = data[6:8]
        self.ttl = data[8:9]
        self.proto = data[9:10]
        self.checksum = data[10:12]
        self.src = [data[12],data[13],data[14],data[15]]
        self.dst = [data[16],data[17],data[18],data[19]]
        if self.hlen != 5:
            self.ops = data[20:self.hlen*4]
            self.data = data[self.hlen*4]
        else:
            self.ops = None
            self.data = data[20:]
class Ethernet:
    def __init__(self,data):
        self.MACDest = data[0:6].hex()
        self.MACSource = data[6:12].hex()
        self.type = data[12:14]
        self.payload = data[14:]
class DHCP:
    class __option:
        def __init__(self,data):
            if data.hex() != 'ff':
                self.length = data[1]
                self.info = data[2:data[1]+2].hex()
            else:
                self.length = 0
                self.info = data[0]
    def __init__(self,data: bytes,endianness):
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
        self.clientAddrPadding = data[34:44]
        self.sname = data[44:108]
        self.file = data[108:236]
        self.magicCookie = data[236:240].hex()
        self.options = []
        i = 0
        while i < len(data[240::]):
            self.options.append(self.__option(data[240+i::]))
            i += self.options[-1].length+2