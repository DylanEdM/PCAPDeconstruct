from datetime import datetime,timezone,timedelta
import linklayer
class Packet:
    class PacketHeader:
        def __init__(self, header_binary):
            epoch_time = int(header_binary[0:4][::global_header[0]].hex(), 16)
            self.datetime = datetime.fromtimestamp(epoch_time,timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            if global_header[1] == 'a1b2c3d4':
                self.nano_seconds = int(header_binary[4:8][::global_header[0]].hex(), 16)*1000
            else:
                self.nano_seconds = int(header_binary[0:4][::global_header[0]].hex(), 16)
            self.timestamp = f'{self.datetime}.{self.nano_seconds}Z GMT'
            self.cap_len = int(header_binary[8:12][::global_header[0]].hex(), 16)
            self.org_len = int(header_binary[12:16][::global_header[0]].hex(), 16)
            self.total_len = self.cap_len + 16
    class PacketData:
        def __init__(self, packet_data):
            pass
    def __init__(self,packet_record):
        self.packet_header = self.PacketHeader(packet_record[0:16])
        self.packet_data = self.PacketData(packet_record[16:])
def global_header(header_binary):
    try:
        endianness = 0
        # Figure out if endianness of a file
        # We can do this using the magic number
        if header_binary[0:4].hex() == ('a1b2c3d4' or 'a1b23c4d'):  # if true, we know big endian
            # if we get the magic number we know the endianness matches our system
            endianness = 1
        elif header_binary[0:4][::-1].hex() == ('a1b2c3d4' or 'a1b23c4d'):
            endianness = -1
        else:
            raise ValueError('Invalid Magic Number, file unreadable')
        magic_number = header_binary[0:4][::endianness].hex()
        major_version = header_binary[4:6].hex().strip('0')
        minor_version = header_binary[6:8].hex().strip('0')
        if major_version != '2' or minor_version != '4':
            raise TypeError(f'Unsupported file version {major_version}.{minor_version}: Unable to parse file')
        snap_len = int(header_binary[16:20][::endianness].hex(), 16)
        link_type = linklayer.shortName(int(header_binary[20:22][::endianness].hex(), 16))
        return endianness, magic_number, major_version, minor_version, snap_len, link_type
    except ValueError as e:
        print(e)
    except TypeError as e:
        print(e)

if __name__ == "__main__":
    _endianness = {-1:'little', 1: 'big'}
    with open("./ExamplePCAPs/CyberSecurity2026.pcap",'rb') as cap:
        binary = cap.read() #read in binary
    global_header = global_header(binary[0:24])
    current_pos = 24
    packets = []
    while current_pos < len(binary):
        packets.append(Packet(binary[current_pos:]))
        current_pos += packets[-1].packet_header.total_len
    pass