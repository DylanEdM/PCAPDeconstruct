import gzip
from definitions import *
import re
from os import system

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
        packets.append(PacketRecord(binary[current_pos:],global_header))
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
    for packet in packets:
        try:
            if packet.packet_data.TCP.sequenceNumber == pointer:
                if packet.packet_data.TCP.length == 0:
                    packetFinal = packet
                    break
                chunks += packet.packet_data.TCP.data
                chunkHexs += packet.packet_data.TCP.data.hex()
                pointer += packet.packet_data.TCP.length
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
            if packet.packet_data.HTTP.referer.__contains__(payloadInitial.packet_data.HTTP.host):
                if packet.packet_data.HTTP.host.__contains__(payloadInitial.packet_data.HTTP.host.lstrip("www.").rstrip(".com")):
                    pass
                else:
                    print(f"User navigated to: '{packet.packet_data.HTTP.host}'")
        except Exception as e:
            pass
    pass