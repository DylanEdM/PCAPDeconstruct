import argparse, os
from definitions import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='PCAP Tool',
        description='Pick apart PCAP file and spot vulnerabilities'
    )
    parser.add_argument('file',nargs='+',help='PCAP file location')
    args = parser.parse_args()
    if not os.path.isfile(args.file[0]):
        print(f"File not found: {args.file[0]}")
        exit(1)
    with open(args.file[0],'rb') as cap:
        binary = cap.read() #read in binary
    global_header = GlobalHeader(binary[0:24])
    global_header.print_header()
    current_pos = 24
    packets = []
    #decode all packets as much as possible
    while current_pos < len(binary):
        packets.append(PacketRecord(binary[current_pos:],global_header))
        current_pos += packets[-1].total_len
        print(f"\nPacket: {len(packets)} decoded!")