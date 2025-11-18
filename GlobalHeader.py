import sys

def main():
    with open("./ExamplePCAPs/CyberSecurity2026.pcap",'rb') as cap:
        binary = cap.read() #read in binary
    header = binary[0:24] #take header
    endianness = ['little','big']
    #Figure out if endianness of a file
    #We can do this using the magic number
    if header[0:4].hex() == ('a1b2c3d4' or 'a1b23c4d'): #big endian
        magic_number = header[0:4].hex()
        # if we get the magic number we know the endianness matches our system
        endianness = [sys.byteorder]
    else:
        magic_number = header[0:4][::-1].hex()
        endianness.remove(sys.byteorder)
if __name__ == "__main__":
    main()