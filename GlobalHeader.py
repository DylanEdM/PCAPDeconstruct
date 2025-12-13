import linklayer
def main():
    with open("./ExamplePCAPs/CyberSecurity2026.pcap",'rb') as cap:
        binary = cap.read() #read in binary
    _endianness = {'little':-1,'big':1}
    endianness = ''
    #Figure out if endianness of a file
    #We can do this using the magic number
    if binary[0:4].hex() == ('a1b2c3d4' or 'a1b23c4d'): # if true, we know big endian
        # if we get the magic number we know the endianness matches our system
        endianness = 'big'
    elif binary[0:4][::-1].hex() == ('a1b2c3d4' or 'a1b23c4d'):
        endianness = 'little'
    else:
        raise ValueError('Invalid Magic Number, file unreadable')
    magic_number = binary[0:4][::_endianness[endianness]].hex()
    major_version = binary[4:6].hex().strip('0')
    minor_version = binary[6:8].hex().strip('0')
    if major_version != '2' or minor_version != '4':
        raise TypeError(f'Unsupported file version {major_version}.{minor_version}: Unable to parse file')
    snap_len = int(binary[16:20][::_endianness[endianness]].hex(),16)
    link_type = linklayer.shortName(int(binary[20:22][::_endianness[endianness]].hex(),16))
    return endianness,magic_number,major_version,minor_version,snap_len,link_type
if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        print(e)
    except TypeError as e:
        print(e)