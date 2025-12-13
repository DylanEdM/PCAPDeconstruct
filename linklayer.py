#<LinkTypeName>, <LinkTypeValue>, <LinkTypeShortName>
linkTypes = [('LINKTYPE_NULL', 0, 'null'),
                ('LINKTYPE_ETHERNET', 1, 'ethernet'),
                ('LINKTYPE_TOKEN_RING', 6, 'token ring'),
                ('LINKTYPE_ARCNET', 7, 'ARCnet'),
                ('LINKTYPE_SLIP', 8, 'SLIP')]
def getLinkType(type):
    out = [lt for lt in linkTypes if lt[1] == type]
    assert len(out) < 2 #double check for duplicates
    if out:
        return out[0]
    else:
        return None

def lookup(type):
    out = (type)
    if out:
        return out[0]
    else:
        return out

def shortName(type):
    out = getLinkType(type)
    if out:
        return out[2]
    else:
        return out