import struct
import base64
import hashlib


def _signature(flags: int,
               protocol: int,
               algorithm: int,
               dnskey: str,
               st=bytes()):
    st += struct.pack('!HBB', flags, protocol, algorithm)
    st += base64.b64decode(dnskey)
    return st


def _calculate_keyid(flags: int,
                     protocol: int,
                     algorithm: int,
                     dnskey: str):
    st = _signature(flags, protocol, algorithm, dnskey)
    
    cnt = 0
    for idx in range(len(st)):
        s = struct.unpack('B', st[idx:idx + 1])[0]
        if (idx % 2) == 0:
            cnt += s << 8
        else:
            cnt += s
    
    return ((cnt & 0xFFFF) + (cnt >> 16)) & 0xFFFF


def unified_domain(domain: str) -> str:
    if not domain:
        return '.'
    if domain[-1] == '.':
        return domain
    return domain + '.'


def _calculate_ds(domain: str,
                  flags: int,
                  protocol: int,
                  algorithm: int,
                  dnskey: str):
    domain = unified_domain(domain)
    
    def _signature_of_domain(domain):
        st = bytes()
        for i in domain.split('.'):
            st += struct.pack('B', len(i)) + i.encode()
        return _signature(flags, protocol, algorithm, dnskey, st)
    
    signature = _signature_of_domain(domain)
    
    return {
        'sha1': hashlib.sha1(signature).hexdigest().upper(),
        'sha256': hashlib.sha256(signature).hexdigest().upper(),
    }


class DNSKEY:
    def __init__(self, dnskey: str):
        self.flags = self.protocol = self.algorithm = self.key = None
        segments = dnskey.split(' ')
        if len(segments) < 4:
            return
        self.flags = int(segments[0])
        self.protocol = int(segments[1])
        self.algorithm = int(segments[2])
        self.key = ''.join(segments[3:])


def convert_domain_dnskey_to_ds(domain: str, dnskey: str) -> list:
    dk = DNSKEY(dnskey)
    
    keyid = _calculate_keyid(dk.flags, dk.protocol, dk.algorithm, dk.key)
    ds = _calculate_ds(domain, dk.flags, dk.protocol, dk.algorithm, dk.key)
    
    return [
        ' '.join([str(keyid), str(dk.algorithm), '1', ds['sha1']]),
        ' '.join([str(keyid), str(dk.algorithm), '2', ds['sha256']])
    ]


def unified_ds(ds: str) -> str:
    segments = ds.split()
    if len(segments) < 4:
        return ''
    s1, s2, s3, *sr = segments
    s4 = ''.join(sr)
    ds = ' '.join([s1, s2, s3, s4])
    return ds.upper()


def is_valid_dnskey(domain: str, dnskey: str, ds: str) -> bool:
    ds = unified_ds(ds)
    dss = convert_domain_dnskey_to_ds(domain, dnskey)
    return ds in dss


def test_success_dnskey():
    domain = "verisignlabs.com"
    dnskey = '257 3 8 AwEAAdiAmIhpo/OUFkl4Y0Tk+cWsmZmpklKZYkgoeKJG8WbNKwEnjMMV T9xoEKFvY4UkmL0/RYE+16Zij9njGbDZbfuDr9GozUFCopAddvkf9Dzi 2EXzN6+buiIVxN0n5Q30eZjt+1w1fYdulZIe3MN+96BT50jCliQ6FSZD 7IGOumOKoG8mxg1WUfFVt3sMF4U+Djth4s2/ECXi5iidYcz7LxhOQ6zk iPVMXaFenSm4rBjkgICYFLI3D44XDwDbErlFloxRl6HVjPokY0zuTswi e3ZENNZYSbdL70PCIBiVmWfBXmKUc9JTGZSK96ozOksWzd8+HWV2s28W +S2O1BGjdrU='
    ds = '57947 8 2 64877DB0EA66B229FBE8380DECF40A8BA36114F5FB34B5BFAEF0716D 6029638D'
    assert is_valid_dnskey(domain, dnskey, ds)
    domain = "verisignlabs.com."
    assert is_valid_dnskey(domain, dnskey, ds)
