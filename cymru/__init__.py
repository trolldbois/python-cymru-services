#!/usr/bin/python -OO
# -*- coding: iso-8859-15 -*-

try:
    import IPy
    def ip_reverse(ip):
        ip = IPy.IP(ip)
        if ip.version() == 4:
            return ip.reverseName()[:-len('.in-addr.arpa.')]
        elif ip.version() == 6:
            return IPy.IP(ip).reverseName()[:-len('.ip6.arpa.')]
        else:
            raise ValueError('IP Type %d is not supported'%(ip.version()))
    def ip_expand(ip):
        return IPy.IP(ip).strNormal()

except ImportError as e:
    import ipaddress # sucks for reverse.
    def ip_reverse(ip):
        ip = ipaddress.ip_address(ip)
        if ip.version == 4:
            _tmp = ip_expand(ip).split('.')
            _tmp.reverse()
            return '.'.join(_tmp)
        elif ip.version == 6:
            _tmp = [ c for c in ip_expand(ip) if c !=':']
            _tmp.reverse()
            return '.'.join(_tmp)
        else:
            raise ValueError('IP Type %d is not supported'%(ip.version))
    def ip_expand(ip):
        return ipaddress.ip_address(ip).exploded



__all__ = ["darknet", "bogon", "ip2asn","mhr","ip_reverse","ip_expand"]

