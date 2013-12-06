#!/usr/bin/env python

import logging
import cymru.ip2asn.dns
import cymru.ip2asn.whois
import cymru.mhr.dns
import cymru.mhr.whois
import cymru.bogon.dns

from cymru import ip_expand

import unittest

logging.basicConfig(level=logging.INFO)



class TestDNS(unittest.TestCase):

    def setUp(self):
        self.c = cymru.ip2asn.dns.DNSClient()

    def testASN(self):
        asns = ['1515','5005','64496']
        datas = self.c.lookupmany_dict(asns,qType='ASN')
        for attr in ['asn','cc','lir','owner','date']:
            self.assertIsNotNone( getattr(datas[asns[0]], attr) )
            self.assertIsNotNone( getattr(datas[asns[1]], attr) )
            self.assertIsNone( getattr(datas[asns[2]], attr) )

    def testOrigin(self):
        ips = ['88.198.224.117','127.0.0.1']
        datas = self.c.lookupmany_dict(ips)
        for attr in ['asn','prefix','cc','lir','date']:
            self.assertIsNotNone( getattr(datas[ips[0]], attr) )
            self.assertIsNone( getattr(datas[ips[1]], attr) )

    def testOrigin6(self):
        ips = ['2001:4860:8010::68','2001:7a8:1:1::76','3ffe:1:1::1']
        datas = self.c.lookupmany_dict(ips,qType='IP6')
        # getip - need ip6 full address
        for attr in ['asn','prefix','cc','lir','date']:
            self.assertIsNotNone( getattr(datas[ip_expand(ips[0])], attr) )
            self.assertIsNotNone( getattr(datas[ip_expand(ips[1])], attr) )
            self.assertIsNone( getattr(datas[ip_expand(ips[2])], attr) )

    def testPeer(self):
        ips = ['91.121.224.117','10.10.11.12']
        datas = self.c.lookupmany_dict(ips,qType='PEER')
        for attr in ['asn','prefix','cc','lir','date']:
            self.assertIsNotNone( getattr(datas[ips[0]], attr) )
            self.assertIsNone( getattr(datas[ips[1]], attr) )




if __name__ == '__main__':
  unittest.main()
