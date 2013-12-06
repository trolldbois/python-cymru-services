#!/usr/bin/env python

import logging
import cymru.ip2asn.dns
import cymru.ip2asn.whois
import cymru.bogon.dns
import cymru.mhr.dns
import cymru.mhr.whois

from cymru import ip_expand

import unittest

class TestDNS(unittest.TestCase):

    def setUp(self):
        self.c = cymru.ip2asn.dns.DNSClient()

    def testASN(self):
        asns = ['1515','5005','64496']
        datas = self.c.lookupmany_dict(asns,qType='ASN')
        for attr in ['asn','cc','lir','owner','date']:
            self.assertIsNotNone( getattr(datas[asns[0]], attr) )
            if attr != 'date': # date can be null
                self.assertIsNotNone( getattr(datas[asns[1]], attr) )
            self.assertIsNone( getattr(datas[asns[2]], attr) )

    def testIP4(self):
        ips = ['88.198.224.117','127.0.0.1']
        datas = self.c.lookupmany_dict(ips)
        for attr in ['asn','prefix','cc','lir','date']:
            self.assertIsNotNone( getattr(datas[ips[0]], attr) )
            self.assertIsNone( getattr(datas[ips[1]], attr) )

    def testIP6(self):
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

class TestWhois(unittest.TestCase):

    def setUp(self):
        self.c = cymru.ip2asn.whois.WhoisClient()

    def testASN(self):
        asns = ['1515','5005','64496']
        datas = [x for x in self.c.lookupmany(asns,qType='ASN')]
        #'asn', is not null in lookup many
        for attr in ['cc','lir','owner','date']:
            self.assertIsNotNone( getattr(datas[0], attr) )
            if attr != 'date': # date can be null
                self.assertIsNotNone( getattr(datas[1], attr) )
            self.assertIsNone( getattr(datas[2], attr) )

    def testIP4(self):
        ips = ['88.198.224.117','127.0.0.1']
        datas = [x for x in self.c.lookupmany(ips)]
        for attr in ['asn','prefix','cc','lir','date']:
            self.assertIsNotNone( getattr(datas[0], attr) )
            # lir can be 'other' ?
            if attr != 'lir':
                self.assertIsNone( getattr(datas[1], attr) )

    def testIP6(self):
        ips = ['2001:4860:8010::68','2001:7a8:1:1::76','3ffe:1:1::1']
        datas = [x for x in self.c.lookupmany(ips,qType='IP6')]
        for attr in ['asn','prefix','cc','lir','date']:
            self.assertIsNotNone( getattr(datas[0], attr) )
            self.assertIsNotNone( getattr(datas[1], attr) )
            self.assertIsNone( getattr(datas[2], attr) )

class TestBogon(unittest.TestCase):

    def setUp(self):
        self.c = cymru.bogon.dns.DNSClient()

    def testBogon(self):
        ips = ['192.168.0.244','198.51.100.0','202.42.42.42']
        datas = self.c.lookupmany_dict(ips,'IP')
        self.assertTrue( datas[ips[0]] )
        self.assertTrue( datas[ips[1]] )
        self.assertFalse( datas[ips[2]] )

    def testFull6Bogon(self):
        ips = ['fe80::4','3ffe:5678:987::3','2001:678:67::01']
        datas = self.c.lookupmany_dict(ips,'FULLIP6')
        self.assertTrue( datas[ips[0]] )
        self.assertFalse( datas[ips[1]] )
        self.assertFalse( datas[ips[2]] )

    def testFull6BogonRange(self):
        ips = ['fe80::4','3ffe:5678:987::3','2001:678:67::01']
        datas = self.c.lookupmany_dict(ips,'FULLIP6RANGE')
        self.assertEqual( datas[ips[0]], '8000::/1', )
        self.assertFalse( datas[ips[1]] )
        self.assertFalse( datas[ips[2]] )

    def testFullBogon(self):
        ips = ['192.168.0.244','198.51.100.0','202.42.42.42']
        datas = self.c.lookupmany_dict(ips,'FULLIP')
        self.assertTrue( datas[ips[0]] )
        self.assertTrue( datas[ips[1]] )
        self.assertFalse( datas[ips[2]] )

    def testFullBogonRange(self):
        ips = ['192.168.0.244','198.51.100.0','202.42.42.42']
        datas = self.c.lookupmany_dict(ips,'FULLIPRANGE')
        self.assertEqual( datas[ips[0]], '192.168.0.0/16', )
        self.assertEqual( datas[ips[1]], '198.51.100.0/24', )
        self.assertFalse( datas[ips[2]] )


class TestMhrDNS(unittest.TestCase):

    def setUp(self):
        self.c = cymru.mhr.dns.DNSClient()

    def testHash(self):
        hashes = ['0fd453efa2320350f2b08fbfe194b39aab5f798d','733a48a9cb49651d72fe824ca91e8d00']
        #'733a48a9cb49651d72fe824ca91e8d00' is malware
        res = [x for x in self.c.lookupmany(hashes)]
        self.assertIsNone( res[0].detection )
        self.assertIsNotNone( res[1].detection )

class TestMhrWhois(unittest.TestCase):

    def setUp(self):
        self.c = cymru.mhr.whois.WhoisClient()

    def testHash(self):
        hashes = ['0fd453efa2320350f2b08fbfe194b39aab5f798d','733a48a9cb49651d72fe824ca91e8d00']
        #'733a48a9cb49651d72fe824ca91e8d00' is malware
        res = [x for x in self.c.lookupmany(hashes)]
        self.assertIsNone( res[0].detection )
        self.assertIsNotNone( res[1].detection )


if __name__ == '__main__':
    unittest.main()
  
