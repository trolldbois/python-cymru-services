#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cymru.py
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
#
# This module is released under the GPL v3 License:
# http://www.opensource.org/licenses/gpl-3.0

import logging

import adns,IPy

from ..core.dns import DNSClient as DNSCoreClient

log = logging.getLogger('cymru.ip2asn.dns')


class record:
  def __init__(self, asn=None, ip=None, prefix=None, cc=None, owner=None,date=None,lir=None):
    self.init(asn, ip, prefix, cc, owner,date,lir)
  def init(self, asn=None, ip=None, prefix=None, cc=None, owner=None,date=None,lir=None):
    def fix(x):
      if x is None:
        return None
      x = x.strip()
      if x == "NA":
        return None
      return str(x.decode('ascii','ignore'))
    self.asn    = fix(asn)
    self.ip     = fix(ip)
    self.prefix = fix(prefix)
    self.cc     = fix(cc)
    self.lir  = fix(lir)
    self.owner  = fix(owner)
    self.date  = fix(date)
  def __repr__(self):
    return "<%s instance: asn:%s|ip:%s|prefix:%s|cc:%s|lir:%s|owner:%s|date:%s>" \
          % (self.__class__, self.asn, self.ip, self.prefix, self.cc, self.lir, self.owner,self.date)

class recordOrigin(record):
  def __init__(self, asn, prefix, cc, lir,date):
    self.init(asn=asn,prefix=prefix,cc=cc,lir=lir,date=date)
  def __repr__(self):
    return "<%s instance: asn:%s|prefix:%s|cc:%s|lir:%s|date:%s>" \
          % (self.__class__, self.asn, self.prefix, self.cc, self.lir, self.date)

class recordOrigin6(recordOrigin):
  def __init__(self, asn, prefix, cc, lir,date):
    self.init(asn=asn,prefix=prefix,cc=cc,lir=lir,date=date)
  def __repr__(self):
    return "<%s instance: asn:%s|prefix:%s|cc:%s|lir:%s|date:%s>" \
          % (self.__class__, self.asn, self.prefix, self.cc, self.lir, self.date)

class recordASN(record):
  def __init__(self, asn, cc, lir, date, owner):
    self.init(asn=asn,cc=cc,lir=lir,date=date, owner=owner)
  def __repr__(self):
    return "<%s instance: asn:%s|cc:%s|lir:%s|owner:%s|date:%s>" \
          % (self.__class__, self.asn, self.cc, self.lir, self.owner,self.date)

class recordPeer(record):
  def __init__(self, asn, prefix, cc, lir,date):
    # asn to list
    asn=",".join(asn.strip().split(" "))
    self.init(asn=asn,prefix=prefix,cc=cc,lir=lir,date=date)
  def __repr__(self):
    return "<%s instance: asn:%s|prefix:%s|cc:%s|lir:%s|date:%s>" \
          % (self.__class__, self.asn, self.prefix, self.cc, self.lir, self.date)


class DNSClient(DNSCoreClient):
  """Python interface to IP-to-ASN service by DNS

  **Usage**

  >>> import socket
  >>> ip = socket.gethostbyname("www.google.com")
  >>> from cymrudns import DNSClient
  >>> c=DNSClient()
  >>> r=c.lookup(ip)
  >>> print r.asn
  15169
  >>> print r.owner
  GOOGLE - Google Inc.
  >>> 
  >>> ip_ms = socket.gethostbyname("www.microsoft.com")
  >>> for r in c.lookupmany([ip, ip_ms]):
  ...     print r.owner
  GOOGLE - Google Inc.
  MICROSOFT-CORP---MSN-AS-BLOCK - Microsoft Corp
  """
  QTYPES=['IP','IP6','ASN','PEER']
  ORIGIN = 'IP'
  __ORIGIN = '.origin.asn.cymru.com.'
  ORIGIN6 = 'IP6'
  __ORIGIN6 = '.origin6.asn.cymru.com.'
  PEER = 'PEER'
  __PEER = '.peer.asn.cymru.com.'
  ASN = 'ASN'
  __ASN = '.asn.cymru.com.'
  
  def __init__(self, memcache_host='localhost:11211'):
    DNSCoreClient.__init__(self,'ip2asn')
    pass

  def _getCB(self,qType):
    if qType == None:
      pass
    elif qType == self.ORIGIN:
      return self._makeRequestOrigin,self._asyncResolveOrigin
    elif qType == self.ORIGIN6:
      return self._makeRequestOrigin6,self._asyncResolveOrigin6
    elif qType == self.PEER:
      return self._makeRequestPeer,self._asyncResolvePeer
    elif qType == self.ASN:
      return self._makeRequestASN,self._asyncResolveASN
    else:
      pass
              
  def _makeRequestOrigin(self,ip):
    return adns.rr.TXT,IPy.IP(ip).reverseName().replace('.in-addr.arpa.',self.__ORIGIN)
  def _makeRequestOrigin6(self,ip):
    return adns.rr.TXT,IPy.IP(ip).reverseName().replace('.ip6.arpa.',self.__ORIGIN6)
  def _makeRequestASN(self,asn):
    return adns.rr.TXT,"AS"+asn+self.__ASN
  def _makeRequestPeer(self,peer):
    return adns.rr.TXT,IPy.IP(peer).reverseName().replace('.in-addr.arpa.',self.__PEER)
    

  def _asyncResolve( self, recordMaker, answer, qname, rr, flags, extra):
    log.debug(' inputs : %s ; qname:%s rr:%s flags:%s l:%s'%(answer, qname, rr, flags, extra) )
    r=''
    qType,realq=extra
    log.debug('Real query : %s , qname : %s '%(realq,qname))
    if (len(answer[3])==0):
      log.warning('No lookup for %s'%(qname))
      r=record()
    else:
      result=answer[3][0][0]
      parts=result.split("|")
      r=recordMaker(*parts)
    self.cache.cache(realq,r,qType)

  '''
    #(0, None, 1259120947, (('9003 | 78.155.128.0/19 | FR | ripencc | 2007-07-31',),)) 25.138.155.78.origin.asn.cymru.com. 16 0 None  
  '''
  def _asyncResolveOrigin( self, answer, qname, rr, flags, l):
    self._asyncResolve(recordOrigin,answer,qname,rr,flags,l)

  '''
    #(0, None, 1292214927, (('15169 | 2001:4860::/32 | US | arin | 2005-03-14',),)) 8.6.0.1.0.8.0.6.8.4.1.0.0.2.origin6.asn.cymru.com. 16 0 None
  '''
  def _asyncResolveOrigin6( self, answer, qname, rr, flags, l):
    self._asyncResolve(recordOrigin6,answer,qname,rr,flags,l)

  '''
    #(0, None, 1292279997, (('16276 | FR | ripencc | 2001-02-15 | OVH OVH',),)) AS16276.asn.cymru.com. 16 0 None  
  '''
  def _asyncResolveASN( self, answer, qname, rr, flags, l):
    self._asyncResolve(recordASN,answer,qname,rr,flags,l)

  '''
    #(0, None, 1292218934, (('1299 3320 3549 4565 5511 6453 6762 10310 | 91.121.0.0/16 | FR | ripencc | 2006-09-20',),))
  '''
  def _asyncResolvePeer( self, answer, qname, rr, flags, l):
    self._asyncResolve(recordPeer,answer,qname,rr,flags,l)

    

def testOrigin():
  log.debug('START TEST ORIGIN')
  c= DNSClient()
  ips=['88.198.224.117','42.42.42.42']
  datas=c.lookupmany_dict(ips)
  for ip in ips:
    log.info("c.lookupmany_dict(%s,qType='IP') = %s"%(ip, datas[IPy.IP(ip).strNormal()]))
  log.debug('END TEST ORIGIN\n\n')

def testOrigin6():
  log.debug('START TEST ORIGIN6')
  c= DNSClient()
  ips=['2001:4860:8010::68','2001:7a8:1:1::76']
  datas=c.lookupmany_dict(ips,qType='IP6')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,qType='IP6') = %s"%(ip,datas[IPy.IP(ip).strNormal()]))
  log.debug('END TEST ORIGIN6\n\n')


def testASN():
  log.debug('START TEST ASN')
  c= DNSClient()
  asns=['1515','5005']
  datas=c.lookupmany_dict(asns,qType='ASN')
  for asn in asns:
    log.info("c.lookupmany_dict(%s,qType='ASN') = %s"%(asn,datas[asn]))
  log.debug('END TEST ASN\n\n')

def testPeer():
  log.debug('START TEST PEER')
  c= DNSClient()
  ips=['91.121.224.117']
  datas=c.lookupmany_dict(ips,qType='PEER')
  for ip in ips:
    log.info("c.lookupmany_dict(%s,qType='PEER') = %s"%(ip,datas[IPy.IP(ip).strNormal()]))
  log.debug('END TEST PEER\n\n')


def testAll():
  testOrigin()
  testOrigin6()
  testASN()
  testPeer()


if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)

