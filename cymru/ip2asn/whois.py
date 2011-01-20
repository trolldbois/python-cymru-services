#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
#
# This module is released under the GPL v3 License:
# http://www.opensource.org/licenses/gpl-3.0

import logging

import IPy

from ..core.whois import WhoisClient as WhoisCoreClient

log = logging.getLogger('cymru.ip2asn.whois')


def fix(x):
  if x is None:
    return None
  x = x.strip()
  if x == "NA":
    return None
  return str(x.decode('ascii','ignore'))

class recordIp:
  def __init__(self, asn=None, ip=None, prefix=None, cc=None, lir=None, date=None, owner=None, info=None):
    self.init(asn, ip, prefix, cc, lir, date, owner, info)
  def init(self, asn=None, ip=None, prefix=None, cc=None, lir=None, date=None, owner=None, info=None):
    self.asn    = fix(asn)
    self.ip     = fix(ip)
    self.prefix = fix(prefix)
    self.cc     = fix(cc)
    self.lir  = fix(lir)
    self.owner  = fix(owner)
    self.date  = fix(date)
    self.info   = fix(info)
  def __repr__(self):
    return "<%s instance: asn:%s|ip:%s|prefix:%s|cc:%s|lir:%s|date:%s|owner:%s>" \
          % (self.__class__, self.asn, self.ip, self.prefix, self.cc, self.lir, self.date,self.owner)

class recordAS:
  def __init__(self, asn=None, cc=None, lir=None, date=None, owner=None):
    self.init(asn, cc, lir, date, owner)
  def init(self, asn=None, cc=None, lir=None, date=None, owner=None):
    self.asn    = fix(asn)
    self.cc     = fix(cc)
    self.lir  = fix(lir)
    self.owner  = fix(owner)
    self.date  = fix(date)
  def __repr__(self):
    return "<%s instance: asn:%s|cc:%s|lir:%s|date:%s|owner:%s>" \
          % (self.__class__, self.asn, self.cc, self.lir, self.date,self.owner)


class WhoisClient(WhoisCoreClient):
  '''Whois light client for Cymru Whois server.'''
  QTYPES=['IP','IP6','ASN']
  client = None
  cache = None
  def __init__(self,server='whois.cymru.com',port=43,memcache_host='localhost:11211'):
    WhoisCoreClient.__init__(self,'ip2asn',server,port,memcache_host)
    
  def _getCB(self,qType):
    if qType == 'IP':
      return self.buildRequest,self.buildRecordOrigin
    elif qType == 'IP6':
      return self.buildRequest,self.buildRecordOrigin6
    elif qType == 'ASN':
      return self.buildRequestAS,self.buildRecordAS
    else:
      pass

  def buildRequest(self,values):
    vstring='\r\n'.join(values)
    vstring='begin\r\nverbose\r\n'+vstring+'\r\nend\r\n'
    return vstring

  def buildRequestAS(self,values):
    vstring='AS'+'\r\nAS'.join(values)
    vstring='begin\r\nverbose\r\n'+vstring+'\r\nend\r\n'
    return vstring

  def buildRecordOrigin(self,response):
    return self.buildRecords(response,recordIp,1,'IP')

  def buildRecordOrigin6(self,response):
    return self.buildRecords(response,recordIp,1,'IP6')
    
  def buildRecordAS(self,response):
    return self.buildRecords(response,recordAS,0,'ASN')

  def buildRecords(self,response,recordMaker,ind,qType):
    lines=response.split('\n')
    log.debug('lines : %s'%(lines))
    records=[]
    for line in lines[1:-1]:
      columns=[col.strip() for col in line.split('|')]
      log.debug('columns %s'%(columns))
      r=recordMaker(*columns)
      log.debug('caching : %s'%(r))
      self.cache.cache(columns[ind],r,qType)
      records.append(r)
    return records
  




def testIPv4():
  log.debug('START TEST IPV4')
  c= WhoisClient()
  ips=['192.168.0.244','198.51.100.0','202.42.42.42']
  datas=[]
  datas=c.lookupmany(ips)
  for data in datas:
    log.info("c.lookupmany(%s,qType='IP') : %s"%(data.ip, data))
  log.debug('END TEST IPV4\n\n')

def testIPv6():
  log.debug('START TEST IPv6')
  c= WhoisClient()
  ips=['2001:4860:8010::68','2001:7a8:1:1::76']
  datas=[]
  datas=c.lookupmany(ips,qType='IP6')
  i=0
  for data in datas:
    log.info("c.lookupmany(%s,qType='IP6') : %s"%(data.ip, data))
    log.info([data])
    i+=1
  log.debug('END TEST IPv6\n\n')

def testASN():
  log.debug('START TEST ASN')
  c= WhoisClient()
  asns=['1515','5005']
  datas=c.lookupmany(asns,qType='ASN')
  for data in datas:
    log.info("c.lookup(%s,qType='ASN') = %s"%(data.asn,data))
  log.debug('END TEST ASN\n\n')

def testAll():
  testIPv4()
  testIPv6()
  testASN()


if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)

