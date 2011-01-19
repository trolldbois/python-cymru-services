#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
#
# This module is released under the GPL v3 License:
# http://www.opensource.org/licenses/gpl-3.0

import socket
import errno
import logging

import ADNS,adns
import IPy

import cache

log = logging.getLogger('core.whois')




class recordIp:
  def __init__(self, asn=None, ip=None, prefix=None, cc=None, lir=None, date=None, owner=None, info=None):
    self.init(asn, ip, prefix, cc, lir, date, owner, info)
  def init(self, asn=None, ip=None, prefix=None, cc=None, lir=None, date=None, owner=None, info=None):
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
    self.info   = fix(info)
  def __repr__(self):
    return "<%s instance: asn:%s|ip:%s|prefix:%s|cc:%s|lir:%s|date:%s|owner:%s>" \
          % (self.__class__, self.asn, self.ip, self.prefix, self.cc, self.lir, self.date,self.owner)


class WhoisClient():
  '''Whois light client for Cymru Whois server.'''
  QTYPES=[None]
  client = None
  cache = None
  def __init__(self,svcName,server='whois.cymru.com',port=43,memcache_host='localhost:11211'):
    self.server=server
    self.port=port
    self.cache=cache.Cache(svcName,memcache_host)
      
  def _lookupmany(self, values, qType=None):
    ''' Lookup the values with a qType query to cymru services.
    '''
    if qType is None:
      qType=self.QTYPES[0]
    # iterwindows on the request...
    if (len(values) == 0):
      return
    fullcache=dict()
    log.debug("lookupmany : %s"%values)
    # query DNS by slices of 100
    for batch in iterwindow(values, 100):
      cached, not_cached = self.cache.get_cached(batch,qType)
      # avoid race condition possible if a entry expires while we are resolving others || small cache size...
      fullcache.update(cached)
      log.debug("cached:%d not_cached:%d" % (len(cached), len(not_cached)) )
      if not_cached:
        # launch resolution for new queries
        for rec in self._lookupmany_raw(not_cached,qType):
          pass
    log.debug("LOOKUP FINISHED")
    # get full results. 
    cached,not_cached = self.cache.get_cached(values,qType)
    fullcache.update(cached)
    log.debug("cached:%d not_cached:%d" % (len(cached), len(not_cached)) )
    # return (found, not_found)
    return fullcache, not_cached
    
    """Look up a single address.  """
  def lookup(self, value, qType=None):
    if qType is None:
      qType=self.QTYPES[0]
    return list(self.lookupmany([value],qType))[0]
    
  def lookupmany(self, values, qType=None):
    """Look up many ip addresses, returning a dictionary of ip -> record"""
    if qType is None:
      qType=self.QTYPES[0]
    # clean values and type IP values
    values = [str(value).strip() for value in values]
    if qType in ['IP','IP6']:
      values = [IPy.IP(value).strNormal() for value in values]
    #go
    found,not_found = self._lookupmany(values,qType)
    #exit same order
    for value in values:
      if value in not_found:
        yield None
      else:
        yield found[value]
    return

  def lookupmany_dict(self, values, qType=None):
    if qType is None:
      qType=self.QTYPES[0]
    # clean values and type IP values
    values = [str(value).strip() for value in values]
    if qType in ['IP','IP6']:
      values = [IPy.IP(value).strNormal() for value in values]
    #go
    return self._lookupmany(values,qType)
  
  def whois(self,query):
    ''' submit queries to whois server'''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((self.server, self.port))
    log.debug(query)
    sock.send(query)
    response = ''
    while True:
      d = sock.recv(4096)
      response += d
      if d == '':
        break
    sock.close()
    return response
      
  ''' submits the queries to ADNS'''
  def _lookupmany_raw(self, values, qType):
    # decide what callbacks to use
    buildRequest, buildRecords=self._getCB(qType)
    #
    values = set(values)
    query=buildRequest(values)
    response=self.whois(query)
    log.debug(response)
    records=buildRecords(response)
    log.debug('cache contents : %s'%(self.cache.c) )
    return response


  def _getCB(self,qType):
    '''Virtual function to be implemented by service specific clients.
    
      Return 2 function reference : buildRequestString,resolveCallback
      
      buildRequestString : Returns the DNS query fqdn.
      resolveCallback : DNS response callback (  def _asyncResolve( self, answer, qname, rr, flags, extra) )

    '''
    #raise NotImplementedError()
    #return None,None
    return self.buildRequest,self.buildRecordOrigin

  def buildRequest(self,values):
    vstring='\r\n'.join(values)
    vstring='begin\r\nverbose\r\n'+vstring+'\r\nend\r\n'
    return vstring

  def buildRecordOrigin(self,response):
    return self.buildRecords(response,recordIp,1,'IP')
    
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
  






def iterwindow(l, slice=50):
  """Generate sublists from an iterator
  >>> list(iterwindow(iter(range(10)),3))
  [[0, 1, 2], [3, 4, 5], [6, 7, 8], [9]]
  """
  assert(slice > 0)
  a=[]
  for x in l:
    if len(a) >= slice :
      yield a
      a=[]
    a.append(x)
  if a:
      yield a




if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)
  #testOrigin()
  #testOrigin6()
  #testASN()
  #testPeer()
  lookup_stdin()

