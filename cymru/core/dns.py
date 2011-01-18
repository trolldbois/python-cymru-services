#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# cymru.py
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

log = logging.getLogger('core.dns')


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


class DNSClient:
  """Python interface to DNS services.
  """
  QTYPES=[None]
  client = None
  cache = None
  
  def __init__(self, svcName, memcache_host='localhost:11211'):
    self.client=ADNS.init()
    self.cache = cache.Cache(svcName,memcache_host)
    
  def _lookupmany(self, values, qType=None):
    ''' Lookup the values with a qType query to cymru services.
    '''
    if qType is None:
      qType=self.QTYPES[0]
    # iterwindows on the request...
    if (len(values) == 0):
      return
    elif (len(values) > 300):
      log.warning('That is alot of queries ... Please use Whois server batch mode')
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
    return _lookupmany(values,qType)
    
  ''' submits the queries to ADNS'''
  def _lookupmany_raw(self, values, qType):
    # decide what callbacks to use
    buildRequest, resolveCB=self._getCB(qType)
    #
    values = set(values)
    keys=[]
    for value in values:
      #build qname and send resolve
      extra=(qType,value)
      fqdn=buildRequest(value)
      log.debug('Lookup %s'%(fqdn))
      self.client.submit(fqdn,adns.rr.TXT, 0, resolveCB, extra)
    self.client.finish()
    records,not_cached=self.cache.get_cached(values,qType)
    return records.itervalues()


  def _getCB(self,qType):
    '''Virtual function to be implemented by service specific clients.
    
      Return 2 function reference : buildRequestString,resolveCallback
      
      buildRequestString : Returns the DNS query fqdn.
      resolveCallback : DNS response callback (  def _asyncResolve( self, answer, qname, rr, flags, extra) )

    '''
    raise NotImplementedError()
  
    


def lookup_stdin():
    from optparse import OptionParser
    import fileinput
    parser = OptionParser(usage = "usage: %prog [options] [files]")
    parser.add_option("-d", "--delim",  dest="delim", action="store", default=None,
        help="delimiter to use instead of justified")
    parser.add_option("-f", "--fields", dest="fields", action="append",
        help="comma separated fields to include (asn,ip,prefix,cc,owner)")

    if HAVE_MEMCACHE:
        parser.add_option("-c", "--cache", dest="cache", action="store", default="localhost:11211",
            help="memcache server (default localhost)")
        parser.add_option("-n", "--no-cache", dest="cache", action="store_false",
            help="don't use memcached")
    else:
        memcache_host = None

    (options, args) = parser.parse_args()

    #fix the fields: convert ['a,b','c'] into ['a','b','c'] if needed
    fields = []
    if options.fields:
        for f in options.fields:
            fields.extend(f.split(","))
    else:
        fields = 'asn ip prefix cc owner'.split()

    #generate the format string
    fieldwidths = {
        'asn': 8,
        'ip': 15,
        'prefix': 18,
        'cc':   2,
        'owner': 0,
    }
    if options.delim:
        format = options.delim.join("%%(%s)s" % f for f in fields)
    else:
        format = ' '.join("%%(%s)-%ds" % (f, fieldwidths[f]) for f in fields)

    #setup the memcache option

    if HAVE_MEMCACHE:
        memcache_host = options.cache
        if memcache_host and ':' not in memcache_host:
            memcache_host += ":11211"

    c=DNSClient(memcache_host=memcache_host)
    ips = []

    for line in fileinput.input(args):
        ip=line.strip()
        ips.append(ip)
    for r in c.lookupmany(ips):
        #print format % r.__dict__
        print r


if __name__ == "__main__":
  logging.basicConfig(level=logging.INFO)
  #testOrigin()
  #testOrigin6()
  #testASN()
  #testPeer()
  lookup_stdin()

