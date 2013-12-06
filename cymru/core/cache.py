#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Loic Jaquemet loic.jaquemet+cymru@gmail.com
#
#
# This module is released under the GPL v3 License:
# http://www.opensource.org/licenses/gpl-3.0

import logging

log = logging.getLogger('cache')

try :
        import memcache
        HAVE_MEMCACHE = True
except ImportError:
        HAVE_MEMCACHE = False

#@functools.lru_cache(maxsize=300)
#.cache_info()
# on fonction

class Cache:
    """
    Wrapper around memcache if present.
    """
    timeout= 60*60*6
    sep=':'
    svcName='default'
    KEY_FMT = "cymru:%s:%s:%s"
    c = None    
    def __init__(self, svcName, memcache_host='localhost:11211'):
        self.c = None
        self.svcName=svcName
        if HAVE_MEMCACHE and memcache_host:
            self.c = memcache.Client([memcache_host])
        else:
            self.c = dict()

    def get_cached(self, values, qType):
        ''' return cached answers and not_cached values from cache '''
        if type(values) != list and type(values) != set :
            log.warning('get_cached should use a list value')
            values = [values]
        log.debug('get_cached START values %s'%( values) )
        cached={}
        keys=[]
        if (not values):
            return {}
        # create keys based on prefix + svcname + qType + qvalue    
        keys = [self.KEY_FMT % (self.svcName,qType,value) for value in values]
        prefixlen = len(self.KEY_FMT % (self.svcName,qType,'')) 
        # PY3, 'value' is not defined/modified in locals()
        # log.debug('get_cached prefixlen %d / %s'%(prefixlen,self.KEY_FMT % (self.svcName,qType,value)) )
        # look in local dict
        if not HAVE_MEMCACHE:
            vals = dict()
            for k in keys:
                log.debug('get_cached looking for key %s'%(k) )
                if ( k in self.c):
                    vals[k] = self.c[k]
            log.debug('get_cached related vals in CACHE %s'%(vals) )
        else:
            vals = self.c.get_multi(keys)
        # vals contains cached cached answers - we return dict based on qvalue
        cached=dict(    (k[prefixlen:], v) for k,v in vals.items())
        if (not cached):
            cached={}
        log.debug('get_cached cached %s'%(cached) )
        # build not_cached
        not_cached = set(values) - set(cached.keys())
        #not_cached = [key[prefixlen:] for key in set(keys) - set(vals.keys()) ]
        log.debug('get_cached not_cached are %s'%(not_cached) )
        return cached, not_cached

    def cache(self,value, r, qType):
        ''' save a query/response in cache for qType '''
        # caching the original IP and not the cidr network .. r.ip = cidr from asn
        if not HAVE_MEMCACHE:
            self.c[self.KEY_FMT % (self.svcName,qType,value)]=r
        else:
            self.c.set(self.KEY_FMT % (self.svcName,qType,value), r, self.timeout)
        log.debug("cache '%s':'%s' "%( (self.KEY_FMT %(self.svcName,qType,value),r) ) )
        return


def testCache():
    c= Cache('bogon')
    ips=['91.121.224.117']
    r='testval|testval|testval'
    c.cache(ips[0],r,'IP')
    cached,not_cached=c.get_cached(ips,'IP')
    if len(not_cached) !=0:
        log.error('test error len not_cached')
    elif len(cached) != 1:
        log.error('test error len cached')
    elif not ips[0] in cached:
        log.error('test error ips[0] not in cached')
    elif cached[ips[0]] != r:
        log.error('test error cached retval is different')
    else:
        log.debug('ok')

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    testCache()

