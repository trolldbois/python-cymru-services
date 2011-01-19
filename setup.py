# -*- coding: utf-8 -*-
from setuptools import setup
from glob import glob

setup(name="cymru-services",
    version="1.2",
    description="Python API for the Cymru Services",
    long_description="""
Python API to use Cymru services. This code is not supported nor endorsed by Cymru.

Code licensed under http://www.gnu.org/licenses/gpl-3.0.txt


Services by cymru :

The Bogon Reference

A bogon prefix is a route that should never appear in the Internet routing table. This can be for one of several reasons - either the prefix is within a private or reserved IP address block, or a block that has not yet been allocated to a Regional Internet Registry (RIR). The Bogon Reference pages provide a number of resources for the filtering of bogon prefixes from your routers and hosts. Check out the bogon reference for more details!

The IP to ASN Mapping Project

Team Cymru provides a number of query interfaces that allow for the mapping of IP addresses to BGP prefixes and Autonomous System Numbers (ASNs), based on BGP feeds from our 50+ BGP peers, and updated every 4 hours. This data is available through traditional WHOIS (TCP 43), DNS (UDP 53), HTTP (TCP 80), and HTTPS (TCP 443). For more information on the data available, and how to query, check out our IP to ASN Mapping Project.

The Malware Hash Registry

The Malware Hash Registry provides the ability to perform lookups of MD5 and SHA-1 hashes of files to see if Team Cymru's malware analysis system has classified them as malware, along with information about when the sample was last seen and an approximate anti-virus detection percentage. For more information on the data returned and how to query this system, check out the Malware Hash Registry.

See https://github.com/trolldbois/python-cymru-services/raw/master/README for full documentation.
    """,

    url="http://packages.python.org/cymru-services/",
    download_url="http://github.com/trolldbois/python-cymru-services/tree/master",
    license='MIT',
    classifiers=[
        "Topic :: System :: Networking",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=['ASN','MHR','PEER','IP','BOGON','cymru'],
    author="Loic Jaquemet",
    author_email="loic.jaquemet+python@gmail.com",
    py_modules = ["cymru"], 
    extras_require = {
        'CACHE':  ["python-memcached"],
	'ADNS':  ["python-adns"],
  'IPy':  ["IPy"],
    },
)
