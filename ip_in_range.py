#!/usr/bin/env python3

"""
10/09/2017
"""
from argparse import ArgumentParser
import os
import sys
from netaddr import IPNetwork, IPAddress


__author__ = 'David Alvarez @dalvarez_s'
__version__ = '0.2'
__doc__ = 'Look IPs up in the Range. ' \
          'UseCase: Useful for identifying IPs not included in the scope of the Vulnerability scan'

def rangeCIDR_to_list(range):
    if "-" in range:
        return range.strip().split("-")
    # pending CIDR

parser = ArgumentParser(
    usage='%(prog)s ip_list range_list',
    description=__doc__,
    prog=os.path.basename(sys.argv[0])
)

parser.add_argument('-l', '--list', choices=['in','out'], help='show IPs [in/out] of the range', required=True)
parser.add_argument('ip_file', help='IPs to be searched')
parser.add_argument('range_file', help='look IPs up in the Range. Accepted formats: 192.168.1.0-192.168.1.255 / 192.168.1.0/24')
parser.add_argument('--version', action='version', version=__version__)


args = parser.parse_args()
filename = args.ip_file
filename2 = args.range_file

with open(filename2) as f:
    ip_range_list = f.readlines()

in_range = []
out_range = []

with open(filename, 'r') as f:
    for line in f:
        ip = line.strip()
        # print (ip)

        ip_found = False
        for net_range in ip_range_list:
            # print (net_range)
            if "-" in net_range:
                ip_min_max = net_range.strip().split("-") #### function

                if (IPAddress(ip_min_max[1]) >= IPAddress(ip)) and (IPAddress(ip_min_max[0]) <= IPAddress(ip)):
                    #if args.list == 'in': print (str(ip)+" IP in the range "+str(ip_min_max))
                    in_range.append(ip)
                    ip_found = True
                    break
            elif "/" in net_range:
                if IPAddress(ip) in IPNetwork(net_range):
                    in_range.append(ip)
                    ip_found = True
                    break

        if ip_found == False:
            out_range.append(ip)

if args.list == 'in':
    for i in in_range: print i
else:
    for i in out_range: print i
