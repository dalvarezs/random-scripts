#!/usr/bin/env python3

"""
10/09/2017
"""
from argparse import ArgumentParser
import os
import sys
from netaddr import IPNetwork, IPAddress, IPRange


__author__ = 'David Alvarez @dalvarez_s'
__version__ = '0.4'
__doc__ = 'Look IPs up in the Range. ' \
          'UseCase: Useful for identifying IPs not included in the scope of the Vulnerability scan' \
          'If network ranges are not found, it iterates the network range to search the IPs from the network range'

#ToDo: clean empty lines
# debug mode printing subnet and net info

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

in_range = []
out_range = []

# Converts a string to IPAddress, IPNetwork or IPRange
def strToNetObject(value):
    if isinstance(value, basestring):
        cvalue = value.replace(" ","").replace('\t',"").replace('"','').replace('\n','')
        if "-" in cvalue:
            ip_min_max = cvalue.split("-")
            return IPRange(ip_min_max[0],ip_min_max[1])

        elif "/" in cvalue:
            return IPNetwork(cvalue)

        else: #it is an IPAddress
            return IPAddress(cvalue)
    else:
        return value

def subnetInOutNet(line,ip_range_list,in_range,out_range):
    ip_found = False
    subnet = False #init var
    for net_range in ip_range_list:
        #print ("[NET]"+net_range)

        net = strToNetObject(net_range)
        subnet = strToNetObject(line)
        if type(net) is not IPAddress:
            if subnet in net:
                in_range.append(line)
                ip_found = True
                #print "[SUBNET] "+str(subnet)+" in [NET] "+str(net)
                break
        else:
            if subnet == net:
                in_range.append(line)
                ip_found = True
                #print "[IP_SUBNET] "+str(subnet)+" == [IP_NET] "+str(net)
                break

    if ip_found == False:
        if not isinstance(subnet,IPAddress):
            #print str(subnet)+ "SUBNET NOT IPADDRESS"+str(type(subnet))
            for subip in subnet:
                subnetInOutNet(subip,ip_range_list,in_range,out_range)
        else:
            out_range.append(line)

with open(filename2) as f:
    ip_range_list = f.readlines()

with open(filename, 'r') as f:
    for line in f:
        subnetInOutNet(line,ip_range_list,in_range,out_range)

if args.list == 'in':
    for i in in_range: print i
else:
    for i in out_range: print i
