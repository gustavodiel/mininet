#!/usr/bin/env python
# encoding=UTF-8

from netifaces import interfaces, ifaddresses, AF_INET
import sys


ips = []

for ifaceName in interfaces():
    addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'nope'}] )]
    if (addresses[0] != 'nope' and addresses[0] != '127.0.0.1'):
        ips.extend(addresses)

sys.stdout.write(', '.join(ips))
