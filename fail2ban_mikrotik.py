#!/usr/bin/python3

import sys
import argparse
from routeros_api import RouterOsApiPool

parser = argparse.ArgumentParser(description="Fail2Ban Mikrotik Script")
parser.add_argument('-m', help='Mikrotik IP', required=True)
parser.add_argument('-s', help='Mikrotik API port', required=True, type=int)
parser.add_argument('-u', help='Mikrotik API User', required=True)
parser.add_argument('-p', help='Mikrotik API Password', required=True)
parser.add_argument('-a', help='Action: ban or unban', required=True)
parser.add_argument('-i', help='IP address', required=True)
parser.add_argument('-l', help='Address List', required=True)
parser.add_argument('-d', help='Dynamic timeout', required=False)
args = parser.parse_args()

try:
    api_pool = RouterOsApiPool(args.m, username=args.u, password=args.p, port=args.s, plaintext_login=True)
    api = api_pool.get_api()
    address_list = api.get_resource('/ip/firewall/address-list')

    existing_entries = address_list.get(address=args.i, list=args.l)

    if args.a == "ban":
        if not existing_entries:
            entry = {'list': args.l, 'address': args.i}
            if args.d:
                entry['timeout'] = args.d
            address_list.add(**entry)
            print(f"IP {args.i} added to list {args.l}")
        else:
            print(f"IP {args.i} in list {args.l} already exists")
            sys.exit(1)

    elif args.a == "unban":
        if existing_entries:
            for entry in existing_entries:
                address_list.remove(id=entry['id'])
            print(f"IP {args.i} removed from list {args.l}")
        else:
            print(f"IP {args.i} in list {args.l} does not exist")
            sys.exit(1)

    api_pool.disconnect()
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
