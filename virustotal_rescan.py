#!/usr/bin/env python
import sys
import os
import json
import time
from virus_total_apis import PublicApi

if len(sys.argv) != 3:
    print("Usage: {} md5_file urls_file".format(sys.argv[0]))
    sys.exit()

if not os.path.isfile(sys.argv[1]):
    print("Input path is not a valid file")
    sys.exit()

original = open(sys.argv[2], 'w')

API_KEY = ''
with open('API_KEY2', 'r') as f:
    API_KEY = f.read().strip()

executables = []

with open(sys.argv[1], 'r') as f:
    executables = [elem.split()[0] for elem in f.read().splitlines()]

executables = [executables[idx:idx+25] for idx in range(0, len(executables), 25)]

vt = PublicApi(API_KEY)
for exe in executables:
    vtreport = vt.rescan_file(','.join(exe))
    while vtreport['response_code'] != 200:
        print('Reached maximum requests/minute, waiting 30 seconds')
        time.sleep(30)
        vtreport = vt.rescan_file(','.join(exe))
    for r in vtreport['results']:
        if r['response_code'] != 1:
            print('Error rescaning file {}'.format(r['resource']))
            original.write('{:<35s}{}\n'.format(r['resource'], 'Not present'))
        else:
            original.write('{:<35s}{}\n'.format(r['resource'], r['permalink']))
    original.flush()
    os.fsync(original.fileno())
original.close()
