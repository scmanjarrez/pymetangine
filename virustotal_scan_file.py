#!/usr/bin/env python
import sys
import os
import json
import time
from virus_total_apis import PublicApi

if len(sys.argv) != 3:
    print("Usage: {} directory urls_file".format(sys.argv[0]))
    sys.exit()

if not os.path.isdir(sys.argv[1]):
    print("Input path is not a valid directory")
    sys.exit()

original = open(sys.argv[2], 'w')

API_KEY = ''
with open('API_KEY2', 'r') as f:
    API_KEY = f.read().strip()

executables = [exe for exe in os.listdir(sys.argv[1]) if os.path.isfile(os.path.join(sys.argv[1], exe))]

vt = PublicApi(API_KEY)
for exe in executables:
    print('Uploading {}'.format(exe))
    vtreport = vt.scan_file(os.path.join(sys.argv[1], exe))
    
    while vtreport['response_code'] != 200:
        print('Reached maximum requests/minute, waiting 30 seconds')
        time.sleep(30)
        vtreport = vt.scan_file(os.path.join(sys.argv[1], exe))
    
    r = vtreport['results']
    if r['response_code'] != 1:
        print('Error rescaning file {}'.format(exe))
        original.write('{:<50s}{}\n'.format(exe, 'An error occurred'))
    else:
        original.write('{:<50s}{}\n'.format(exe, r['permalink']))
    
    original.flush()
    os.fsync(original.fileno())
original.close()
