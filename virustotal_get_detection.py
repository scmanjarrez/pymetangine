#!/usr/bin/env python
import sys
import os
import json
import time
from virus_total_apis import PublicApi

if len(sys.argv) != 3:
    print("Usage: {} md5_file detections_file".format(sys.argv[0]))
    sys.exit()

if not os.path.isfile(sys.argv[1]):
    print("Input file is not a valid file")
    sys.exit()

original = open(sys.argv[2], 'w')

API_KEY = ''
with open('API_KEY2', 'r') as f:
    API_KEY = f.read().strip()

executables = []

with open(sys.argv[1], 'r') as f:
    executables = [tuple(line.split()) for line in f.read().splitlines()]

vt = PublicApi(API_KEY)
for exe in executables:
    print('Gathering report for {}'.format(exe[1]))
    vtreport = vt.get_file_report(exe[0])
    
    while vtreport['response_code'] != 200:
        print('Reached maximum requests/minute, waiting 30 seconds')
        time.sleep(30)
        vtreport = vt.get_file_report(exe[0])
    
    r = vtreport['results']
    if r['response_code'] != 1:
        print('Error gathering report for file {}'.format(exe[1]))
        original.write('{:<50s}{}/{}\n'.format(exe[1], '-', '-'))
    else:
        original.write('{:<50s}{}/{}\n'.format(exe[1], r['positives'], r['total']))
    original.flush()
    os.fsync(original.fileno())
original.close()
