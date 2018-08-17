#!/usr/bin/env python
import sys
import os
import json
import time
import matplotlib.pyplot as plt
import numpy as np

if len(sys.argv) != 5:
    print("Usage: {} orig_detec rnd_y_detect rnd_n_detect results".format(sys.argv[0]))
    sys.exit()

if not os.path.isfile(sys.argv[1]):
    print("File {} is not a valid file".format(sys.argv[1]))
    sys.exit()

if not os.path.isfile(sys.argv[2]):
    print("File {} is not a valid file".format(sys.argv[2]))
    sys.exit()

if not os.path.isfile(sys.argv[3]):
    print("File {} is not a valid file".format(sys.argv[3]))
    sys.exit()

orig = {}
with open(sys.argv[1], 'r') as f:
    for line in f.read().splitlines():
        elem = line.split()
        aux = elem[1].split('/')
        percent = round(float(aux[0])/float(aux[1])*100, 2)
        orig[elem[0]] = percent

rndy = {}
with open(sys.argv[2], 'r') as f:
    for line in f.read().splitlines():
        elem = line.split()
        aux = elem[1].split('/')
        percent = round(float(aux[0])/float(aux[1])*100, 2)
        rndy[elem[0].replace('_ry.bin', '.bin')] = percent

rndn = {}
with open(sys.argv[3], 'r') as f:
    for line in f.read().splitlines():
        elem = line.split()
        aux = elem[1].split('/')
        percent = round(float(aux[0])/float(aux[1])*100, 2)
        rndn[elem[0].replace('_rn.bin', '.bin')] = percent

results = open(sys.argv[4], 'w')

results.write('{:50s}{:10s}{:10s}{:10s}\n'.format('Sample_MD5', 'Original', 'Random_Y', 'Random_N'))
to_plot = []
for elem in orig:
    results.write('{:50s}{:5.2f}{:10.2f}{:10.2f}\n'.format(elem, orig[elem], rndy[elem], rndn[elem]))
    to_plot.append((orig[elem], rndy[elem], rndn[elem]))
results.close()

to_plot = sorted(to_plot, key=lambda x: x[0])
plot = np.array(to_plot)
plt_sz = len(to_plot)

plt.plot(range(plt_sz), plot[:, 0], 'k', label='Original', linewidth=1)
plt.plot(range(plt_sz), plot[:, 1], 'r', label='Random_Y', linewidth=0.5)
plt.plot(range(plt_sz), plot[:, 2], 'lime', label='Random_N', linewidth=1.2, alpha=0.6)
#plt.plot(range(plt_sz), np.mean(plot[:, 0]) * np.ones(plt_sz), 'dimgray', label='Org_mean', linewidth=1)
#plt.plot(range(plt_sz), np.mean(plot[:, 1]) * np.ones(plt_sz), 'tomato', label='Rnd_y_mean', linewidth=1)
#plt.plot(range(plt_sz), np.mean(plot[:, 2]) * np.ones(plt_sz), 'darkgreen', label='Rnd_n_mean', linewidth=1)

plt.legend()
plt.show()
