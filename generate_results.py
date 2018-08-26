#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import json
import time
import matplotlib.pyplot as plt
import numpy as np
import re

if len(sys.argv) != 6:
    print("Usage: {} det_org det_rdy det_rdn sub_rdy results".format(sys.argv[0]))
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

if not os.path.isfile(sys.argv[4]):
    print("File {} is not a valid file".format(sys.argv[4]))
    sys.exit()

org = {}
with open(sys.argv[1], 'r') as f:
    for line in f.read().splitlines():
        elem = line.split()
        aux = elem[1].split('/')
        percent = round(float(aux[0])/float(aux[1])*100, 2)
        org[elem[0]] = percent

rdy = {}
with open(sys.argv[2], 'r') as f:
    for line in f.read().splitlines():
        elem = line.split()
        aux = elem[1].split('/')
        percent = round(float(aux[0])/float(aux[1])*100, 2)
        rdy[elem[0].replace('_ry.bin', '.bin')] = percent

sub_rdy = {}
pattern = re.compile('(\w+\.bin)\s*(\d+)\s*/\s*(\d+)')
with open(sys.argv[4], 'r') as f:
    for line in f.read().splitlines():
        elem, sub_done, tot_sub = pattern.match(line).groups()
        sub_rdy[elem] = (int(sub_done), int(tot_sub))

rdn = {}
with open(sys.argv[3], 'r') as f:
    for line in f.read().splitlines():
        elem = line.split()
        aux = elem[1].split('/')
        percent = round(float(aux[0])/float(aux[1])*100, 2)
        rdn[elem[0].replace('_rn.bin', '.bin')] = percent

results = open(sys.argv[5], 'w')

results.write('{:50s}{:10s}{:10s}{:10s}{:15s}{:15s}\n\n'.format('Sample_MD5', 'Original', 'Random_Y', 'Random_N', 'Sust_Rnd_Y', 'Sust_Rnd_N'))

to_plot = []
sup_rdy_org = []
inf_rdy_org = []
sup_rdn_org = []
inf_rdn_org = []

for idx, elem in enumerate(sorted(org, key=org.get)):
    n_sub, t_sub = sub_rdy[elem]
    results.write('{:50s}{:5.2f}{:10.2f}{:10.2f}{:15.0f}{:15.0f}\n'.format(elem, org[elem], rdy[elem], rdn[elem], n_sub, t_sub))
    to_plot.append((org[elem], rdy[elem], rdn[elem], n_sub, t_sub))
    if rdy[elem] > org[elem]:
        sup_rdy_org.append(str(idx+1))
    elif org[elem] - rdy[elem] <= 2.0:
        inf_rdy_org.append(str(idx+1))
    if rdn[elem] > org[elem]:
        sup_rdn_org.append(str(idx+1))
    elif org[elem] - rdn[elem] <= 2.0:
        inf_rdn_org.append(str(idx+1))

to_plot = sorted(to_plot, key=lambda x: x[0])
to_plot2 = sorted(to_plot, key=lambda x: x[1])
to_plot3 = sorted(to_plot, key=lambda x: x[2])

plot = np.array(to_plot)
#aux = np.amax(plot[:, 3])
#aux1 = np.amin(plot[:, 3])
#plot[:, 3] = plot[:, 3] / abs(aux) * 10.
plot2 = np.array(to_plot2)
plot3 = np.array(to_plot3) 

plt_sz = len(to_plot)
org_mean = np.mean(plot[:, 0])
rdy_mean = np.mean(plot[:, 1])
rdn_mean = np.mean(plot[:, 2]) 

results.write('\n{:50s}{:5.2f}{:10.2f}{:10.2f}\n'.format("Medias", org_mean, rdy_mean, rdn_mean))

results.write('\n{:50s}{:50s}\n'.format("Sim. Sup. rdy_org", ", ".join(sup_rdy_org)))
results.write('{:50s}{:50s}\n'.format("Sim. Inf(2). rdy_org", ", ".join(inf_rdy_org)))
results.write('\n{:50s}{:50s}\n'.format("Sim. Sup. rdn_org", ", ".join(sup_rdn_org)))
results.write('{:50s}{:50s}\n'.format("Sim. Inf(2). rdn_org", ", ".join(inf_rdn_org)))

results.close()

print("Media org: {}\nMedia rdy: {}\nMedia rdn: {}".format(org_mean, rdy_mean, rdn_mean))

print("[rdy] Sim. Sup. rdy_org: {}".format(", ".join(sup_rdy_org)))
print("[rdy] Sim. Inf(2). rdy_org: {}".format(", ".join(inf_rdy_org)))
print("[rdn] Sim. Sup. rdn_org: {}".format(", ".join(sup_rdn_org)))
print("[rdn] Sim. Inf(2). rdn_org: {}".format(", ".join(inf_rdn_org)))

rang = range(1, plt_sz + 1)

plt1 = plt.figure(1)
ax1 = plt1.add_subplot(1,1,1)
# Muestras ordenadas de menor a mayor
ax1.plot(plot[:, 0], rang, 'k', label='Original', linewidth=1)
ax1.plot(plot2[:, 1], rang, 'r', label='Random_Y', linewidth=0.5)
ax1.plot(plot3[:, 2], rang, 'lime', label='Random_N', linewidth=1.2, alpha=0.6)
# Medias de planteamientos
ax1.plot(np.mean(plot[:, 0]) * np.ones(plt_sz), rang, 'dimgray', label='Org_mean', linewidth=1)
ax1.plot(np.mean(plot2[:, 1]) * np.ones(plt_sz), rang, 'tomato', label='Rnd_y_mean', linewidth=1)
ax1.plot(np.mean(plot3[:, 2]) * np.ones(plt_sz), rang, 'darkgreen', label='Rnd_n_mean', linewidth=1)
# Modificar etiqueta de ejes y su escala
ax1.set_xlabel(u"Índice de detección (%)")
ax1.set_yticks(range(0, plt_sz + 10, 100))
ax1.axis([0, 100, 0, 1510])

plt2 = plt.figure(2)
ax2 = plt2.add_subplot(1,1,1)
# Muestras vs índice detección
ax2.plot(rang, plot[:, 0], 'k', label='Original', linewidth=1)
ax2.plot(rang, plot[:, 1], 'r', label='Random_Y', linewidth=0.5)
ax2.plot(rang, plot[:, 2], 'lime', label='Random_N', linewidth=1.2, alpha=0.6)
# Medias de planteamientos
ax2.plot(rang, org_mean * np.ones(plt_sz), 'dimgray', label='Org_mean', linewidth=1)
ax2.plot(rang, rdy_mean * np.ones(plt_sz), 'tomato', label='Rnd_y_mean', linewidth=1)
ax2.plot(rang, rdn_mean * np.ones(plt_sz), 'darkgreen', label='Rnd_n_mean', linewidth=1)
# Muestras con similud mayor o inferior a la original
ax2.plot(list(map(int, sup_rdy_org)), plot[list(map(lambda x: x-1, map(int, sup_rdy_org))), 1], 'red', marker=7, label='Sup. Rdy. Org', linestyle='None')
ax2.plot(list(map(int, inf_rdy_org)), plot[list(map(lambda x: x-1, map(int, inf_rdy_org))), 1], 'salmon', marker=6, label='Inf. Rdy. Org', linestyle='None')
ax2.plot(list(map(int, sup_rdn_org)), plot[list(map(lambda x: x-1, map(int, sup_rdn_org))), 2], 'darkgreen', marker=7, label='Sup. Rdn. Org', linestyle='None')
ax2.plot(list(map(int, inf_rdn_org)), plot[list(map(lambda x: x-1, map(int, inf_rdn_org))), 2], 'olive', marker=6, label='Inf. Rdn. Org', linestyle='None')
# Modificar etiqueta de ejes y su escala
ax2.set_xlabel(u"Muestras")
ax2.set_ylabel(u"Índice de detección (%)")
ax2.set_xticks(range(0, plt_sz + 10, 100))
ax2.axis([0, 1510, 0, 100])

#plt3 = plt.figure(3)
#ax3 = plt3.add_subplot(1,1,1)
#yaxis2 = ax3.twinx()
# Muestras vs índice detección
#ax3.plot(rang, plot[:, 0], 'k', label='Original', linewidth=1)
#ax3.plot(rang, plot[:, 1], 'r', label='Random_Y', linewidth=0.5)
#ax3.plot(rang, plot[:, 2], 'lime', label='Random_N', linewidth=1.2, alpha=0.6)
# Nuevo eje Y
#yaxis2.set_ylabel("Sustituciones")
#yaxis2.plot(rang, plot[:, 3], 'magenta', marker='.', label='Sust. Hechas.', linestyle='None')
#yaxis2.plot(rang, plot[:, 4], 'blue', marker='.', label='Sust. Tot.', linestyle='None')
#yaxis2.set_ylim(0, 4)
#yaxis2.set_yticks(range(0, 25, 1))

plt.legend()
plt.show()

