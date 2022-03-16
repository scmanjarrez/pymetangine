#!/usr/bin/env python

# SPDX-License-Identifier: GPL-3.0-or-later

# helper_plotter - Plotter helper.

# Copyright (C) 2022 Sergio Chica Manjarrez.

# This file is part of pymetangine.

# pymetangine is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# pymetangine is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with GNU Emacs.  If not, see <https://www.gnu.org/licenses/>.

import matplotlib.pyplot as plt
import argparse
import numpy as np
import sys
import os
import re


def normalize_name(name):
    return name.replace('_ry.bin', '.bin').replace('_rn.bin', '.bin')


def parse_file(filename):
    ret = {}
    with open(filename, 'r') as f:
        for line in f.read().splitlines():
            name, pos, _, tot = line.split()
            percent = round(float(pos) / float(tot) * 100, 2)
            ret[normalize_name(name)] = percent
    return ret


def plot(axis, datax, datay,
         color=None, label=None, linewidth=None,
         alpha=None, marker=None, linestyle=None):
    axis.plot(datax, datay,
              color=color, marker=marker, label=label,
              linewidth=linewidth, alpha=alpha, linestyle=linestyle)


def main(args):
    if not os.path.isfile(args.detog):
        print(f"Invalid {args.detog} file.")
        sys.exit(1)

    if not os.path.isfile(args.detry):
        print(f"Invalid {args.detry} file.")
        sys.exit(1)

    if not os.path.isfile(args.detrn):
        print(f"Invalid {args.detrn} file.")
        sys.exit(1)

    if not os.path.isfile(args.mutry):
        print(f"Invalid {args.mutry} file.")
        sys.exit(1)

    if os.path.exists(args.output) and not os.path.isfile(args.output):
        print(f"Invalid {args.output} file.")
        sys.exit(1)

    og = parse_file(args.detog)
    ry = parse_file(args.detry)
    rn = parse_file(args.detrn)

    regex = re.compile(r'(\w+\.bin)\s*(\d+)\s*/\s*(\d+)')
    mry = {}
    with open(args.mutry, 'r') as f:
        for line in f.read().splitlines():
            name, pos, tot = regex.match(line).groups()
            mry[normalize_name(name)] = (int(pos), int(tot))

    with open(args.output, 'w') as f:
        f.write(
            f"{'Sample_Hash':<50s}{'DetRate_OG':<15s}{'DetRate_RY':<15s}"
            f"{'DetRate_RN':<15s}{'Mut_RY':<15s}{'Mut_RN':<15s}"
            f"\n\n"
        )

        to_plot = []
        ry_gt_og = []
        ry_lt_og = []
        rn_gt_og = []
        rn_lt_og = []

        for idx, sample in enumerate(sorted(og, key=og.get)):
            mut, mut_tot = mry[sample]
            f.write(
                f"{sample:<50s}{og[sample]:<15.2f}{ry[sample]:<15.2f}"
                f"{rn[sample]:<15.2f}{mut:<15d}{mut_tot:<15d}"
                f"\n"
            )
            to_plot.append((og[sample], ry[sample], rn[sample], mut, mut_tot))
            if ry[sample] > og[sample]:
                ry_gt_og.append(str(idx + 1))
            elif og[sample] - ry[sample] <= 2.0:
                ry_lt_og.append(str(idx + 1))
            if rn[sample] > og[sample]:
                rn_gt_og.append(str(idx + 1))
            elif og[sample] - rn[sample] <= 2.0:
                rn_lt_og.append(str(idx + 1))

        plot0 = np.array(sorted(to_plot, key=lambda x: x[0]))
        plot1 = np.array(sorted(to_plot, key=lambda x: x[1]))
        plot2 = np.array(sorted(to_plot, key=lambda x: x[2]))

        og_mean = np.mean(plot0[:, 0])
        ry_mean = np.mean(plot1[:, 1])
        rn_mean = np.mean(plot2[:, 2])

        f.write(
            f"\n"
            f"{'Means':<50s}{og_mean:<15.2f}{ry_mean:<15.2f}{rn_mean:<15.2f}"
            f"\n"
        )

        f.write(
            f"\n"
            f"{'Det. RY -gt OG':<50s}{', '.join(ry_gt_og):<50s}"
            f"\n"
            )
        f.write(
            f"{'Det. RY -lt OG':<50s}{', '.join(ry_lt_og):<50s}"
            f"\n"
            )

        f.write(
            f"\n"
            f"{'Det. RN -gt OG':<50s}{', '.join(rn_gt_og):<50s}"
            f"\n"
        )
        f.write(
            f"{'Det. RN -lt OG':<50s}{', '.join(rn_lt_og):<50s}"
            f"\n"
        )

        if args.print:
            print(f"Mean OG: {og_mean:.2f}")
            print(f"Mean ry: {ry_mean:.2f}")
            print(f"Mean rn: {rn_mean:.2f}")

            print(f"Det RY -gt OG: {', '.join(ry_gt_og)}")
            print(f"Det RY -lt OG: {', '.join(ry_lt_og)}")

            print(f"Det RN -gt OG: {', '.join(rn_gt_og)}")
            print(f"Det RN -lt OG: {', '.join(rn_lt_og)}")

        if not args.nographic:
            plt_sz = len(to_plot)
            rng = range(1, plt_sz + 1)

            # Detection rate, sorted from lower to higher
            fig1, ax1 = plt.subplots()
            fig1.suptitle("Detection rate (sorted from lower to higher)")

            plot(ax1, plot0[:, 0], rng, 'k', "OG", 1)
            plot(ax1, plot1[:, 1], rng, 'r', "RY", 0.5)
            plot(ax1, plot2[:, 2], rng, 'lime', "RN", 1.2)

            plot(ax1, og_mean * np.ones(plt_sz), rng,
                 'dimgray', f"Mean (OG): {og_mean:.2f}", 1)
            plot(ax1, ry_mean * np.ones(plt_sz), rng,
                 'tomato', f"Mean (RY): {ry_mean:.2f}", 1)
            plot(ax1, rn_mean * np.ones(plt_sz), rng,
                 'darkgreen', f"Mean (RN): {rn_mean:.2f}", 1)

            ax1.legend()
            ax1.axis([0, 100, 0, plt_sz + plt_sz * 0.01])
            ax1.set_yticks(range(0, round(plt_sz + plt_sz * 0.01), 100))
            ax1.set_xlabel(u"Detection rate (%)")
            ax1.set_ylabel(u"Nº Sample")

            # Detection rate, comparison between original and mutated samples
            fig2, ax2 = plt.subplots()
            fig2.suptitle("Detection rate (comparison between original and "
                          "mutated samples)")

            plot(ax2, rng, plot0[:, 0], 'k', "OG", 1)
            plot(ax2, rng, plot0[:, 1], 'r', "RY", 0.5)
            plot(ax2, rng, plot0[:, 2], 'lime', "RN", 1.2, 0.6)

            plot(ax2, rng, og_mean * np.ones(plt_sz),
                 'dimgray', f"Mean (OG): {og_mean:.2f}", 1)
            plot(ax2, rng, ry_mean * np.ones(plt_sz),
                 'tomato', f"Mean (RY): {ry_mean:.2f}", 1)
            plot(ax2, rng, rn_mean * np.ones(plt_sz),
                 'darkgreen', f"Mean (RN): {rn_mean:.2f}", 1)

            # Mutations with detection rate greater or
            # marginally lower than original
            plot(ax2, list(map(int, ry_gt_og)),
                 plot0[list(map(lambda x: x-1, map(int, ry_gt_og))), 1],
                 'r', "Det. RY -gt OG", marker=7, linestyle='None')
            plot(ax2, list(map(int, ry_lt_og)),
                 plot0[list(map(lambda x: x-1, map(int, ry_lt_og))), 1],
                 'salmon', "Det. RY -lt OG", marker=6, linestyle='None')
            plot(ax2, list(map(int, rn_gt_og)),
                 plot0[list(map(lambda x: x-1, map(int, rn_gt_og))), 2],
                 'darkgreen', "Det. RN -gt OG", marker=7, linestyle='None')
            plot(ax2, list(map(int, rn_lt_og)),
                 plot0[list(map(lambda x: x-1, map(int, rn_lt_og))), 2],
                 'olive', "Det. RN -lt OG", marker=6, linestyle='None')

            ax2.legend()
            ax2.axis([0, plt_sz + plt_sz * 0.01, 0, 100])
            ax2.set_xticks(range(0, round(plt_sz + plt_sz * 0.01), 100))
            ax2.set_xlabel(u"Nº Sample")
            ax2.set_ylabel(u"Detection rate (%)")

            plt.show()


if __name__ == '__main__':
    argparser = argparse.ArgumentParser(
        prog="helper_plotter", description="Helper to plot results.")
    argparser.add_argument('-dg', '--detog',
                           required=True,
                           help="Original sample detections.")
    argparser.add_argument('-dy', '--detry',
                           required=True,
                           help="RandomYes sample detections.")
    argparser.add_argument('-dn', '--detrn',
                           required=True,
                           help="RandomNo sample detections.")
    argparser.add_argument('-my', '--mutry',
                           required=True,
                           help="RandomYes sample mutations.")
    argparser.add_argument('-o', '--output',
                           default='plot.result',
                           help="Results output file.")
    argparser.add_argument('-p', '--print',
                           action='store_true',
                           help="Print values on stdout.")
    argparser.add_argument('-ng', '--nographic',
                           action='store_true',
                           help="Disable plot.")

    args = argparser.parse_args()

    main(args)
