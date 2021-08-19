#!/usr/bin/env python

# helper_virustotal - VirusTotal scan/gather results helper.

# Copyright (C) 2021 Sergio Chica Manjarrez.

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

from alive_progress import alive_bar, config_handler
from virus_total_apis import PublicApi
import argparse
import time
import os
import re


COPYRIGHT = """
pymetangine  Copyright (C) 2021 Sergio Chica Manjarrez.
This program comes with ABSOLUTELY NO WARRANTY; for details check below.
This is free software, and you are welcome to redistribute it
under certain conditions; check below for details.
"""


def scan_phase(args, api, logger, samples):
    with alive_bar(
            total=len(samples), title="[SCAN] Samples") as bar:
        for sample in samples:
            analysis = api.scan_file(sample)
            while analysis['response_code'] != 200:
                print("Error: Reached maximum requests/minute. "
                      "Sleeping 60 seconds.")
                time.sleep(60)
                analysis = api.scan_file(sample)
            logger.write(
                f"{os.path.basename(sample):<40s}\t"
                f"{analysis['results']['permalink'].split('f-')[0]}\n"
            )
            bar()


def results_phase(args, api, logger):
    sample_hash = re.compile(r'file/(.*?)/')
    with open(args.input, 'r') as f:
        samples = [(hashes.split('\t')[0], sample_hash.search(hashes).group(1))
                   for hashes in f.read().splitlines()]
    with alive_bar(
            total=len(samples), title="[SCAN] Samples") as bar:
        for name, sample in samples:
            report = api.get_file_report(sample)
            while report['response_code'] != 200:
                print("Error: Reached maximum requests/minute. "
                      "Sleeping 60 seconds.")
                time.sleep(60)
                report = api.get_file_report(sample)
            res = report['results']
            if res['response_code'] != 1:
                print(f"Warning: Report for {sample} not ready yet.")
                log = f"{name:<40s}\t{'-':<5s}/{'-':>5s}\n"
            else:
                log = (f"{name:<40s}\t"
                       f"{res['positives']:<5d}/{res['total']:>5d}\n")
            logger.write(log)
            bar()


def main():
    config_handler.set_global(bar='classic', spinner='classic')
    argparser = argparse.ArgumentParser(
        prog="helper_virustotal",
        description='VirusTotal helper to scan/gather results.')

    argparser.add_argument('-i', '--input',
                           required=True,
                           help=("Folder path to scan or "
                                 "file path with HASH - URL pattern."))
    argparser.add_argument('-o', '--output',
                           default='virustotal',
                           help=("File name for url/detection output."))
    argparser.add_argument('-k', '--key',
                           default='.key_virustotal',
                           help="File containing VirusTotal API key.")

    group = argparser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--scan',
                       action='store_true',
                       help="Scan directory given as input.")
    group.add_argument('-r', '--results',
                       action='store_true',
                       help="Collect results of files given as input.")

    args = argparser.parse_args()

    print(COPYRIGHT)

    with open(args.key, 'r') as f:
        key = f.read().strip()
    api = PublicApi(key)

    if args.scan:
        if not os.path.isdir(args.input):
            print("Error: Invalid input folder path.")
        else:
            samples = [f'{os.path.join(args.input, sample)}'
                       for sample in os.listdir(args.input)]
            with open(f'{args.output}.url', 'w') as f:
                scan_phase(args, api, f, samples)

    if args.results:
        if not os.path.isfile(args.input):
            print("Error: Invalid input file path.")
        else:
            with open(f'{args.output}.detection', 'w') as f:
                results_phase(args, api, f)


if __name__ == '__main__':
    main()
