#!/usr/bin/env python

# helper_malshare - MalShare download helper.

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

from concurrent.futures import ThreadPoolExecutor
from alive_progress import alive_bar
import argparse
import requests
import time
import os


BATCH = 50
THREADS = 5
DELAY = 0.5

COPYRIGHT = """
pymetangine  Copyright (C) 2021 Sergio Chica Manjarrez.
This program comes with ABSOLUTELY NO WARRANTY; for details check below.
This is free software, and you are welcome to redistribute it
under certain conditions; check below for details.
"""


def sample_batch(key, output, samples):
    for i in range(0, len(samples), BATCH):
        yield [(key, output, sample) for sample in samples[i:i + BATCH]]


def download(sample):
    key, output, hashid = sample
    try:
        req = requests.get(
            f"https://malshare.com/api.php?"
            f"api_key={key}&action=getfile&hash={hashid}")
    except (req.exceptions.ConnectionError,
            req.exceptions.ConnectTimeout) as e:
        print("Error ocurred:", hashid, e)
    else:
        with open(
                os.path.join(output, f"{hashid}.bin"), 'wb') as f:
            f.write(req.content)
        time.sleep(DELAY)
        return hashid


def main():
    argparser = argparse.ArgumentParser(
        prog="helper_malshare",
        description='MalShare helper to download samples.')

    argparser.add_argument('-i', '--input',
                           required=True,
                           help=('Input file containing HASH of samples '
                                 'to download. HASH: MD5/SHA1/SHA256.'))

    argparser.add_argument('-o', '--output',
                           default='samples',
                           help='Output directory to save samples.')

    argparser.add_argument('-k', '--key',
                           default='.key_malshare',
                           help='File containing MalShare API key.')

    args = argparser.parse_args()

    print(COPYRIGHT)

    if not os.path.exists(args.output):
        os.makedirs(args.output, exist_ok=True)

    with open(args.key, 'r') as f:
        key = f.read().strip()

    hashes = []
    with open(args.input, 'r') as f:
        hashes = f.read().splitlines()

    sample_generator = sample_batch(key, args.output, hashes)
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        with alive_bar(
                total=len(hashes)//BATCH+1, title="[DWNLD] Samples",
                bar='classic', spinner='classic') as bar:
            for batch in sample_generator:
                results = executor.map(download, batch)
                list(results)  # block until batch downloaded
                bar()


if __name__ == "__main__":
    main()
