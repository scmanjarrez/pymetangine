#!/usr/bin/env python

# pymetangine - main program.

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

import metaengine
import argparse
import r2pipe
import shutil
import sys
import os


_RED = '\033[91m'
_GREEN = '\033[92m'
_YELLOW = '\033[93m'
_BLUE = '\033[94m'
_CLEANC = '\033[0m'
_NC = ''


def log(log_type, msg):
    lt = {'info': f'{_GREEN}[+] {_CLEANC}',
          'debug': f'{_BLUE}[*] {_CLEANC}',
          'debugw': f'{_YELLOW}[-] {_CLEANC}',
          'error': f'{_RED}[!] {_CLEANC}'}
    print(f"{lt[log_type]}{msg}")


def mutate_function(args, meta, func):
    n_ins = len(func['ops'])
    ins_idx = 0
    list_mutations = []
    while ins_idx < n_ins:
        ins_analyzed = func['ops'][ins_idx]

        if ins_analyzed['type'] not in meta.mutable_ins:
            ins_idx += 1
            continue

        while True:
            mut = meta.gen_mutations(func['ops'], ins_idx)
            if mut is not None:
                mutation, size = mut
                if args.random == 'n' and not mutation:
                    continue

                if ins_analyzed['size'] == size:
                    if args.debug:
                        mt = mutation if mutation else ins_analyzed['opcode']
                        log('debug' if mutation else 'debugw',
                            f"Mutating instruction "
                            f"({ins_analyzed['offset']:#x}): "
                            f"{ins_analyzed['opcode']:20s} -->    {mt:30s}")
                    if mutation:
                        list_mutations.append(
                            {'offset': ins_analyzed['offset'],
                             'bytes': meta.gen_bytes(mutation)})
                else:
                    ins_to_skip = size-ins_analyzed['size']
                    if ins_analyzed['type'] == 'upush':
                        orig_ins = (f"{func['ops'][ins_idx]['opcode']}; "
                                    f"{func['ops'][ins_idx + 1]['opcode']}")
                    else:
                        orig_ins = f"nop{'; nop'*ins_to_skip}"

                    same_ins = mutation == '' or mutation == orig_ins
                    if args.random == 'n' and same_ins:
                        continue

                    ins_idx += ins_to_skip

                    if args.debug:
                        mt = mutation if not same_ins else orig_ins
                        log('debug' if not same_ins else 'debugw',
                            f"Mutating instruction "
                            f"({ins_analyzed['offset']:#x}): "
                            f"{orig_ins:20s} -->    {mt:30s}")
                    if not same_ins:
                        list_mutations.append(
                            {'offset': ins_analyzed['offset'],
                             'bytes': meta.gen_bytes(mutation)})
                meta.ins_inc()
            break
        ins_idx += 1
    return list_mutations


def patch_executable(args, r2, meta, mutations, logger=None):
    log('info', f"Writing mutations to {args.output}")
    for idx, mutation in enumerate(mutations):
        r2.cmd(f"wx {mutation['bytes']} @{mutation['offset']}")

    log('info',
        f"Mutations: {len(mutations)}/{meta.ins}")

    if args.batch:
        logger.write(f"{len(mutations):<5d}/{meta.ins:>5d}\n")


def main(args, r2, meta, logger=None):
    if args.debug:
        log('debug', "Loading functions information.")
    functions = r2.cmdj('aflj')

    if functions is not None:
        if args.debug:
            log('debug', "Disassembling functions.")
        mutations = []
        for fun in functions:
            if fun['type'] == 'fcn':
                try:
                    fun_code = r2.cmdj(f"pdfj @{fun['name']}")
                except:  # noqa
                    log('error',
                        f"Function {fun['name']} could not be disassembled")
                else:
                    mutation = mutate_function(args, meta, fun_code)
                    if mutation is not None and mutation:
                        mutations.append(mutation)

        log('info', "Starting patching routine.")
        mutations = [offsbytes for sub_list in mutations
                     for offsbytes in sub_list]
        patch_executable(args, r2, meta, mutations, logger)

        if not args.batch:
            log('info', "Exiting...\n")
    else:
        log('error', "Could not load any function.")
        if args.batch:
            logger.write("Error: Could not load any function.\n")
    r2.quit()


def configure_environment(args, logger=None):
    shutil.copyfile(args.input, args.output)

    log('info', f"Opening {args.input} in radare2.")
    r2 = r2pipe.open(args.output, ['-w'])

    if args.debug:
        log('debug', "Analyzing architecture of the executable.")

    exe_info = r2.cmdj('ij')
    if 'bin' in exe_info:
        if exe_info['bin']['arch'] == 'x86':
            bits = exe_info['bin']['bits']
            if args.debug:
                log('debug', f"Detected {bits} bits architecture.")
        else:
            log('error', "Architecture not supported.")
            if args.batch:
                logger.write('Error: Architecture not supported.\n')
            return None
    else:
        log('error', "File format not supported.")
        if args.batch:
            logger.write("Error: File format not supported.\n")
        return None

    log('info', "Analyzing executable.")
    r2.cmd('aaa')

    meta = metaengine.MetaEngine(bits)

    return r2, meta


def check_batch_dir(in_dir, out_dir):
    if not os.path.isdir(in_dir):
        log('error', "Invalid input folder path.")
        sys.exit(1)

    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        log('error', "Invalid output folder path.")
        sys.exit(1)

    if not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
        if args.debug:
            log('debug', f"Creating directory {out_dir}.")


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog="pymetangine",
        description="A python metamorphic engine for PE/PE+ using radare2.")

    parser.add_argument('-b', '--batch',
                        nargs='?', const='batch.log', default='',
                        help=("Enable batch execution, "
                              "receiving a directory as input/output."))

    parser.add_argument('-i', '--input',
                        required=True,
                        help="Path to input executable/directory.")

    parser.add_argument('-o', '--output',
                        default=['mutations/mutated.bin', 'mutations'],
                        help=("Path to output executable/directory. "
                              "Default: mutations/mutated.bin, mutations "
                              "for file/directory."))

    parser.add_argument('-d', '--debug',
                        action='store_true',
                        help="Enable debug messages during execution.")

    parser.add_argument('-r', '--random',
                        choices=['y', 'n'], default='y',
                        help=("Change mode of replacements, "
                              "random/all substitutions."))

    parser.add_argument('--no-color',
                        action='store_true',
                        help="Disable ANSI color output.")

    args = parser.parse_args()

    if args.no_color:
        global _GREEN, _BLUE, _YELLOW, _RED, _CLEANC
        _GREEN = _BLUE = _YELLOW = _RED = _CLEANC = _NC

    # Set args.output default value.
    if isinstance(args.output, list):
        if not args.batch:
            args.output = args.output[0]  # mutations/mutated.bin
        else:
            args.output = args.output[1]  # mutations

    if args.debug:
        log('debug', "Parsing arguments.")

    return args


# nop insertion, dead code insertion, instruction subs, register subs
if __name__ == '__main__':
    args = parse_arguments()

    if args.batch:
        check_batch_dir(args.input, os.path.join(args.input, args.output))
        in_dir = args.input
        out_dir = args.output

        samples = [sample for sample in os.listdir(in_dir)
                   if os.path.isfile(os.path.join(in_dir, sample))]

        with open(args.batch, 'w') as f:
            for idx, sample in enumerate(samples):
                args.input = os.path.join(in_dir, sample)
                postfix = '_ry.bin'
                if args.random == 'n':
                    postfix = '_rn.bin'
                args.output = os.path.join(
                    in_dir, out_dir, sample).replace('.bin', postfix)

                f.write(f"{sample:40s}")

                log('info', f"File {idx+1}/{len(samples)}.")
                r2, meta = configure_environment(args, f)
                if r2 is not None:
                    main(args, r2, meta, f)
                print()
    else:
        args.output = os.path.join(os.path.dirname(args.input), args.output)
        r2, meta = configure_environment(args)
        if r2 is not None:
            main(args, r2, meta)
