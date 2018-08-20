import sys
import r2pipe
import argparse
import shutil
import MetaEngine as me
import keystone as ks
from termcolor import colored
from os import listdir, mkdir
from os.path import isfile, isdir, join, exists

KS = None
META = None
total_ins = 0
batch_log = None


def generate_bytes(code):
    asm, _ = KS.asm(code)
    return "".join(["{:02x}".format(ins) for ins in asm])


def mutate_function(args, func):
    global total_ins
    n_ins = len(func["ops"])
    ins_idx = 0
    mutations = []
    while ins_idx < n_ins:
        ins_analyzed = func["ops"][ins_idx]

        if ins_analyzed["type"] not in META.mutable_ins:
            ins_idx += 1
            continue

        while True:
            meta = META.generate_mutations(func["ops"], ins_idx)
            if meta is not None:
                mutation, size = meta
                if args.random == 'n' and not mutation:
                    continue

                if ins_analyzed["size"] == size:
                    if args.debug:
                        print colored("[DEBUG] Mutating instruction ({:#x}): {:20s} -->    {:30s}"
                              .format(ins_analyzed["offset"], ins_analyzed["opcode"],
                                      mutation if mutation else ins_analyzed["opcode"]), "green" if mutation else "magenta")
                    if mutation:
                        mutations.append({"offset": ins_analyzed["offset"], "bytes": generate_bytes(mutation)})
                else:
                    ins_to_skip = size-ins_analyzed["size"]
                    if ins_analyzed["type"] == "upush":
                        orig_ins = "{}; {}".format(func["ops"][ins_idx]["opcode"], func["ops"][ins_idx + 1]["opcode"])
                    else:
                        orig_ins = "nop" + "; nop" * ins_to_skip

                    same_ins = mutation == "" or mutation == orig_ins
                    if args.random == 'n' and same_ins:
                        continue

                    ins_idx += ins_to_skip

                    if args.debug:
                        print colored("[DEBUG] Mutating instruction ({:#x}): {:20s} -->    {:30s}"
                              .format(ins_analyzed["offset"], orig_ins,
                                      mutation if not same_ins else orig_ins), "green" if not same_ins else "magenta")
                    if not same_ins:
                        mutations.append({"offset": ins_analyzed["offset"], "bytes": generate_bytes(mutation)})

                total_ins += 1
            break
        ins_idx += 1
    return mutations


def patch_executable(args, r2, list_mutations):
    print colored("[INFO] Writing mutations to {}".format(args.output), "cyan")
    for idx, mutation in enumerate(list_mutations):
        r2.cmd("wx {} @{}".format(mutation["bytes"], mutation["offset"]))

    print colored("[INFO] Total number of mutations: {}/{}"
          .format(len(list_mutations), total_ins), "cyan")

    if args.batch:
        batch_log.write('{:<5d}/{:>5d}\n'.format(len(list_mutations), total_ins))


def main(args, r2):
    print colored("[INFO] Loading functions information.", "cyan")
    functions = r2.cmdj("aflj")

    if functions is not None:
        print colored("[INFO] Disassembling functions.", "cyan")
        mutations = []
        for fun in functions:
            if fun["type"] == "fcn":
                try:
                    fun_code = r2.cmdj("pdfj @{}".format(fun["name"]))
                except:
                    print colored("[ERROR] Function {} could not be disassembled".format(fun["name"]), "red")
                else:
                    mutation = mutate_function(args, fun_code)
                    if mutation is not None and mutation:
                        mutations.append(mutation)

        print colored("[INFO] Starting patching routine.", "cyan")
        mutations = [dict for sub_list in mutations for dict in sub_list]
        patch_executable(args, r2, mutations)

        print colored("[INFO] Exiting...", "cyan")
    else:
        print colored("[ERROR] Could not load any function.", "red")
        if args.batch:
            batch_log.write('{}\n'.format("Error: Could not load any function."))
    r2.quit()


def configure_environment(args):
    global KS, META, total_ins
    shutil.copyfile(args.input, args.output)

    print colored("[INFO] Opening {} in radare2.".format(args.input), "cyan")
    r2 = r2pipe.open(args.output, ["-w"])

    if args.debug:
        print colored("[DEBUG] Analyzing architecture of the executable.", "green")

    exe_info = r2.cmdj('ij')
    if 'bin' in exe_info:
        if exe_info['bin']['arch'] == "x86":
            bits = exe_info['bin']['bits']
            print colored("[INFO] Detected {} bits architecture.".format(bits), "cyan")
        else:
            print colored("[ERROR] Architecture not supported.", "red")
            if args.batch:
                batch_log.write('{}\n'.format("Error: Architecture not supported."))
            return None
    else:
        print colored("[ERROR] Format file not supported.", "red")
        if args.batch:
            batch_log.write('{}\n'.format("Error: File format not supported."))
        return None

    print colored("[INFO] Analyzing executable code.", "cyan")
    r2.cmd('aaa')

    KS = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32 if bits == 32 else ks.KS_MODE_64)
    META = me.MetaEngine(bits)
    total_ins = 0

    return r2


def prepare_batch_execution(args):
    global batch_log
    if not exists(args.input):
        mkdir(args.input)
        if args.debug:
            print colored("[DEBUG] Creating directory {}.".format(args.input), "green")

    if exists(args.input) and not isdir(args.input):
        print colored("[ERROR] The input path is not a directory.", "red")
        sys.exit()

    if not exists(args.output):
        mkdir(args.output)
        if args.debug:
            print colored("[DEBUG] Creating directory {}.".format(args.output), "green")

    if exists(args.output) and not isdir(args.output):
        print colored("[ERROR] The output path is not a directory.", "red")
        sys.exit()

    print colored("[INFO] Disabling debugging to not clutter terminal.", "cyan")
    args.debug = False

    batch_log = open(args.batch, 'w')


def parse_arguments():
    argparser = argparse.ArgumentParser(prog="pymetangine",
                                        description='A python metamorphic engine for PE/PE+ using radare2.')
    argparser.add_argument('-b', '--batch', nargs='?', const='batch.log', default='',
                           help='Enable batch execution, receiving a directory as input/output.')
    argparser.add_argument('-i', '--input', required=True,
                           help='Path to input executable/directory.')
    argparser.add_argument('-o', '--output', default=['meta.exe', 'meta'],
                           help='Path to output executable/directory. Default: meta.exe/meta for file/directory.')
    argparser.add_argument('-d', '--debug', action='store_true',
                           help='Enable debug messages during execution.')
    argparser.add_argument('-r', '--random', choices=['y', 'n'], default='y',
                           help='Change mode of replacements, random/all substitutions.')

    args = argparser.parse_args()

    # Set default value for args.output, meta if args.batch, meta.exe otherwise
    if type(args.output) is list:
        if not args.batch:
            args.output = args.output[0]
        else:
            args.output = args.output[1]

    if args.debug:
        print colored("[DEBUG] Parsing arguments.", "green")

    return args


# insercion de instrucciones inocuas, insercion de codigo muerto
# sustitucion de instrucciones, sustituciones de registros
if __name__ == "__main__":
    args = parse_arguments()
    if args.batch:
        prepare_batch_execution(args)

        executables = [exe for exe in listdir(args.input)
                       if isfile(join(args.input, exe))]

        in_dir = args.input
        out_dir = args.output

        for exe in executables:
            args.input = join(in_dir, exe)
            if args.random == 'n':
                args.output = join(out_dir, exe).replace('.bin', '_rn.bin')
            else:
                args.output = join(out_dir, exe).replace('.bin', '_ry.bin')

            batch_log.write("{:50s}".format(exe))

            r2 = configure_environment(args)
            if r2 is not None:
                main(args, r2)

        batch_log.close()
    else:
        r2 = configure_environment(args)
        if r2 is not None:
            main(args, r2)