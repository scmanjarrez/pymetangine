import sys
import r2pipe
import argparse
import shutil
import MetaEngine as me
import keystone as ks
from termcolor import colored

KS = None
META = None


def generate_bytes(code):
    asm, _ = KS.asm(code)
    return "".join(["{:02x}".format(ins) for ins in asm])


def mutate_function(args, func):
    n_ins = len(func["ops"])
    ins_idx = 0
    mutations = []
    while ins_idx < n_ins:
        ins_analyzed = func["ops"][ins_idx]
        if ins_analyzed["type"] not in META.mutable_ins:
            ins_idx += 1
            continue

        meta = META.generate_mutations(func["ops"], ins_idx)
        if meta is not None:
            mutation, size = meta

            if ins_analyzed["size"] == size:
                if args.debug:
                    print colored("[DEBUG] Mutating instruction ({:#x}): {:15s} --> {:30s}"
                          .format(ins_analyzed["offset"], ins_analyzed["opcode"],
                                  mutation if mutation != "" else ins_analyzed["opcode"]), "green" if mutation != "" else "magenta")
                if mutation:
                    mutations.append({"offset": ins_analyzed["offset"], "bytes": generate_bytes(mutation)})
            else:
                ins_to_skip = size-ins_analyzed["size"]
                # TODO -> cambiar nop; nop por push reg2; pop reg1 cuando sea necesario
                n_nops = "nop" + "; nop" * ins_to_skip
                same_ins = mutation == "" or mutation == n_nops

                if args.debug:
                    print colored("[DEBUG] Mutating instruction ({:#x}): {:15s} --> {:30s}"
                          .format(ins_analyzed["offset"], n_nops,
                                  mutation if not same_ins else n_nops), "green" if not same_ins else "magenta")

                ins_idx += ins_to_skip
                if not same_ins:
                    mutations.append({"offset": ins_analyzed["offset"], "bytes": generate_bytes(mutation)})
        ins_idx += 1
    return mutations


def patch_executable(args, r2, list_mutations):
    print colored("[INFO] Writing mutations to {}".format(args.output), "cyan")
    for idx, mutation in enumerate(list_mutations):
        r2.cmd("wx {} @{}".format(mutation["bytes"], mutation["offset"]))

    print colored("[INFO] Total number of mutations: {}"
          .format(len(list_mutations)), "cyan")


def main(args, r2):
    print colored("[INFO] Loading functions information.", "cyan")
    functions = r2.cmdj("aflj")

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
    r2.quit()


def configure_environment(args):
    global KS, META
    shutil.copyfile(args.input, args.output)

    print colored("[INFO] Opening {} in radare2.".format(args.input), "cyan")
    r2 = r2pipe.open(args.output, ["-w"])

    if args.debug:
        print colored("[DEBUG] Analyzing architecture of the executable.", "green")

    exe_info = r2.cmdj('ij')
    if exe_info['bin']['arch'] == "x86":
        bits = exe_info['bin']['bits']
        print colored("[INFO] Detected {} bits architecture.".format(bits), "cyan")
    else:
        print colored("[ERROR] Architecture not supported.", "red")
        sys.exit()

    print colored("[INFO] Analyzing executable code.", "cyan")
    r2.cmd('aaa')

    KS = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32 if bits == 32 else ks.KS_MODE_64)
    META = me.MetaEngine(bits)

    return r2


def parse_arguments():
    argparser = argparse.ArgumentParser(prog="pymetangine",
                                     description='A python metamorphic engine for x86_64 using radare2.')
    argparser.add_argument('-i', '--input', required=True,
                        help='Indicate the path to the input executable')
    argparser.add_argument('-o', '--output', default='meta.exe',
                        help='Indicate the path to the output executable. Otherwise, use default output: meta.exe.')
    argparser.add_argument('-d', '--debug', action='store_true',
                           help='Generate debug messages of the execution.')

    args = argparser.parse_args()

    if args.debug:
        print colored("[DEBUG] Parsing arguments.", "green")

    return args

# insercion de instrucciones inocuas, insercion de codigo muerto
# sustitucion de instrucciones, sustituciones de registros
if __name__ == "__main__":
    args = parse_arguments()
    r2 = configure_environment(args)
    main(args, r2)