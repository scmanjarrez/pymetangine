from itertools import combinations
import keystone as ks
import random
import re


class MetaEngine:
    def __init__(self, bits):
        self.ks = ks.Ks(ks.KS_ARCH_X86,
                        ks.KS_MODE_32 if bits == 32 else
                        ks.KS_MODE_64)
        self.bits = bits
        self._ins = 0
        self.gen_regexp()

    @property
    def ins(self):
        return self._ins

    def ins_inc(self):
        self._ins = self._ins + 1

    def gen_bytes(self, code):
        asm, _ = self.ks.asm(code)
        return ''.join(['{:02x}'.format(ins) for ins in asm])

    def gen_nops(self, size):
        reg = random.choice(self.regs)
        if size == 1:
            return 'nop'
        if self.bits == 32:
            if size == 2:
                choice = random.randint(1, 4)
                if choice == 1:
                    return 'pushfd; popfd'
                elif choice == 2:
                    return 'pushad; popad'
                elif choice == 3:
                    return 'push {}; pop {}'.format(reg, reg)
                else:
                    return '{}; {}'.format(self.gen_nops(1),
                                           self.gen_nops(1))
            elif size == 3:
                choice = random.randint(1, 3)
                rnd_ins_1B = random.choice(
                    ['pushfd', 'popfd', 'pushad', 'popad',
                     'push {}', 'pop {}', 'inc {}', 'dec {}'])
                if choice == 1:
                    return 'jmp {}; {}'.format(3, rnd_ins_1B.format(reg))
                elif choice == 2:
                    return '{}; {}'.format(self.gen_nops(1),
                                           self.gen_nops(2))
                else:
                    return '{}; {}'.format(self.gen_nops(2),
                                           self.gen_nops(1))
        elif self.bits == 64:
            if size == 2:
                choice = random.randint(1, 3)
                if choice == 1:
                    return 'pushfq; popfq'
                elif choice == 2:
                    return 'push {}; pop {}'.format(reg, reg)
                else:
                    return '{}; {}'.format(self.gen_nops(1),
                                           self.gen_nops(1))
            elif size == 3:
                choice = random.randint(1, 4)
                # nop; push; pop already in case no-op_1B; no-op_2B
                # push; pop; nop already in case no-op_2B; no-op_1B
                # nop; pushfq; popfq already in case no-op_1B; no-op_2B
                # pushfq; popfq; nop already in case no-op_2B; no-op_1B
                if choice == 1:
                    return 'push {0}; {1}; pop {0}'.format(
                        reg, self.gen_nops(1))
                elif choice == 2:
                    return 'pushfq; {}; popfq'.format(self.gen_nops(1))
                elif choice == 3:
                    return '{}; {}'.format(self.gen_nops(1), self.gen_nops(2))
                else:
                    return '{}; {}'.format(self.gen_nops(2), self.gen_nops(1))
            elif size == 4:
                choice = random.randint(1, 2)
                if choice == 1:
                    rnd_ins_1B_x2 = random.sample(
                        ['push {}', 'pop {}', 'pushfq', 'popfq'], 2)
                    rnd_ins_2B = random.choice(
                        ['mov {}, {}', 'test {}, {}', 'cmp {}, {}',
                         'or {}, {}', 'sub {}, {}', 'inc {}',
                         'xor {}, {}', 'and {}, {}', 'dec {}'])
                    rnd = random.randint(1, 2)
                    if rnd == 1:
                        reg2 = random.choice(self.regs)
                        rnd_ins = rnd_ins_1B_x2.format(reg, reg2)
                    else:
                        reg_32b = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
                        rnd_ins = rnd_ins_2B.format(random.choice(reg_32b))
                    return 'jmp {}; {}'.format(4, rnd_ins)
                else:
                    return '{}; {}'.format(self.gen_nops(2),
                                           self.gen_nops(2))

    def gen_regexp(self):
        self.mutable_ins = frozenset(
            ['nop', 'upush', 'mov', 'acmp', 'or', 'xor', 'sub']
        ) if self.bits == 32 else frozenset(
            ['nop', 'mov', 'acmp', 'or', 'xor', 'sub'])
        # upush -> push reg | acmp -> test reg, reg
        self.regs = (['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi']
                     if self.bits == 32 else
                     ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi'])
        #  for some reason these registers crash the program:
        #  r8, r9, r10, r11, r12, r13, r14, r15
        self.nop_1B = re.compile(r'nop$')
        self.push_1B = re.compile(r'push (e..)$')
        self.pop_1B = re.compile(r'pop (e..)$')
        self.mov_2B = re.compile(r'mov (e..), (e..)$')
        self.test_2B = re.compile(r'test (e..), ((?=\1)...)$')
        self.or_2B = re.compile(r'or (e..), ((?=\1)...)$')
        self.xor_2B = re.compile(r'xor (e..), ((?=\1)...)$')
        self.sub_2B = re.compile(r'sub (e..), ((?=\1)...)$')
        self.mov_5B = re.compile(
            r'mov (e..), (0?x?(?:[0-7][\dA-Fa-f]|[\dA-Fa-f]))$')
        if self.bits == 64:
            self.mov_3B = re.compile(r'mov (r.[ixp]), (r.[ixp])$')
            self.test_3B = re.compile(
                r'test (r[a-ds189][ixp0-5]), ((?=\1)...)$')
            self.or_3B = re.compile(r'or (r[a-ds189][ixp0-5]), ((?=\1)...)$')
            self.xor_3B = re.compile(r'xor (r[a-ds189][ixp0-5]), ((?=\1)...)$')
            self.sub_3B = re.compile(r'sub (r[a-ds189][ixp0-5]), ((?=\1)...)$')

    def gen_permutation(self, ins1, ins2):
        res = []
        for locations in combinations(range(len(ins1) + len(ins2)), len(ins2)):
            out = ins1[:]
            for location, element in zip(locations, ins2):
                out.insert(location, element)
            res.append('; '.join(map(str, out)))
        return random.choice(res)

    def gen_mutations(self, ins_list, idx):
        if ins_list[idx]['size'] == 1:
            m1 = self.nop_1B.match(ins_list[idx]['opcode'])
            if m1 is not None:
                if (idx + 1 < len(ins_list) and
                    ins_list[idx + 1]['type'] != 'invalid'):  # noqa
                    m2 = self.nop_1B.match(ins_list[idx + 1]['opcode'])
                    if m2 is not None:
                        if (idx + 2 < len(ins_list) and
                            ins_list[idx + 2]['type'] != 'invalid'):  # noqa
                            m3 = self.nop_1B.match(ins_list[idx + 2]['opcode'])
                            if m3 is not None:  # nop; nop; nop
                                # flip a coin to change ins
                                rnd = random.randint(1, 2)
                                if rnd == 1:
                                    # equivalent instruction
                                    return '{}'.format(self.gen_nops(3)), 3
                                else:
                                    # original instruction
                                    return '', 3
                            else:  # nop; nop
                                rnd = random.randint(1, 2)
                                if rnd == 1:
                                    return '{}'.format(self.gen_nops(2)), 2
                                else:
                                    return '', 2
            m1 = self.push_1B.match(ins_list[idx]['opcode'])
            if m1 is not None:
                if (idx + 1 < len(ins_list) and
                    ins_list[idx + 1]['type'] != 'invalid'):  # noqa
                    m2 = self.pop_1B.match(ins_list[idx + 1]['opcode'])
                    if m2 is not None:  # push reg1; pop reg2
                        rnd = random.randint(1, 2)
                        if rnd == 1:  # mov reg2, reg1
                            return 'mov {}, {}'.format(
                                m2.group(1), m1.group(1)), 2
                        else:
                            return '', 2
            return None
        if ins_list[idx]['size'] == 2:
            m1 = self.mov_2B.match(ins_list[idx]['opcode'])
            if m1 is not None:
                if m1.group(1) == m1.group(2):  # mov reg1, reg1
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # no-op; no-op
                        return '{}'.format(self.gen_nops(2)), 2
                    else:  # mov reg1, reg1
                        return '', 2
                elif (m1.group(1) != m1.group(2) and
                      self.bits == 32):  # mov reg2, reg1
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # push reg1; pop reg2
                        return 'push {}; pop {}'.format(
                            m1.group(2), m1.group(1)), 2
                    else:  # mov reg2, reg1
                        return '', 2
            m1 = self.test_2B.match(ins_list[idx]['opcode'])
            if m1 is not None:  # test reg1, reg1
                rnd = random.randint(1, 2)
                if rnd == 1:  # or reg1, reg1
                    return 'or {0}, {0}'.format(m1.group(1)), 2
                else:  # test reg1, reg1
                    return '', 2
            m1 = self.or_2B.match(ins_list[idx]['opcode'])
            if m1 is not None:  # or reg1, reg1
                rnd = random.randint(1, 2)
                if rnd == 1:  # test reg1, reg1
                    return 'test {0}, {0}'.format(m1.group(1)), 2
                else:  # or reg1, reg1
                    return '', 2
            m1 = self.xor_2B.match(ins_list[idx]['opcode'])
            if m1 is not None:  # xor reg1, reg1
                rnd = random.randint(1, 2)
                if rnd == 1:  # sub reg1, reg1
                    return 'sub {0}, {0}'.format(m1.group(1)), 2
                else:  # xor reg1, reg1
                    return '', 2
            m1 = self.sub_2B.match(ins_list[idx]['opcode'])
            if m1 is not None:  # sub reg1, reg1
                rnd = random.randint(1, 2)
                if rnd == 1:  # xor reg1, reg1
                    return 'xor {0}, {0}'.format(m1.group(1)), 2
                else:  # sub reg1, reg1
                    return '', 2
            return None
        if self.bits == 64:
            if ins_list[idx]['size'] == 3:
                m1 = self.mov_3B.match(ins_list[idx]['opcode'])
                if m1 is not None:  # mov reg1, reg2
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # no-op; push reg2; pop reg1
                        ins_pair1 = ['{0}']
                        ins_pair2 = ['push {1}', 'pop {2}']
                        return (self.gen_permutation(ins_pair1, ins_pair2)
                                .format(self.gen_nops(1),
                                        m1.group(2), m1.group(1)), 3)
                    else:
                        return '', 3
                m1 = self.test_3B.match(ins_list[idx]['opcode'])
                if m1 is not None:  # test reg1, reg1
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # or reg1, reg1
                        return 'or {0}, {0}'.format(m1.group(1)), 3
                    else:  # test reg1, reg1
                        return '', 3
                m1 = self.or_3B.match(ins_list[idx]['opcode'])
                if m1 is not None:  # or reg1, reg1
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # test reg1, reg1
                        return 'test {0}, {0}'.format(m1.group(1)), 3
                    else:  # or reg1, reg1
                        return '', 3
                m1 = self.xor_3B.match(ins_list[idx]['opcode'])
                if m1 is not None:  # xor reg1, reg1
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # sub reg1, reg1
                        return 'sub {0}, {0}'.format(m1.group(1)), 3
                    else:  # xor reg1, reg1
                        return '', 3
                m1 = self.sub_3B.match(ins_list[idx]['opcode'])
                if m1 is not None:  # sub reg1, reg1
                    rnd = random.randint(1, 2)
                    if rnd == 1:  # xor reg1, reg1
                        return 'xor {0}, {0}'.format(m1.group(1)), 3
                    else:  # sub reg1, reg1
                        return '', 3
                return None
        if self.bits == 32:
            if ins_list[idx]['size'] == 5:
                m1 = self.mov_5B.match(ins_list[idx]['opcode'])
                if m1 is not None:
                    if m1.group(2) in ['0x1', '1']:  # mov reg1, 1
                        rnd = random.randint(0, 3)
                    elif m1.group(2) in ['0x0', '0']:  # mov reg1, 0
                        rnd = random.randint(3, 6)
                    else:  # mov reg1, imm
                        rnd = random.randint(1, 3)
                    if rnd == 0:
                        # permutations, keeping order
                        # (push before pop, xor before inc)
                        # of --> pushfd; xor reg1, reg1; inc reg1; popfd
                        ins_pair1 = ['pushfd', 'popfd']
                        ins_pair2 = ['xor {0}, {0}', 'inc {0}']
                        return (self.gen_permutation(ins_pair1, ins_pair2)
                                .format(m1.group(1)), 5)
                    elif rnd == 1:
                        # permutations, keeping order
                        # (push before pop)
                        # of --> push imm; pop reg; no-op
                        ins_pair1 = ['{0}']
                        ins_pair2 = ['push {1}', 'pop {2}']
                        return (self.gen_permutation(ins_pair1, ins_pair2)
                                .format(self.gen_nops(2),
                                        m1.group(2), m1.group(1)), 5)
                    elif rnd == 2:
                        # permutations, keeping order
                        # (push before pop)
                        # of --> push imm; pop reg; no-op; no-op
                        ins_pair1 = ['{0}', '{1}']
                        ins_pair2 = ['push {2}', 'pop {3}']
                        return (self.gen_permutation(ins_pair1, ins_pair2)
                                .format(self.gen_nops(1),
                                        self.gen_nops(1),
                                        m1.group(2), m1.group(1)), 5)
                    elif rnd == 3:
                        return '', 5
                    elif rnd == 4:
                        # permutations, keeping order
                        # (push before xor before pop,
                        # so flags are not modified)
                        # of --> pushfd; xor reg1, reg1; popfd; no-op
                        ins_pair1 = ['pushfd', 'xor {0}, {0}', 'popfd']
                        ins_pair2 = ['{1}']
                        return (self.gen_permutation(ins_pair1, ins_pair2)
                                .format(m1.group(1), self.gen_nops(1)), 5)
                    elif rnd == 5:
                        # permutations, keeping order
                        # (push before sub before pop,
                        # so flags are not modified)
                        # of --> pushfd; sub reg1, reg1; popfd; no-op
                        ins_pair1 = ['pushfd', 'sub {0}, {0}', 'popfd']
                        ins_pair2 = ['{1}']
                        return (self.gen_permutation(ins_pair1, ins_pair2)
                                .format(m1.group(1), self.gen_nops(1)), 5)
                    else:
                        # pushfd; and reg1, 0; popfd
                        return ('pushfd; and {}, 0; popfd'
                                .format(m1.group(1)), 5)
                return None
