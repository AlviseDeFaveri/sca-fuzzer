#
# Parse two debug traces and check what is the first architectural instruction
# that differs between the two.
#

import sys
import os
import IPython

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def printc(color, content):
    print(color + str(content) + bcolors.ENDC)

def getpc(line):
    return line.strip().split(' ')[0]

def is_relevant(line):
    return line.startswith('[ARCH]')

class CmpFile:
    """
    Each file beign compared.
    """
    def __init__(self, path):
        self.fd = open(path)
        self.cur_line = None
        self.accumulated = []
        self.ended = False
        self.idx = 0

    def next(self):
        """
        Get next line that contains an instruction address.
        """
        if self.ended:
            return None

        self.accumulated = []
        self.cur_line = self.fd.readline()
        self.idx += 1

        # Instructions disassembled by DynamoRIO start with 2 spaces and the PC.
        while not is_relevant(self.cur_line):
            # Save previous lines.
            self.accumulated += [self.cur_line]
            # Read next line.
            self.cur_line = self.fd.readline()
            self.idx += 1

            if self.cur_line == "":
                self.ended = True
                return None

        return self.cur_line

    def dump(self, color):
        # Currently accumulated
        for l in self.accumulated:
            printc(color, l.replace('\n',''))
        # Current line
        printc(color, self.cur_line.replace('\n',''))
        # Next accumulated
        self.next()
        for l in self.accumulated:
            printc(color, l.replace('\n',''))

def cmp_vals(f1, f2, crash):
    """
    Compare two trace entries. If they are different and crash is True, spawn a shell.
    """
    val1 = f1.cur_line.split('(')[0].split(':')[1].strip()
    val2 = f2.cur_line.split('(')[0].split(':')[1].strip()

    if val1 != val2:
        if crash:
            printc(bcolors.FAIL, f"[{f1.idx}] {val1} != [{f2.idx}] {val2}")
            return False
        else:
            printc(bcolors.WARNING, f"[{f1.idx}] {val1} != [{f2.idx}] {val2}")
            return True
    else:
        print(f"[{f1.idx}] {val1} == [{f2.idx}] {val2}")
        return True


# Files to compare.
f1 = CmpFile(sys.argv[1])
f2 = CmpFile(sys.argv[2])
prev1 = None
prev2 = None

# Kill after python embed.
kill = False

while not f1.ended and not f2.ended:
    # Get next instruction on both files.
    l1 = f1.next()
    l2 = f2.next()

    if l1 is None:
        print(f'f1 finished at idx {f1.idx}!')
        break

    if l2 is None:
        print(f'f2 finished at idx {f2.idx}!')
        break

    # Parse program counter.
    # l1 = getpc(l1)
    # l2 = getpc(l2)

    # The second trace is allowed to have repeated entries for the same PC.
    # if l1 != l2 and prev2 == l2:
    #     cmp_vals(f1, f2, False)
    #     # l2 = getpc(f2.next())
    #     l2 = f2.next()
    #     l2 = f2.next()
    #     l2 = f2.next()

    # if l1.startswith('  0x000'):
    #     prev1 = l1
    # if l2.startswith('  0x000'):
    #     prev2 = l2

    same = cmp_vals(f1, f2, False)
    if not same and kill:
        print("----------------")
        f1.dump(bcolors.OKBLUE)

        print("----------------")
        f2.dump(bcolors.OKGREEN)

        print("----------------")
        IPython.embed()
        os._exit(-1)

f1.fd.close()
f2.fd.close()
