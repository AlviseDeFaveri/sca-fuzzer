from typing import Optional

from elftools.elf.elffile import ELFFile
from pygdbmi.gdbcontroller import GdbController

class SymbolServer:
    def __init__(self, binary: str) -> None:
        pass

    def get_location(self, address: int) -> Optional[str]:
        return None


class GdbSymbolServer(SymbolServer):
    def __init__(self, binary: str) -> None:
        # Start gdb process
        self.gdbmi = GdbController()
        # Load binary
        _ = self.gdbmi.write(f'file {binary}')

    def get_location(self, address: int) -> str:
        # Try to get source location
        response = self.gdbmi.write(f'info line *{hex(address)}')
        payload = response[1]["payload"]
        # If not available, get at least function name
        if "No line number" in payload:
            return self.get_func_name(address)
        else:
            # Format as <file>:<line>
            splitted = payload.split(" ")
            payload = splitted[3].replace("\"","") + ":" + splitted[1]

        return payload.strip()

    def get_func_name(self, address: int) -> str:
        response = self.gdbmi.write(f'info sym {hex(address)}')
        payload = response[1]["payload"]
        # Format as <module>+<offset>
        splitted = payload.strip().split(" ")
        payload = splitted[0] + "+" + splitted[2]

        return payload.strip()


class ElfSymbolServer(SymbolServer):
    def __init__(self, binary: str):
        with open(binary, "rb") as f:
            self._elf_data = ELFFile(f)
            self.dwarf_info = self._elf_data.get_dwarf_info()

    def get_location(self, address: int) -> Optional[str]:
        # Go over all the line programs in the DWARF information, looking for
        # one that describes the given address.
        for CU in self.dwarf_info.iter_CUs():
            # First, look at line programs to find the file/line for the address
            line = self.dwarf_info.line_program_for_CU(CU)
            if not line:
                continue
            delta = 1 if line.header.version < 5 else 0
            prevstate = None
            for entry in line.get_entries():
                # We're interested in those entries where a new state is assigned
                if entry.state is None:
                    continue
                # Looking for a range of addresses in two consecutive states that
                # contain the required address.
                if prevstate and prevstate.address <= address < entry.state.address:
                    filename = line['file_entry'][prevstate.file - delta].name.decode()
                    line = prevstate.line
                    return f"{filename}:{line}"
                if entry.state.end_sequence:
                    # For the state with `end_sequence`, `address` means the address
                    # of the first byte after the target machine instruction
                    # sequence and other information is meaningless. We clear
                    # prevstate so that it's not used in the next iteration. Address
                    # info is used in the above comparison to see if we need to use
                    # the line information for the prevstate.
                    prevstate = None
                else:
                    prevstate = entry.state

        # if we're here, we didn't find a symbol
        return None


class CombinedSymbolServer(SymbolServer):
    def __init__(self, binary: str):
        # Fast
        self.elf_server = ElfSymbolServer(binary)
        # Slow
        self.gdb_server = GdbSymbolServer(binary)

    def get_location(self, address: int) -> str:
        result = self.elf_server.get_location(address)
        if result is None:
            result = self.gdb_server.get_func_name(address)

        return result

