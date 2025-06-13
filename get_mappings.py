import gdb

class GetMappings(gdb.Command):
    """Command to get memory mappings of the current process."""

    def __init__(self):
        super(GetMappings, self).__init__("get_mappings", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # Ensure the process is running
        if not gdb.execute("info proc", to_string=True):
            print("No process is currently being debugged.")
            return

        # Use the `info proc mappings` command to get memory mappings
        try:
            mappings = gdb.execute("info proc mappings", to_string=True)
            print("Memory Mappings:\n")
            print(mappings)
        except gdb.error as e:
            print(f"Error retrieving mappings: {e}")

# Register the command
GetMappings()

