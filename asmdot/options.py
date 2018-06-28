from argparse import Namespace

class Options:

    def initialize_options(self, args: Namespace, arch: str):
        """Initializes the options, setting its attributes based on command-line parameters."""
        self.arch : str = arch
        self.bigendian : bool = args.big_endian
