from argparse import Namespace

class Options:

    def initialize_options(self, args: Namespace, arch: str):
        """Initializes the options, setting its attributes based on command-line parameters."""
        self.bindings : bool = args.bindings
        self.arch : str = arch
