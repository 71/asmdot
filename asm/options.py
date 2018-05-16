from argparse import Namespace
from .ast import TYPE_BYTE, TYPE_VOID

class Options:

    def initialize_options(self, args: Namespace, arch: str):
        """Initializes the options, setting its attributes based on command-line parameters."""
        self.mutable_buffer : bool = args.update_pointer
        self.bindings : bool = args.bindings
        self.arch : str = arch

        if getattr(args, 'return') == 'size':
            self.return_type = TYPE_BYTE
            self.return_size = True
        else:
            self.return_type = TYPE_VOID
            self.return_size = False
