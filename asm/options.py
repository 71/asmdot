from argparse import Namespace

class Options:

    def initialize_options(self, args: Namespace, arch: str):
        """Initializes the options, setting its attributes based on command-line parameters."""
        self.mutable_buffer : bool = args.update_pointer
        self.bindings : bool = args.bindings
        self.arch : str = arch

        if getattr(args, 'return') == 'size':
            self.return_type = 'int'
            self.return_size = True, False
        else:
            self.return_type = 'void'
            self.return_size = False
