from argparse import Namespace

class Options:

    def initialize_options(self, args: Namespace, arch: str):
        """Initializes the options, setting its attributes based on command-line parameters."""
        self.prefix_function_names : bool = args.prefix
        self.mutable_buffer : bool = args.update_pointer
        self.bindings : bool = args.bindings
        self.prefix : bool = args.prefix
        self.arch : str = arch

        if getattr(args, 'return') == 'size':
            self.returntype = 'int'
            self.return_size, self.return_success = True, False
        elif getattr(args, 'return') == 'success':
            self.returntype = 'bool'
            self.return_size, self.return_success = False, True
        else:
            self.returntype = 'void'
            self.return_size, self.return_success = False, False
