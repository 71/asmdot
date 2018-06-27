from logzero import logger
from typing import Type

from .emit import *

def handle_command_line(force: bool = False):
    """Handles the provided command like arguments.
    
       If @force is `True`, this function will be executed regardless if whether
       the current module is the main module."""

    def decorator(emitter_class: Type[Emitter]):
        from .arch.arm import ArmArchitecture
        from .arch.mips import MipsArchitecture
        from .arch.x86 import X86Architecture

        from .helpers import create_default_argument_parser, \
                             emitter_hooks,                  \
                             ensure_directory_exists,        \
                             parent, debug, info, ASMLOGGER
        
        import inspect

        # Ensure we're supposed to handle command line
        caller_frame = inspect.stack()[1]

        if not force:
            caller_module_name = caller_frame[0].f_globals['__name__']

            if caller_module_name != '__main__':
                return
        
        # Got this far, we can continue peacefully
        import logging, os.path

        architectures = [ ArmArchitecture(), MipsArchitecture(), X86Architecture() ]

        # Set up verbosity
        args, _ = create_default_argument_parser().parse_known_args()
        verbosity = args.verbose

        if verbosity == 0:
            ASMLOGGER.setLevel(logging.FATAL)
        elif verbosity == 1:
            ASMLOGGER.setLevel(logging.ERROR)
        elif verbosity == 2:
            ASMLOGGER.setLevel(logging.WARN)
        elif verbosity == 3:
            ASMLOGGER.setLevel(logging.INFO)
        else:
            ASMLOGGER.setLevel(logging.DEBUG)
        
        # Load all arguments
        parser = create_default_argument_parser()
        
        emitter_class.register(parser)

        for arch in architectures:
            arch.__class__.register(parser) # type: ignore
        
        args = parser.parse_args()

        if args.help:
            # Stop execution and show help message.
            # We only do this now so that the help message also contains usage of arguments
            # registered by loaded architectures / sources / languages.
            parser.print_help()
            quit(0)

        output_dir = args.output or                   \
                     parent(caller_frame.filename) or \
                     os.getcwd()

        
        # Translate architectures one by one
        for arch in architectures:
            # Initialize architecture and test source
            arch.initialize(args)

            test_source = arch.tests
            emitter : Emitter = emitter_class(args, arch.name)

            debug('Translating', arch.name.upper(), '.')

            # Ready output files
            output_path = os.path.join(output_dir, emitter.filename)

            if not args.no_tests and emitter.test_filename:
                test_path = os.path.join(output_dir, emitter.test_filename)
            else:
                test_path = None
            
            declarations = list( arch.declarations )
            functions = list( arch.functions )

            # Translate source
            if not args.no_sources:
                ensure_directory_exists(output_path)

                with open(output_path, 'w', newline='\n') as output, emitter_hooks(emitter, output):
                    emitter.write_header()

                    for decl in arch.declarations:
                        emitter.write_decl(decl)

                    emitter.write_separator()

                    for fun in arch.functions:
                        emitter.write_function(fun)
                    
                    emitter.write_footer()

                info('Translated', arch.name.upper(), ' sources.')
            
            # Translate tests
            if test_path and test_source:
                ensure_directory_exists(test_path)

                test_source.declarations = declarations
                test_source.functions = functions

                with open(test_path, 'w', newline='\n') as output, emitter_hooks(emitter, output):
                    emitter.write_test_header()

                    for test_case in test_source.test_cases:
                        emitter.write_test(test_case)

                    emitter.write_test_footer()
    
                info('Translated', arch.name.upper(), ' tests.')
    
    return decorator
