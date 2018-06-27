from logzero import logger
from typing import Type

from .arch.arm  import ArmArchitecture
from .arch.mips import MipsArchitecture
from .arch.x86  import X86Architecture

from .emit import *


def handle_command_line(force: bool = False):
    """Handles the provided command like arguments.
    
       If @force is `True`, this function will be executed regardless if whether
       the current module is the main module."""
    
    def decorator(emitter_class: Type[Emitter]):
        from .helpers import *
        
        if not force:
            import inspect

            caller_module = inspect.stack()[1][0].f_globals
            caller_module_name = caller_module['__name__']

            if caller_module_name != '__main__':
                return
        
        # Got this far, we can continue peacefully
        import logging

        architectures = [ ArmArchitecture(), MipsArchitecture(), X86Architecture() ]

        # Set up verbosity
        args, _ = create_default_argument_parser().parse_known_args()
        verbosity = args.verbose

        if verbosity == 0:
            logzero.loglevel(logging.FATAL)
        elif verbosity == 1:
            logzero.loglevel(logging.ERROR)
        elif verbosity == 2:
            logzero.loglevel(logging.WARN)
        elif verbosity == 3:
            logzero.loglevel(logging.INFO)
        else:
            logzero.loglevel(logging.DEBUG)
        
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

        output_dir = args.output_dir

        
        # Translate architectures one by one
        for arch in architectures:
            # Initialize architecture and test source 
            arch.initialize(args)

            test_source = arch.tests
            emitter : Emitter = emitter_class(args, arch.name)

            # Ready output files
            logger.debug(f'Translating architecture {arch.name.capitalize()}...')

            output_path = os.path.join(output_dir, emitter.filename)

            if emitter.test_filename:
                test_path = os.path.join(output_dir, emitter.test_filename)

                ensure_directory_exists(test_path)
            else:
                test_path = None

            ensure_directory_exists(emitter.filename)

            # Translate source
            with open(output_path, 'w', newline='\n') as output, emitter_hooks(emitter, output):
                emitter.write_header()

                for decl in arch.declarations:
                    emitter.write_decl(decl)

                emitter.write_separator()

                for fun in arch.functions:
                    emitter.write_function(fun)
                
                emitter.write_footer()
            
            # Translate tests
            if test_path and test_source:
                with open(test_path, 'w', newline='\n') as output, emitter_hooks(emitter, output):
                    emitter.write_test_header()

                    for test_case in test_source.test_cases:
                        emitter.write_test(test_case)

                    emitter.write_test_footer()

            logger.info(f'Translated architecture {arch.name.capitalize()}.')
    
    return decorator
