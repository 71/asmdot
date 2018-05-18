from asm.emit import *  # pylint: disable=W0614

class PythonEmitter(Emitter):
    
    @property
    def language(self):
        return 'python'

    @property
    def filename(self):
        return f'{self.arch}.py'
    
    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            'bool': 'ctypes.c_bool',
            r'(u?int\d+)': r'ctypes.c_\1'
        }, ty.id)
    
    def initialize(self, args: Namespace):
        super().initialize(args)

        if not self.bindings:
            raise UnsupportedOption('no-bindings', 'The Python emitter can only generate bindings.')
        
        self.prefix = 'prefix' in args and args.prefix
        self.indent = Indent('    ')

    def write_header(self, out: IO[str]):
        self.write( 'import ctypes\nfrom . import voidptr, voidptrptr\nfrom enum import Enum, Flag\n\n')

    def write_footer(self, out: IO[str]):
        self.write('return asm\n', indent=True)
        self.indent -= 1

    def write_expr(self, expr: Expression, out: IO[str]):
        pass
    
    def write_stmt(self, stmt: Statement, out: IO[str]):
        pass
    
    def write_separator(self, out: IO[str]):
        self.write(f'def load_{self.arch}(lib: str = "asmdot"):\n')
        self.indent += 1
        self.write(f'"""Loads the ASM. library using the provided path, and returns a wrapper around the {self.arch} architecture."""\n', indent=True)
        self.write( 'asm = ctypes.cdll.LoadLibrary(lib)\n\n', indent=True)

    def write_function(self, fun: Function, out: IO[str]):
        keywords = ['and']
        name = prefix(self, fun.fullname)

        if name in keywords:
            name = f'["{name}"]'
        else:
            name = f'.{name}'

        self.write(f'asm{name}.restype = None\n', indent=True)
        self.write(f'asm{name}.argtypes = [ voidptrptr', indent=True)

        for _, ctype in fun.params:
            self.write(f', {ctype}')

        self.write(' ]\n')
        self.write(f'asm{name}.__doc__ = "{fun.descr}"\n', indent=True)

        if self.prefix:
            # Create function name with no prefix, if C API has prefixes.
            name = fun.fullname

            if name in keywords:
                name = f'["{name}"]'
            else:
                name = f'.{name}'

            self.write(f'asm{name} = asm.{self.arch}_{fun.fullname}\n', indent=True)

        self.write('\n')
    
    def write_decl(self, decl: Declaration, out: IO[str]):
        if isinstance(decl, Enumeration):
            sub = 'Flag' if decl.flags else 'Enum'

            self.write('class ', decl.type, f'(int, {sub}):\n')
            self.indent += 1
            self.write('"""', decl.descr, '"""\n', indent=True)

            for name, value, _ in decl.members + decl.additional_members:
                self.write(name, ' = ', value, '\n', indent=True)
            
            self.write('\n')
            self.write('@classmethod\n', indent=True)
            self.write('def from_param(cls, data): return data if isinstance(data, cls) else cls(data)\n\n', indent=True)
            self.indent -= 1

        elif isinstance(decl, DistinctType):
            self.write(decl.type, ' = ', decl.type.underlying, '\n\n')

        else:
            raise UnsupportedDeclaration(decl)
