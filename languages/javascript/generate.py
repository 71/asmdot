from asmdot import *  # pylint: disable=W0614

separator = '''

export class {}Assembler {{
    private ofs: number = 0;

    public constructor(readonly buffer: DataView) {{}}

    public get offset(): number {{ return this.ofs; }}
    public set offset(ofs: number) {{
        if (ofs < 0 || ofs > this.buffer.byteLength)
            throw RangeError();
        
        this.ofs = ofs;
    }}

'''

@handle_command_line()
class JavaScriptEmitter(Emitter):
    cast_params: List[str] = []
    declaration_names: List[str] = []


    @property
    def language(self):
        return 'javascript'

    @property
    def filename(self):
        return f'src/{self.arch}.ts'

    @property
    def test_filename(self):
        return f'test/{self.arch}.test.ts'


    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

        self.indent = Indent('    ')


    def get_function_name(self, function: Function) -> str:
        return function.fullname

    def get_type_name(self, ty: IrType) -> str:
        return replace_pattern({
            'bool': 'boolean',
            r'u?int\d+': 'number'
        }, ty.id)

    def get_builtin_name(self, builtin: Builtin) -> str:
        if builtin is BUILTIN_X86_PREFIX:
            return 'getPrefix'
        else:
            return builtin.name


    def write_header(self):
        self.declaration_names.append(f'{self.arch.capitalize()}Assembler')

    def write_separator(self):
        self.write(separator.format(self.arch.capitalize()))
        self.indent += 1
    
    def write_footer(self):
        self.indent -= 1
        self.write('}\n')


    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')
        
        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)
        
        elif isinstance(expr, Ternary):
            self.write('(', expr.condition, ' ? ', expr.consequence, ' : ', expr.alternative, ')')

        elif isinstance(expr, Var):
            if expr.name in self.cast_params:
                self.write('(', expr.name, ' ? 1 : 0)')
            else:
                self.write(expr.name)

        elif isinstance(expr, Call):
            self.write(expr.builtin, '(', join_any(', ', expr.args), ')')
        
        elif isinstance(expr, Literal):
            self.write(expr.value)

        else:
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement):
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value)
        
        elif isinstance(stmt, Conditional):
            self.writelinei('if (', stmt.condition, ') {')

            with self.indent.further():
                self.write_stmt(stmt.consequence)
            
            if stmt.alternative:
                self.writelinei('} else {')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)
            else:
                self.writelinei('}')
        
        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s)
        
        elif isinstance(stmt, Set):
            call = 'this.buffer.set'

            if stmt.type.under in (TYPE_U8, TYPE_U16, TYPE_U32, TYPE_U64):
                call += 'Uint'
            else:
                call += 'Int'
            
            call += str(stmt.type.under.size * 8)

            if stmt.type.under in (TYPE_U8, TYPE_I8):
                self.writelinei(call, '(this.ofs, ', stmt.value, ');')
            else:
                endian = 'false' if self.bigendian else 'true'
                
                self.writelinei(call, '(this.ofs, ', stmt.value, ', ', endian, ');')
            
            self.writelinei('this.ofs += ', stmt.type.size, ';')

        elif isinstance(stmt, Define):
            self.writelinei(f'let {stmt.name} = ', stmt.value, ';')

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.writelinei('// ', fun.descr)
        self.writei('public ', fun.name, '(')
        self.write(', '.join([ f'{name}: {typ}' for name, typ, _ in fun.params ]))
        self.write(') {\n')
        self.indent += 1

        for name, typ, usagetyp in fun.params:
            if typ is TYPE_BOOL and usagetyp is not TYPE_BOOL:
                self.cast_params.append(name)

        for condition in fun.conditions:
            self.writelinei('if (!', condition, ') throw Error();')

        for stmt in fun.body:
            self.write_stmt(stmt)
        
        self.indent -= 1
        self.writei('}\n\n')


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.declaration_names.append(str(decl.type))

            self.write('// ', decl.descr, '\n')
            self.write('export const enum ', decl.type, ' {\n')
            self.indent += 1

            for name, value, descr, _ in decl.members + decl.additional_members:
                self.writei('// ', descr, '\n')
                self.writei(name, ' = ', value, ',\n')
            
            self.indent -= 1
            self.write('}\n\n')
        
        elif isinstance(decl, DistinctType):
            self.declaration_names.append(str(decl.type))
            self.write('// ', decl.descr, '\n')

            if decl.constants:
                self.write('export const enum ', decl.type, ' {\n')
                self.indent += 1

                for name, value in decl.constants:
                    self.writei(name.upper(), ' = ', value, ',\n')

                self.indent -= 1
                self.write('}\n')
            else:
                self.write('export type ', decl.type, ' = ', decl.type.underlying, ';\n')
            
            self.write('\n')
        
        else:
            raise UnsupportedDeclaration(decl)


    def write_test_header(self):
        imports = ', '.join(self.declaration_names)

        self.write( 'import { arrayBufferToArray } from "./helpers";\n')
        self.write(f'import {{ {imports} }} from "../src/{self.arch}";\n\n')

    def write_test(self, test: TestCase):
        self.writelinei('test("', test.name, '", () => {')
        self.indent += 1

        self.writelinei('const arrayBuffer = new ArrayBuffer(', len(test.expected), ');')
        self.writelinei('const dataView = new DataView(arrayBuffer);\n')
        self.writelinei('const buffer = new ', self.arch.capitalize(), 'Assembler(dataView);\n')

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{arg.type.type}.{arg.const.name.upper()}'
            if isinstance(arg, ArgEnumMember):
                return f'{arg.enum.type}.{arg.member.name}'
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            args_str = ', '.join([ arg_str(arg) for arg in args ])

            self.writelinei('buffer.', func.name, '(', args_str, ');')
        
        self.writeline()
        self.writelinei('expect(arrayBufferToArray(arrayBuffer)).toEqual([ ', join_any(', ', test.expected), ' ]);')
        self.indent -= 1

        self.writeline('});\n')
