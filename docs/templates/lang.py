from asmdot import *  # pylint: disable=W0614

# Uncomment the following line to ensure the language
# can be directly used through the command line.
# @handle_command_line()
class ExampleEmitter(Emitter):
    """Example `Emitter` that can be used to easily get started creating new bindings.

       This example is a simplified and commented version of the C emitter available
       in the src/lang/c.py file."""

    @property
    def language(self):
        # Returns the identifier of the language.
        #
        # This identifier will be used to name the directory in which
        # all files are put.
        return 'example'

    @property
    def filename(self):
        # Relative path to the file that is to be generated.
        #
        # In this case, a file '$OUTPUT_DIR/subdir/arch.ext' would be generated.
        return f'subdir/{self.arch}.ext'

    @property
    def test_filename(self):
        # (Optional)
        # Relative path to the test file that is to be generated.
        return f'test/{self.arch.ext}'


    def get_type_name(self, ty: IrType) -> str:
        # (Optional)
        # Return another name for the given type for this language.
        #
        # This can be used to customize the built-in types or coding conventions
        # specific to each language. This method is used by `IrType.__str__()` when
        # it is overriden.
        #
        # The methods `get_operator(self, Operator)`, `get_function_name(self, Function)`
        # and # `get_builtin_name(self, Builtin)` serve the same purpose, but for
        # `Operator`, `Function` and `Builtin` respectively.
        #
        # Furthermore, the utility function `` is provided to easily replace
        # common patterns. If no pattern matches the given type, its initial name is
        # returned.
        return replace_pattern({
            r'uint(\d+)': r'u\1'
        }, ty.id)


    @staticmethod
    def register(parser: ArgumentParser):
        # (Optional)
        # Register custom command line parameters for additional options.
        group = parser.add_argument_group('Example language')
        group.add_argument('-s', '--long-name', action='store_true', help='Help text.')

    def __init__(self, args: Namespace, arch: str):
        # (Optional)
        # Initialize the emitter, giving it the possibility to access its registered
        # arguments.
        super().__init__(args)

        self.example_arg : bool = args.long_name

        # You can also override `self.indent` depending on your needs
        self.indent = Indent('    ') # Default is two spaces


    def write_header(self):
        # (Optional)
        self.writeline('# Header...')
        self.indent += 1

        # Other utilities are provided for writing.

        self.write('# Not only ', type(str), 'ings.\n', indent=True)
        self.writeline('# Also, ablility to automatically add \\n.', indent=True)

        self.writei('# If you don\'t like writing `indent=True`, just add `i` to the\n')
        self.writelinei('# function name!')

        # Oh, and writing expressions or statements via `self.write` is optimized,
        # and just as fast as using `self.write_expr` and `self.write_stmt`.

        with self.indent.further():
            # Here, all indent is greater by a single unit.
            # Additionally, an integer can be given to control how much the indent
            # changes.
            self.writelinei('# Indented further...')

    def write_separator(self):
        # (Optional)
        self.writeline('# Write text that comes after custom declarations, but before\n',
                       '# function definitions.')
    
    def write_footer(self):
        # (Optional)
        self.write('# Write whatever goes at the end of the file.')
        self.indent -= 1


    def write_expr(self, expr: Expression):
        # Here, expressions should be written to the output stream based on their type.
        #
        # Also, please note that every call made to methods in the `Emitter` class
        # modify the Expression.__str__() and Statement.__str__()
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')
        
        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)
        
        elif isinstance(expr, Ternary):
            self.write('(', expr.condition, ' ? ', expr.consequence, ' : ', expr.alternative, ')')
        
        elif isinstance(expr, Var):
            self.write(expr.name)
        
        elif isinstance(expr, Call):
            self.write(expr.builtin, '(', join_any(', ', expr.args), ')')
        
        elif isinstance(expr, Literal):
            self.write(expr.value)
        
        else:
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement):
        # Same but with statements...
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value, ';')
        
        elif isinstance(stmt, Conditional):
            self.writelinei('if (', stmt.condition, ')')

            with self.indent.further():
                self.write_stmt(stmt.consequence)
            
            if stmt.alternative:
                self.writelinei('else')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)

        elif isinstance(stmt, Block):
            with self.indent.further(-1):
                self.writelinei('{')
        
            for s in stmt.statements:
                self.write_stmt(s)

            with self.indent.further(-1):
                self.writelinei('}')

        elif isinstance(stmt, Set):
            self.writelinei(f'*({stmt.type}*)(*buf) = ', stmt.value, ';')
            self.writelinei(f'(*buf) += ', stmt.type.size, ';')

        elif isinstance(stmt, Define):
            self.writelinei(f'{stmt.type} {stmt.name} = ', stmt.value, ';')

        else:
            raise UnsupportedStatement(stmt)
    
    def write_function(self, fun: Function):
        # Emit full function bodies, including their signature.
        #
        # Here is a simplified example of the C emitter.
        self.write(f'void {fun.name}(void** buf')

        for name, ctype, _ in fun.params:
            self.write(f', {ctype} {name}') # Here, `ctype` will use `get_type_name`
                                            # defined above.

            # Note the third tuple element, which is usually named 'usage type'.
            # It defines how the value will be used within the function.
            #
            # For example, in ARM, many instructions have switches that can be enabled.
            # In practice, those switches are encoded by shifting them to the
            # left by a constant value. In most languages, though, shifting a bool by
            # an integer is illegal.
            #
            # Thus, for a switch boolean, `ctype` would be TYPE_BOOL, but `usagetype`
            # would be TYPE_U32. Most languages actually convert these values at the
            # start of each function, but you may implement this as you like.

        self.write(') {\n')

        self.indent += 1

        for condition in fun.conditions:
            # Some assertions are made, and can be implemented as you wish.
            self.writelinei('assert(', condition, ');')

        for stmt in fun.body:
            # Finally, write the body of the function!
            self.write_stmt(stmt)
        
        self.write('}\n\n')
        self.indent -= 1


    def write_decl(self, decl: Declaration):
        # Emit declarations (either `Enumeration`s or `DistincType`s).
        #
        # They can have very different behaviors depending on whether
        # they are flags, so watch out for that!

        if isinstance(decl, Enumeration):
            self.write('/// ', decl.descr, '\n')
            self.write('typedef enum {\n')

            for _, value, descr, fullname in decl.members + decl.additional_members:
                self.write('    ///\n')
                self.write('    /// ', descr, '\n')
                self.write('    ', fullname, ' = ', value, ',\n')

            self.write('} ', decl.type, ';\n\n')
        
        elif isinstance(decl, DistinctType):
            self.write('#define ', decl.type, ' ', decl.type.underlying, '\n')

            for name, value in decl.constants:
                self.write('#define ', decl.type, '_', name, ' ', value, '\n')

        else:
            raise UnsupportedDeclaration(decl)
    

    def write_test_header(self):
        # (Optional)
        # Write the header of the test file.
        #
        # If @test_filename is None, this function will never be called.
        self.writelinei('...')
        self.indent += 1
    
    def write_test_footer(self):
        # (Optional)
        # Write the footer of the test file.
        #
        # If @test_filename is None, this function will never be called.
        self.writei('...')
        self.indent -= 1

    def write_test(self, test: TestCase):
        # (Optional)
        # Write the given test case to the test file.
        #
        # If @test_filename is None, this function will never be called.
        self.writelinei(f'void ', test.name.replace(' ', '_'), '() {')
        self.indent += 1

        for func, args in test.calls:
            # Each call is made up of one Function defined in the architecture,
            # and a list of arguments (which are either constants, enum members
            # or literals).
            self.writelinei('buf.', func.name, '(', '...', ')')
        
        self.writelinei('assert bytes == b"', test.expected_string, '"')
        self.writeline()

        self.indent -= 1
