from asmdot import *  # pylint: disable=W0614
from typing import Tuple

header = '''// Automatically generated file.
package {}

import (
\t"bytes"
\t"encoding/binary"
\t"errors"
\t"io"
)

// Bypass unused module error if we don't have assertions.
var _ = errors.New

var (
\tinterbuf         = [8]byte{{}}
\tbyteOrder        = binary.LittleEndian
\tswappedByteOrder = binary.BigEndian
)

func write16(w io.Writer, x uint16) error {{
\tbyteOrder.PutUint16(interbuf[:], x)
\t_, err := w.Write(interbuf[:2])
\treturn err
}}

func writeSwapped16(w io.Writer, x uint16) error {{
\tswappedByteOrder.PutUint16(interbuf[:], x)
\t_, err := w.Write(interbuf[:2])
\treturn err
}}

func write32(w io.Writer, x uint32) error {{
\tbyteOrder.PutUint32(interbuf[:], x)
\t_, err := w.Write(interbuf[:4])
\treturn err
}}

func writeSwapped32(w io.Writer, x uint32) error {{
\tswappedByteOrder.PutUint32(interbuf[:], x)
\t_, err := w.Write(interbuf[:4])
\treturn err
}}

func write64(w io.Writer, x uint64) error {{
\tbyteOrder.PutUint64(interbuf[:], x)
\t_, err := w.Write(interbuf[:])
\treturn err
}}

func writeSwapped64(w io.Writer, x uint64) error {{
\tswappedByteOrder.PutUint64(interbuf[:], x)
\t_, err := w.Write(interbuf[:])
\treturn err
}}

'''

header_x86 = '''
func getPrefix16(r *Reg16) byte {
	if uint8(*r) < 8 {
		return byte(*r)
	}

	*r = Reg16(uint8(*r) - 8)
	return 1
}

func getPrefix32(r *Reg32) byte {
	if uint8(*r) < 8 {
		return byte(*r)
	}

	*r = Reg32(uint8(*r) - 8)
	return 1
}

func getPrefix64(r *Reg64) byte {
	if uint8(*r) < 8 {
		return byte(*r)
	}

	*r = Reg64(uint8(*r) - 8)
	return 1
}
'''

def _camel_case(s: str) -> str:
    return s[0] + s.title().replace('_', '')[1:]

def _pascal_case(s: str) -> str:
    return s.title().replace('_', '')

@handle_command_line()
class GoEmitter(Emitter):
    modified_list: List[str] = []
    var_map: Dict[str, Tuple[IrType, IrType]] = {}

    @property
    def language(self):
        return 'go'

    @property
    def filename(self):
        return f'{self.arch}/{self.arch}.go'

    @property
    def test_filename(self):
        return f'{self.arch}/{self.arch}_test.go'


    def get_function_name(self, function: Function) -> str:
        return _pascal_case(function.fullname)

    def get_operator(self, op: Operator) -> str:
        if op == OP_BITWISE_XOR:
            return '!='
        else:
            return op.op

    def get_builtin_name(self, builtin: Builtin) -> str:
        if builtin == BUILTIN_X86_PREFIX:
            return 'getPrefix'
        else:
            return builtin.name


    def __init__(self, args: Namespace, arch: str) -> None:
        super().__init__(args, arch)

        self.indent = Indent('\t')


    def write_header(self):
        self.write(header.format(self.arch))

        if self.arch == 'x86':
            self.write(header_x86)

    def write_separator(self):
        self.writeline()


    def write_expr(self, expr: Expression):
        if isinstance(expr, Binary):
            self.write('(', expr.l, ' ', expr.op, ' ', expr.r, ')')

        elif isinstance(expr, Unary):
            self.write(expr.op, expr.v)

        elif isinstance(expr, Ternary):
            self.write('(func() { if ', expr.condition, ' { return ', expr.consequence, ' } else { return ', expr.alternative, ' })()')

        elif isinstance(expr, Var):
            name = _camel_case(expr.name)

            if name in self.modified_list:
                name = name + '_'
            else:
                name = f'{self.var_map[expr.name][1]}({name})'

            self.write(name)

        elif isinstance(expr, Call):
            if self.var_map[expr.args[0].name][0].id == 'Reg16':
                self.write(expr.builtin, '16(&', expr.args[0].name, ')')
            elif self.var_map[expr.args[0].name][0].id == 'Reg32':
                self.write(expr.builtin, '32(&', expr.args[0].name, ')')
            elif self.var_map[expr.args[0].name][0].id == 'Reg64':
                self.write(expr.builtin, '64(&', expr.args[0].name, ')')

        elif isinstance(expr, Literal):
            self.write(expr.value)

        else:
            raise UnsupportedExpression(expr)

    def write_stmt(self, stmt: Statement):
        if isinstance(stmt, Assign):
            self.writelinei(stmt.variable, ' = ', stmt.value)

        elif isinstance(stmt, Conditional):
            self.writelinei('if ', stmt.condition, ' {')

            with self.indent.further():
                self.write_stmt(stmt.consequence)

            if stmt.alternative:
                self.writelinei('} else {')

                with self.indent.further():
                    self.write_stmt(stmt.alternative)

            self.writelinei('}')

        elif isinstance(stmt, Block):
            for s in stmt.statements:
                self.write_stmt(s)

        elif isinstance(stmt, Set):
            if stmt.type.under in (TYPE_U8, TYPE_I8):
                self.writelinei('if err := w.WriteByte(byte(', stmt.value, ')); err != nil {')
            else:
                if self.bigendian:
                    write = f'writeSwapped{stmt.type.under.size * 8}'
                else:
                    write = f'write{stmt.type.under.size * 8}'

                self.writelinei('if err := ', write, '(w, uint', stmt.type.under.size * 8, '(', stmt.value, ')); err != nil {')

            self.writelinei('\treturn err')
            self.writelinei('}')

        elif isinstance(stmt, Define):
            self.writelinei(f'{stmt.name} := ', stmt.value)

        else:
            raise UnsupportedStatement(stmt)

    def write_function(self, fun: Function):
        self.modified_list.clear()
        self.write(f'func {fun.name}(w *bytes.Buffer')

        for name, typ, usagetyp in fun.params:
            self.write(f', {_camel_case(name)} {typ}')
            self.var_map[name] = typ, usagetyp

        self.write(') error {\n')

        self.indent += 1

        for name, typ, usagetyp in fun.params:
            if typ is TYPE_BOOL and usagetyp is not TYPE_BOOL:
                name = _camel_case(name)

                self.writelinei(f'var {name}_ {usagetyp} = 0')
                self.writelinei(f'if {name} {{')
                self.writelinei(f'\t{name}_ = 1')
                self.writelinei( '}')
                self.modified_list.append(name)

        for condition in fun.conditions:
            self.writelinei('if !', condition, ' {')
            self.writelinei('\treturn errors.New("Failed precondition: ', condition, '.")')
            self.writelinei('}')

        for stmt in fun.body:
            self.write_stmt(stmt)

        self.writelinei('return nil')
        self.write('}\n\n')
        self.indent -= 1


    def write_decl(self, decl: Declaration):
        if isinstance(decl, Enumeration):
            self.writeline('// ', decl.descr)
            self.writeline('type ', decl.type, ' ', decl.type.underlying, '\n')
            self.writeline('const (')

            for _, value, descr, fullname in decl.members + decl.additional_members:
                self.writeline('\t// ', descr)
                self.writeline('\t', fullname, ' ', decl.type, ' = ', value)

            self.writeline(')')

        elif isinstance(decl, DistinctType):
            self.writeline('// ', decl.descr)
            self.writeline('type ', decl.type, ' ', decl.type.underlying, '\n')
            self.writeline('const (')

            for name, value in decl.constants:
                self.writeline('\t', name.upper(), ' ', decl.type, ' = ', value)

            self.writeline(')')

        else:
            raise UnsupportedDeclaration(decl)

        self.writeline()


    def write_test_header(self):
        self.writeline('package ', self.arch, '\n')
        self.writeline('import (\n\t"bytes"\n\t"testing"\n)\n')

    def write_test(self, test: TestCase):
        self.write('func Test', _pascal_case(test.name.replace(' ', '_')), '(t *testing.T) {\n')
        self.indent += 1

        self.writelinei('buf := new(bytes.Buffer)\n')

        def arg_str(arg: TestCaseArgument):
            if isinstance(arg, ArgConstant):
                return f'{arg.const.name.upper()}'
            if isinstance(arg, ArgEnumMember):
                return arg.member.fullname
            elif isinstance(arg, ArgInteger):
                return str(arg.value)
            else:
                raise UnsupportedTestArgument(arg)

        for func, args in test.calls:
            self.writei(func.name, '(buf')

            for arg in args:
                self.write(', ', arg_str(arg))

            self.write(')\n')

        self.writeline()
        self.writelinei('if buf.Len() != ', len(test.expected), ' {')
        self.writelinei('\tt.Errorf("buf.Len() = %d; want ', len(test.expected), '", buf.Len())')
        self.writelinei('}')
        self.writelinei('if !bytes.Equal(buf.Bytes(), []byte{', test.expected_bytes, '}) {')
        self.writelinei('\tt.Errorf("buf.Bytes() is not valid")')
        self.writelinei('}')
        self.indent -= 1

        self.write('}\n\n')
