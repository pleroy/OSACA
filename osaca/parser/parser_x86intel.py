#!/usr/bin/env python3

import os
import pyparsing as pp
import re
import ruamel
import string

from osaca.parser import BaseParser
from osaca.parser.directive import DirectiveOperand
from osaca.parser.identifier import IdentifierOperand
from osaca.parser.immediate import ImmediateOperand
from osaca.parser.instruction_form import InstructionForm
from osaca.parser.label import LabelOperand
from osaca.parser.memory import MemoryOperand
from osaca.parser.register import RegisterOperand

# References:
#   ASM386 Assembly Language Reference, document number 469165-003, https://mirror.math.princeton.edu/pub/oldlinux/Linux.old/Ref-docs/asm-ref.pdf.
#   Microsoft Macro Assembler BNF Grammar, https://learn.microsoft.com/en-us/cpp/assembler/masm/masm-bnf-grammar?view=msvc-170.
#   Intel Architecture Code Analyzer User's Guide, https://www.intel.com/content/dam/develop/external/us/en/documents/intel-architecture-code-analyzer-3-0-users-guide-157552.pdf.
class ParserX86Intel(BaseParser):
    _instance = None

    # A handy utility for converting x86.yml to a form that has the destination first.
    @staticmethod
    def convertYAML():
        MODULE_DATA_DIR = os.path.join(
            os.path.dirname(os.path.split(os.path.abspath(__file__))[0]), "data/"
        )

        yaml = ruamel.yaml.YAML()
        yaml.preserve_quotes = True
        with open(os.path.join(MODULE_DATA_DIR, "isa/x86.yml"), "r", encoding="utf8") as fin:
            data = yaml.load(fin)

            for iform in data["instruction_forms"]:
                has_destination = False
                has_single_destination_at_end = False
                for o in iform["operands"]:
                    if o.get("source", False):
                        if has_destination:
                            has_single_destination_at_end = False
                    if o.get("destination", False):
                        if has_destination:
                            has_single_destination_at_end = False
                        else:
                            has_destination = True
                            has_single_destination_at_end = True
                if has_single_destination_at_end:
                    sources = iform["operands"][:-1]
                    destination = iform["operands"][-1]
                    sources.insert(0, destination)
                    iform["operands"] = sources

            with open(os.path.join(MODULE_DATA_DIR, "isa/x86_intel.yml"), "w", encoding="utf8") as fout:
                print(fout.name)
                yaml.dump(data, fout)

    # Singleton pattern, as this is created very many times.
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ParserX86Intel, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        super().__init__()
        self._equ = {}

    def isa(self):
        return "x86"

    # The IACA manual says: "For For Microsoft* Visual C++ compiler, 64-bit version, use
    # IACA_VC64_START and IACA_VC64_END, instead" (of IACA_START and IACA_END).
    def start_marker(self):
        return [
            InstructionForm(
                mnemonic="mov",
                operands=[RegisterOperand(name="AL"), ImmediateOperand(value=111)]
            ),
            InstructionForm(
                mnemonic="mov",
                operands=[
                    MemoryOperand(
                        base=RegisterOperand(name="GS"),
                        offset=ImmediateOperand(value=111)
                    ),
                    RegisterOperand(name="AL")
                ]
            ),
        ]

    def end_marker(self):
        return [
            InstructionForm(
                mnemonic="mov",
                operands=[RegisterOperand(name="AL"), ImmediateOperand(value=222)]
            ),
            InstructionForm(
                mnemonic="mov",
                operands=[
                    MemoryOperand(
                        base=RegisterOperand(name="GS"),
                        offset=ImmediateOperand(value=222)
                    ),
                    RegisterOperand(name="AL")
                ]
            ),
        ]

    def construct_parser(self):
        """Create parser for x86 Intel ISA."""
        # Numeric literal.
        binary_number = pp.Combine(
            pp.Word("01") + pp.CaselessLiteral("B")
        )
        octal_number = pp.Combine(
            pp.Word("01234567") + pp.CaselessLiteral("O")
        )
        decimal_number = pp.Combine(
            pp.Optional(pp.Literal("-")) + pp.Word(pp.nums)
        )
        hex_number = pp.Combine(
            pp.Word(pp.hexnums) + pp.CaselessLiteral("H")
        )
        float_number = pp.Combine(
            pp.Optional(pp.Literal("-")) + pp.Word(pp.nums) + pp.Word(".", pp.nums)
        ).setResultsName("value")
        integer_number = (
            binary_number ^ octal_number ^ decimal_number ^ hex_number
        ).setResultsName("value")

        # Comment.
        self.comment = pp.Literal(";") + pp.Group(
            pp.ZeroOrMore(pp.Word(pp.printables))
        ).setResultsName(self.comment_id)

        # Types.
        data_type = (
            pp.CaselessKeyword("BYTE")
            | pp.CaselessKeyword("DWORD")
            | pp.CaselessKeyword("FWORD")
            | pp.CaselessKeyword("MMWORD")
            | pp.CaselessKeyword("OWORD")
            | pp.CaselessKeyword("QWORD")
            | pp.CaselessKeyword("REAL10")
            | pp.CaselessKeyword("REAL4")
            | pp.CaselessKeyword("REAL8")
            | pp.CaselessKeyword("SBYTE")
            | pp.CaselessKeyword("SDWORD")
            | pp.CaselessKeyword("SQWORD")
            | pp.CaselessKeyword("SWORD")
            | pp.CaselessKeyword("TBYTE")
            | pp.CaselessKeyword("WORD")
            | pp.CaselessKeyword("XMMWORD")
            | pp.CaselessKeyword("YMMWORD")
        ).setResultsName("data_type")

        # Identifier.  Note that $ is not mentioned in the ASM386 Assembly Language Reference,
        # but it is mentioned in the MASM syntax
        first = pp.Word(pp.alphas + "$?@_", exact=1)
        rest = pp.Word(pp.alphanums + "$?@_")
        identifier = pp.Group(
            pp.Combine(first + pp.Optional(rest)).setResultsName("name")
        ).setResultsName("identifier")

        # Register.
        # This follows the MASM grammar.
        special_register = (
            pp.CaselessKeyword("CR0")
            | pp.CaselessKeyword("CR2")
            | pp.CaselessKeyword("CR3")
            | pp.CaselessKeyword("DR0")
            | pp.CaselessKeyword("DR1")
            | pp.CaselessKeyword("DR2")
            | pp.CaselessKeyword("DR3")
            | pp.CaselessKeyword("DR6")
            | pp.CaselessKeyword("DR7")
            | pp.CaselessKeyword("TR3")
            | pp.CaselessKeyword("TR4")
            | pp.CaselessKeyword("TR5")
            | pp.CaselessKeyword("TR6")
            | pp.CaselessKeyword("TR7")
        ).setResultsName("name")
        gp_register = (
            pp.CaselessKeyword("AX")
            | pp.CaselessKeyword("EAX")
            | pp.CaselessKeyword("CX")
            | pp.CaselessKeyword("ECX")
            | pp.CaselessKeyword("DX")
            | pp.CaselessKeyword("EDX")
            | pp.CaselessKeyword("BX")
            | pp.CaselessKeyword("EBX")
            | pp.CaselessKeyword("DI")
            | pp.CaselessKeyword("EDI")
            | pp.CaselessKeyword("SI")
            | pp.CaselessKeyword("ESI")
            | pp.CaselessKeyword("BP")
            | pp.CaselessKeyword("EBP")
            | pp.CaselessKeyword("SP")
            | pp.CaselessKeyword("ESP")
            | pp.CaselessKeyword("R8W")
            | pp.CaselessKeyword("R8D")
            | pp.CaselessKeyword("R9W")
            | pp.CaselessKeyword("R9D")
            | pp.CaselessKeyword("R12D")
            | pp.CaselessKeyword("R13W")
            | pp.CaselessKeyword("R13D")
            | pp.CaselessKeyword("R14W")
            | pp.CaselessKeyword("R14D")
        ).setResultsName("name")
        byte_register = (
            pp.CaselessKeyword("AL")
            | pp.CaselessKeyword("AH")
            | pp.CaselessKeyword("CL")
            | pp.CaselessKeyword("CH")
            | pp.CaselessKeyword("DL")
            | pp.CaselessKeyword("DH")
            | pp.CaselessKeyword("BL")
            | pp.CaselessKeyword("BH")
            | pp.CaselessKeyword("R8B")
            | pp.CaselessKeyword("R9B")
            | pp.CaselessKeyword("R10B")
            | pp.CaselessKeyword("R11B")
            | pp.CaselessKeyword("R12B")
            | pp.CaselessKeyword("R13B")
        ).setResultsName("name")
        qword_register = (
            pp.CaselessKeyword("RAX")
            | pp.CaselessKeyword("RCX")
            | pp.CaselessKeyword("RDX")
            | pp.CaselessKeyword("RBX")
            | pp.CaselessKeyword("RSP")
            | pp.CaselessKeyword("RBP")
            | pp.CaselessKeyword("RSI")
            | pp.CaselessKeyword("RDI")
            | pp.CaselessKeyword("R8")
            | pp.CaselessKeyword("R9")
            | pp.CaselessKeyword("R10")
            | pp.CaselessKeyword("R11")
            | pp.CaselessKeyword("R12")
            | pp.CaselessKeyword("R13")
            | pp.CaselessKeyword("R14")
            | pp.CaselessKeyword("R15")
        ).setResultsName("name")
        fpu_register = pp.Combine(
            pp.CaselessKeyword("ST")
            + pp.Optional(pp.Literal("(") + pp.Word("01234567") + pp.Literal(")"))
        ).setResultsName("name")
        xmm_register = (
            pp.Combine(pp.CaselessLiteral("XMM") + pp.Word(pp.nums))
            | pp.Combine(pp.CaselessLiteral("XMM1") + pp.Word("012345"))
        )
        simd_register = (
            pp.Combine(pp.CaselessLiteral("MM") + pp.Word("01234567"))
            | xmm_register
            | pp.Combine(pp.CaselessLiteral("YMM") + pp.Word(pp.nums))
            | pp.Combine(pp.CaselessLiteral("YMM1") + pp.Word("012345"))
        ).setResultsName("name")
        segment_register = (
            pp.CaselessKeyword("CS")
            | pp.CaselessKeyword("DS")
            | pp.CaselessKeyword("ES")
            | pp.CaselessKeyword("FS")
            | pp.CaselessKeyword("GS")
            | pp.CaselessKeyword("SS")
        ).setResultsName("name")
        self.register = pp.Group(
            special_register
            | gp_register
            | byte_register
            | qword_register
            | fpu_register
            | simd_register
            | segment_register
        ).setResultsName(self.register_id)

        # Register expressions.
        base_register = self.register
        index_register = self.register
        scale = pp.Word("1248", exact=1)
        displacement = pp.Group(integer_number | identifier).setResultsName(self.immediate_id)
        register_expression = pp.Group(
            pp.Literal("[")
            + pp.Optional(base_register.setResultsName("base"))
            + pp.Optional(
                pp.Literal("+")
                + index_register.setResultsName("index")
                + pp.Optional(pp.Literal("*") + scale.setResultsName("scale"))
            )
            + pp.Optional(
                pp.Literal("+")
                + pp.Group(displacement).setResultsName("displacement")
            )
            + pp.Literal("]")
        ).setResultsName("register_expression")

        # Immediate.
        immediate = pp.Group(
            integer_number | float_number | identifier
        ).setResultsName(self.immediate_id)

        # Expressions.
        # The ASM86 manual has weird expressions on page 130 (displacement outside of the register
        # expression, multiple register expressions).  Let's ignore those for now, but see
        # https://stackoverflow.com/questions/71540754/why-sometimes-use-offset-flatlabel-and-sometimes-not.
        address_expression = pp.Group(
            self.register.setResultsName("segment") + pp.Literal(":") + immediate
            ^ immediate + register_expression
            ^ register_expression
        ).setResultsName("address_expression")

        offset_expression = pp.Group(
            pp.CaselessKeyword("OFFSET")
            + pp.Group(
                pp.CaselessKeyword("GROUP")
                | pp.CaselessKeyword("SEGMENT")
                | pp.CaselessKeyword("FLAT")
            )
            # The MASM grammar has the ":" immediately after "OFFSET", but that's not what MSVC
            # outputs.
            + pp.Literal(":")
            + identifier
        ).setResultsName("offset_expression")
        ptr_expression = pp.Group(
            data_type + pp.CaselessKeyword("PTR") + address_expression
        ).setResultsName("ptr_expression")
        short_expression = pp.Group(
            pp.CaselessKeyword("SHORT") + identifier
        ).setResultsName("short_expression")

        # Instructions.
        mnemonic = pp.Word(
            pp.alphas, pp.alphanums
        ).setResultsName("mnemonic")
        operand = pp.Group(
            self.register
            | pp.Group(
                offset_expression
                | ptr_expression
                | short_expression
                | address_expression
            ).setResultsName(self.memory_id)
            | immediate
        )
        self.instruction_parser = (
            mnemonic
            + pp.Optional(operand.setResultsName("operand1"))
            + pp.Optional(pp.Suppress(pp.Literal(",")))
            + pp.Optional(operand.setResultsName("operand2"))
            + pp.Optional(pp.Suppress(pp.Literal(",")))
            + pp.Optional(operand.setResultsName("operand3"))
            + pp.Optional(pp.Suppress(pp.Literal(",")))
            + pp.Optional(operand.setResultsName("operand4"))
            + pp.Optional(self.comment)
        )

        # Label.
        self.label = pp.Group(
            identifier.setResultsName("name")
            + pp.Literal(":")
            + pp.Optional(self.instruction_parser)
        ).setResultsName(self.label_id)

        # Directives.
        # Parameter can be any quoted string or sequence of characters besides ';' (for comments)
        # or ',' (parameter delimiter).  See ASM386 p. 38.
        directive_parameter = (
            pp.quotedString
            ^ (
                pp.Word(pp.printables, excludeChars=",;")
                + pp.Optional(pp.Suppress(pp.Literal(",")))
            )
            ^ pp.Suppress(pp.Literal(","))
        )
        # The directives that don't start with a "." are ambiguous with instructions, so we list
        # them explicitly.
        # TODO: The directives that are types introduce a nasty ambiguity with instructions.  Skip
        # them for now, apparently the MSVC output uses the short D? directives.
        directive_keywords = (
            pp.CaselessKeyword("ALIAS")
            | pp.CaselessKeyword("ALIGN")
            | pp.CaselessKeyword("ASSUME")
            #| pp.CaselessKeyword("BYTE")
            | pp.CaselessKeyword("CATSTR")
            | pp.CaselessKeyword("COMM")
            | pp.CaselessKeyword("COMMENT")
            | pp.CaselessKeyword("DB")
            | pp.CaselessKeyword("DD")
            | pp.CaselessKeyword("DF")
            | pp.CaselessKeyword("DQ")
            | pp.CaselessKeyword("DT")
            | pp.CaselessKeyword("DW")
            #| pp.CaselessKeyword("DWORD")
            | pp.CaselessKeyword("ECHO")
            | pp.CaselessKeyword("END")
            | pp.CaselessKeyword("ENDP")
            | pp.CaselessKeyword("ENDS")
            | pp.CaselessKeyword("EQU")
            | pp.CaselessKeyword("EVEN")
            | pp.CaselessKeyword("EXTRN")
            | pp.CaselessKeyword("EXTERNDEF")
            #| pp.CaselessKeyword("FWORD")
            | pp.CaselessKeyword("GROUP")
            | pp.CaselessKeyword("INCLUDE")
            | pp.CaselessKeyword("INCLUDELIB")
            | pp.CaselessKeyword("INSTR")
            | pp.CaselessKeyword("INVOKE")
            | pp.CaselessKeyword("LABEL")
            #| pp.CaselessKeyword("MMWORD")
            | pp.CaselessKeyword("OPTION")
            | pp.CaselessKeyword("ORG")
            | pp.CaselessKeyword("PAGE")
            | pp.CaselessKeyword("POPCONTEXT")
            | pp.CaselessKeyword("PROC")
            | pp.CaselessKeyword("PROTO")
            | pp.CaselessKeyword("PUBLIC")
            | pp.CaselessKeyword("PUSHCONTEXT")
            #| pp.CaselessKeyword("QWORD")
            #| pp.CaselessKeyword("REAL10")
            #| pp.CaselessKeyword("REAL4")
            #| pp.CaselessKeyword("REAL8")
            | pp.CaselessKeyword("RECORD")
            #| pp.CaselessKeyword("SBYTE")
            #| pp.CaselessKeyword("SDWORD")
            | pp.CaselessKeyword("SEGMENT")
            | pp.CaselessKeyword("SIZESTR")
            | pp.CaselessKeyword("STRUCT")
            | pp.CaselessKeyword("SUBSTR")
            | pp.CaselessKeyword("SUBTITLE")
            #| pp.CaselessKeyword("SWORD")
            #| pp.CaselessKeyword("TBYTE")
            | pp.CaselessKeyword("TEXTEQU")
            | pp.CaselessKeyword("TITLE")
            | pp.CaselessKeyword("TYPEDEF")
            | pp.CaselessKeyword("UNION")
            #| pp.CaselessKeyword("WORD")
            #| pp.CaselessKeyword("XMMWORD")
            #| pp.CaselessKeyword("YMMWORD")
        )
        self.directive = pp.Group(
            pp.Optional(~directive_keywords + identifier)
            + (
                pp.Combine(pp.Literal(".") + pp.Word(pp.alphanums + "_"))
                | pp.Literal("=")
                | directive_keywords
            ).setResultsName("name")
            + pp.ZeroOrMore(directive_parameter).setResultsName("parameters")
            + pp.Optional(self.comment)
        ).setResultsName(self.directive_id)

    def parse_line(self, line, line_number=None):
        """
        Parse line and return instruction form.

        :param str line: line of assembly code
        :param line_number: default None, identifier of instruction form
        :type line_number: int, optional
        :return: ``dict`` -- parsed asm line (comment, label, directive or instruction form)
        """
        instruction_form = InstructionForm(line=line, line_number=line_number)
        result = None

        # 1. Parse comment.
        try:
            result = self.process_operand(self.comment.parseString(line, parseAll=True))
            instruction_form.comment = " ".join(result[self.comment_id])
        except pp.ParseException:
            pass

        # 2. Parse label.
        if not result:
            try:
                # Returns tuple with label operand and comment, if any.
                result = self.process_operand(self.label.parseString(line, parseAll=True))
                instruction_form.label = result[0].name
                if result[1]:
                    instruction_form.comment = " ".join(result[1])
            except pp.ParseException:
                pass

        # 3. Parse directive.
        if not result:
            try:
                # Returns tuple with directive operand and comment, if any.
                result = self.process_operand(self.directive.parseString(line, parseAll=True))
                instruction_form.directive = result[0]
                if result[1]:
                    instruction_form.comment = " ".join(result[1])
            except pp.ParseException:
                pass

        # 4. Parse instruction.
        if not result:
            try:
                result = self.parse_instruction(line)
            except pp.ParseException:
                raise ValueError(
                    "Could not parse instruction on line {}: {!r}".format(line_number, line)
                )
            instruction_form.mnemonic = result.mnemonic
            instruction_form.operands = result.operands
            instruction_form.comment = result.comment
        return instruction_form

    def make_instruction(self, parse_result):
        """
        Parse instruction in asm line.

        :param parse_result: tuple resulting from calling `parseString` on the `instruction_parser`.
        :returns: `dict` -- parsed instruction form
        """
        operands = []
        # Add operands to list
        # Check first operand
        if "operand1" in parse_result:
            operands.append(self.process_operand(parse_result.operand1))
        # Check second operand
        if "operand2" in parse_result:
            operands.append(self.process_operand(parse_result.operand2))
        # Check third operand
        if "operand3" in parse_result:
            operands.append(self.process_operand(parse_result.operand3))
        # Check fourth operand
        if "operand4" in parse_result:
            operands.append(self.process_operand(parse_result.operand4))
        return_dict = InstructionForm(
            mnemonic=parse_result.mnemonic,
            operands=operands,
            label_id=None,
            comment_id=" ".join(parse_result[self.comment_id])
                       if self.comment_id in parse_result else None,
        )

        return return_dict

    def parse_instruction(self, instruction):
        """
        Parse instruction in asm line.

        :param str instruction: Assembly line string.
        :returns: `dict` -- parsed instruction form
        """
        return self.make_instruction(
            self.instruction_parser.parseString(instruction, parseAll=True)
        )

    def parse_register(self, register_string):
        """Parse register string"""
        try:
            return self.process_operand(
                self.register.parseString(register_string, parseAll=True)
            )
        except pp.ParseException:
            return None

    def is_flag_dependend_of(self, flag_a, flag_b):
        """Check if ``flag_a`` is dependent on ``flag_b``"""
        # we assume flags are independent of each other, e.g., CF can be read while ZF gets written
        # TODO validate this assumption
        return flag_a.name == flag_b.name

    def is_reg_dependend_of(self, reg_a, reg_b):
        """Check if ``reg_a`` is dependent on ``reg_b``"""
        reg_a_name = reg_a.name.upper()
        reg_b_name = reg_b.name.upper()

        # Check if they are the same registers
        if reg_a_name == reg_b_name:
            return True
        # Check vector registers first
        if self.is_vector_register(reg_a):
            if self.is_vector_register(reg_b):
                if reg_a_name[1:] == reg_b_name[1:]:
                    # Registers in the same vector space
                    return True
            return False
        # Check basic GPRs
        gpr_groups = {
            "A": ["RAX", "EAX", "AX", "AH", "AL"],
            "B": ["RBX", "EBX", "BX", "BH", "BL"],
            "C": ["RCX", "ECX", "CX", "CH", "CL"],
            "D": ["RDX", "EDX", "DX", "DH", "DL"],
            "SP": ["RSP", "ESP", "SP", "SPL"],
            "SRC": ["RSI", "ESI", "SI", "SIL"],
            "DST": ["RDI", "EDI", "DI", "DIL"],
        }
        if self.is_basic_gpr(reg_a):
            if self.is_basic_gpr(reg_b):
                for dep_group in gpr_groups.values():
                    if reg_a_name in dep_group:
                        if reg_b_name in dep_group:
                            return True
            return False

        # Check other GPRs
        ma = re.match(r"R([0-9]+)[DWB]?", reg_a_name)
        mb = re.match(r"R([0-9]+)[DWB]?", reg_b_name)
        if ma and mb and ma.group(1) == mb.group(1):
            return True

        # No dependencies
        return False

    def is_basic_gpr(self, register):
        """Check if register is a basic general purpose register (ebi, rax, ...)"""
        if any(char.isdigit() for char in register.name) or any(
            register.name.lower().startswith(x) for x in ["mm", "xmm", "ymm", "zmm"]
        ):
            return False
        return True

    def is_gpr(self, register):
        """Check if register is a general purpose register"""
        if register is None:
            return False
        if self.is_basic_gpr(register):
            return True
        return re.match(r"R([0-9]+)[DWB]?", register.name, re.IGNORECASE)

    def is_vector_register(self, register):
        """Check if register is a vector register"""
        if register is None or register.name is None:
            return False
        if register.name.rstrip(string.digits).lower() in [
            "mm",
            "xmm",
            "ymm",
            "zmm",
        ]:
            return True
        return False

    def get_reg_type(self, register):
        """Get register type"""
        if register is None:
            return False
        if self.is_gpr(register):
            return "gpr"
        elif self.is_vector_register(register):
            return register.name.rstrip(string.digits).lower()
        raise ValueError

    def process_operand(self, operand):
        """Post-process operand"""
        if self.directive_id in operand:
            return self.process_directive(operand[self.directive_id])
        if self.identifier in operand:
            return self.process_identifier(operand[self.identifier])
        if self.immediate_id in operand:
            return self.process_immediate(operand[self.immediate_id])
        if self.label_id in operand:
            return self.process_label(operand[self.label_id])
        if self.memory_id in operand:
            return self.process_memory_address(operand[self.memory_id])
        if self.register_id in operand:
            return self.process_register(operand[self.register_id])
        return operand

    def process_directive(self, directive):
        # TODO: This is putting the identifier in the parameters.  No idea if it's right.
        parameters = [directive.identifier.name] if "identifier" in directive else []
        parameters.extend(directive.parameters)
        directive_new = DirectiveOperand(
            name=directive.name,
            parameters=parameters or None
        )
        # Interpret the "=" directives because the generated assembly is full of symbols that are
        # defined there.
        if directive.name == "=":
            self._equ[parameters[0]] = parameters[1]
        return directive_new, directive.get("comment")

    def process_register(self, operand):
        return RegisterOperand(name=operand.name)

    def process_register_expression(self, register_expression):
        displacement = register_expression.get("displacement")
        base = register_expression.get("base")
        index = register_expression.get("index")
        scale = int(register_expression.get("scale", "1"), 0)
        displacement_op = self.process_immediate(displacement.immediate) if displacement else None
        base_op = RegisterOperand(name=base.name) if base else None
        index_op = RegisterOperand(name=index.name) if index else None
        new_memory = MemoryOperand(offset=displacement_op, base=base_op, index=index_op, scale=scale)
        return new_memory

    def process_address_expression(self, address_expression):
        # TODO: It seems that we could have a prefix immediate operand, a displacement in the
        # brackets, and an offset.  How all of this works together is somewhat mysterious.
        immediate_operand = (
            self.process_immediate(address_expression.immediate)
            if "immediate" in address_expression else None
        )
        register_expression = (
            self.process_register_expression(address_expression.register_expression)
            if "register_expression" in address_expression else None
        )
        segment = (
            self.process_register(address_expression.segment)
            if "segment" in address_expression else None
        )
        if register_expression:
            if immediate_operand:
                register_expression.offset = immediate_operand
            return register_expression
        elif segment:
            return MemoryOperand(base=segment, offset=immediate_operand)
        else:
            return MemoryOperand(base=immediate_operand)

    def process_offset_expression(self, offset_expression):
        # TODO: Record that this is an offset expression.
        return MemoryOperand(base=self.process_identifier(offset_expression.identifier))

    def process_ptr_expression(self, ptr_expression):
        # TODO: Do something with the data_type.
        return self.process_address_expression(ptr_expression.address_expression)

    def process_short_expression(self, short_expression):
        # TODO: Do something with the fact that it is short.
        return LabelOperand(name=short_expression.identifier.name)

    def process_memory_address(self, memory_address):
        """Post-process memory address operand"""
        if "address_expression" in memory_address:
            return self.process_address_expression(memory_address.address_expression)
        elif "offset_expression" in memory_address:
            return self.process_offset_expression(memory_address.offset_expression)
        elif "ptr_expression" in memory_address:
            return self.process_ptr_expression(memory_address.ptr_expression)
        elif "short_expression" in memory_address:
            return self.process_short_expression(memory_address.short_expression)
        return memory_address

    def process_label(self, label):
        """Post-process label asm line"""
        # Remove duplicated 'name' level due to identifier.
        label["name"] = label["name"]["name"]
        return (LabelOperand(name=label.name),
                self.make_instruction(label) if "mnemonic" in label else None)

    def process_immediate(self, immediate):
        """Post-process immediate operand"""
        if "identifier" in immediate:
            # Actually an identifier, change declaration.
            return self.process_identifier(immediate.identifier)
        new_immediate = ImmediateOperand(value=immediate.value)
        new_immediate.value = self.normalize_imd(new_immediate)
        return new_immediate

    def process_identifier(self, identifier):
        if identifier.name in self._equ:
            # Actually an immediate, change declaration.
            new_immediate = ImmediateOperand(
                identifier=identifier.name,
                value=self._equ[identifier.name]
            )
            new_immediate.value = self.normalize_imd(new_immediate)
            return new_immediate
        return IdentifierOperand(name=identifier.name)

    def get_regular_source_operands(self, instruction_form):
        """Get source operand of given instruction form assuming regular src/dst behavior."""
        # if there is only one operand, assume it is a source operand
        if len(instruction_form.operands) == 1:
            return [instruction_form.operands[0]]
        return [op for op in instruction_form.operands[1:]]

    def get_regular_destination_operands(self, instruction_form):
        """Get destination operand of given instruction form assuming regular src/dst behavior."""
        # if there is only one operand, assume no destination
        if len(instruction_form.operands) == 1:
            return []
        # return first operand
        return instruction_form.operands[:1]

    def normalize_imd(self, imd):
        """Normalize immediate to decimal based representation"""
        if isinstance(imd.value, str):
            if '.' in imd.value:
                return float(imd.value)
            # Now parse depending on the base.
            base = {'B': 2, 'O': 8, 'H': 16}.get(imd.value[-1], 10)
            value = 0
            negative = imd.value[0] == '-'
            start = +negative
            stop = len(imd.value) if base == 10 else -1
            for c in imd.value[start:stop]:
                value = value * base + int(c, base)
            return -value if negative else value
        else:
            return imd.value

    def normalize_mnemonic(self, mnemonic):
        return mnemonic

