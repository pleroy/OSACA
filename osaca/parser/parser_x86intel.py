#!/usr/bin/env python3

import pyparsing as pp

from osaca.parser import BaseParser
from osaca.parser.instruction_form import InstructionForm
from osaca.parser.identifier import IdentifierOperand
from osaca.parser.immediate import ImmediateOperand
from osaca.parser.label import LabelOperand
from osaca.parser.memory import MemoryOperand
from osaca.parser.register import RegisterOperand

class ParserX86Intel(BaseParser):
    _instance = None

    # Singleton pattern, as this is created very many times.
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ParserX86Intel, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        super().__init__()
        self.isa = "x86"

    def construct_parser(self):
        """Create parser for x86 Intel ISA."""
        # Numeric literal.
        binary_number = pp.Combine(
            pp.Word("01") + pp.Literal("B")
        )
        octal_number = pp.Combine(
            pp.Word("01234567") + pp.Literal("O")
        )
        decimal_number = pp.Combine(
            pp.Optional(pp.Literal("-")) + pp.Word(pp.nums)
        )
        hex_number = pp.Combine(
            pp.Word(pp.hexnums) + pp.Literal("H")
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

        # Identifier.  Note that $ is not mentioned in the ASM386 Assembly Language Reference,
        # but it is mentioned in the MASM syntax:
        # https://learn.microsoft.com/en-us/cpp/assembler/masm/masm-bnf-grammar?view=msvc-170.
        first = pp.Word(pp.alphas + "$?@_", exact=1)
        rest = pp.Word(pp.alphanums + "$?@_")
        identifier = pp.Group(
            pp.Combine(first + pp.Optional(rest)).setResultsName("name")
        ).setResultsName("identifier")

        # Register.
        self.register = pp.Group(
            pp.Combine(
                pp.Literal("ST(") + pp.Word("01234567") + pp.Literal(")")
            ).setResultsName("name") |
            pp.Word(pp.alphas, pp.alphanums).setResultsName("name")
        ).setResultsName(self.register_id)

        # Register expressions.
        base_register = self.register
        index_register = self.register
        scale = pp.Word("1248", exact=1)
        displacement = pp.Group(integer_number | identifier).setResultsName(self.immediate_id)
        register_expression = pp.Group(
            # The assembly produced by MSVC appears to have the displacement first, just like in the
            # AT&T syntax, even though the Intel syntax wants it within the brackets.  Better allow
            # both.  Note that "displacement" is the Intel terminology, AT&T uses "offset".
            pp.Optional(
                pp.Group(displacement).setResultsName("displacement1")
            ) +
            pp.Literal("[") +
            pp.Optional(base_register.setResultsName("base")) +
            pp.Optional(
                pp.Literal("+") +
                index_register.setResultsName("index") +
                pp.Optional(pp.Literal("*") + scale.setResultsName("scale"))
            ) +
            pp.Optional(
                pp.Literal("+") +
                pp.Group(displacement).setResultsName("displacement2")
            ) +
            pp.Literal("]")
        ).setResultsName("register_expression")

        # Types.
        ptr_type = pp.Group(
            (
                pp.Literal("BIT") ^
                pp.Literal("BYTE") ^
                pp.Literal("WORD") ^
                pp.Literal("DWORD") ^
                pp.Literal("PWORD") ^
                pp.Literal("QWORD") ^
                pp.Literal("TBYTE") ^
                pp.Literal("NEAR") ^
                pp.Literal("FAR")
            ) +
            pp.Literal("PTR")
        ).setResultsName("ptr_type")

        # Memory reference.
        memory = pp.Group(
            ptr_type + register_expression
        ).setResultsName(self.memory_id)

        # Immediate.
        # TODO: Support complex expressions?
        immediate = pp.Group(
            integer_number ^ float_number ^ identifier
        ).setResultsName(self.immediate_id)

        # Instructions.
        mnemonic = pp.Word(
            pp.alphas, pp.alphanums
        ).setResultsName("mnemonic")
        operand_first = pp.Group(
            memory ^ self.register ^ immediate ^ identifier
        )
        operand_rest = pp.Group(
            memory ^ self.register ^ immediate ^ identifier
        )
        self.instruction_parser = (
            mnemonic
            + pp.Optional(operand_first.setResultsName("operand1"))
            + pp.Optional(pp.Suppress(pp.Literal(",")))
            + pp.Optional(operand_rest.setResultsName("operand2"))
            + pp.Optional(pp.Suppress(pp.Literal(",")))
            + pp.Optional(operand_rest.setResultsName("operand3"))
            + pp.Optional(pp.Suppress(pp.Literal(",")))
            + pp.Optional(operand_rest.setResultsName("operand4"))
            + pp.Optional(self.comment)
        )

        # Label.
        self.label = pp.Group(
            identifier.setResultsName("name")
            + pp.Literal(":")
            + pp.Optional(self.instruction_parser)
        ).setResultsName(self.label_id)

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

        # 1. Parse comment
        try:
            result = self.process_operand(self.comment.parseString(line, parseAll=True))
            instruction_form.comment = " ".join(result[self.comment_id])
        except pp.ParseException:
            pass

        # 2. Parse label
        if not result:
            try:
                # returns tuple with label operand and comment, if any
                result = self.process_operand(self.label.parseString(line, parseAll=True))
                instruction_form.label = result[0].name
                if result[1] is not None:
                    instruction_form.comment = " ".join(result[1])
            except pp.ParseException:
                pass

        # 4. Parse instruction
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

    def process_operand(self, operand):
        """Post-process operand"""
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

    def process_register(self, operand):
        return RegisterOperand(name=operand.name)

    def process_memory_address(self, memory_address):
        """Post-process memory address operand"""
        # TODO: Use the ptr type.
        ptr_type = memory_address.ptr_type
        register_expression = memory_address.register_expression
        displacement = register_expression.get(
            "displacement1",
            register_expression.get("displacement2")
        )
        base = register_expression.get("base")
        index = register_expression.get("index")
        scale = int(register_expression.get("scale", "1"), 0)
        displacement_op = self.process_immediate(displacement.immediate) if displacement else None
        base_op = RegisterOperand(name=base.name) if base else None
        index_op = RegisterOperand(name=index.name) if index else None
        new_dict = MemoryOperand(offset=displacement_op, base=base_op, index=index_op, scale=scale)
        # Add segmentation extension if existing
        if self.segment_ext in memory_address:
            new_dict.segment_ext = memory_address[self.segment_ext]
        return new_dict

    def process_label(self, label):
        """Post-process label asm line"""
        # Remove duplicated 'name' level due to identifier.
        label["name"] = label["name"]["name"]
        return (LabelOperand(name=label.name),
                self.make_instruction(label) if "mnemonic" in label else None)

    def process_immediate(self, immediate):
        """Post-process immediate operand"""
        if "identifier" in immediate:
            # actually an identifier, change declaration
            return self.process_identifier(immediate.identifier)
        new_immediate = ImmediateOperand(value=immediate.value)
        new_immediate.value = self.normalize_imd(new_immediate)
        return new_immediate

    def process_identifier(self, identifier):
        return IdentifierOperand(name=identifier.name)

    def normalize_imd(self, imd):
        """Normalize immediate to decimal based representation"""
        if isinstance(imd, IdentifierOperand):
            return imd
        if imd.value is not None:
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
        # identifier
        return imd
