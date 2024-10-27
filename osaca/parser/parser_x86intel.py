#!/usr/bin/env python3

import pyparsing as pp

from osaca.parser import BaseParser
from osaca.parser.instruction_form import InstructionForm
from osaca.parser.identifier import IdentifierOperand
from osaca.parser.immediate import ImmediateOperand
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
        ).setResultsName("value")
        octal_number = pp.Combine(
            pp.Word("01234567") + pp.Literal("O")
        ).setResultsName("value")
        decimal_number = pp.Combine(
            pp.Optional(pp.Literal("-")) + pp.Word(pp.nums)
        ).setResultsName("value")
        hex_number = pp.Combine(
            pp.Word(pp.hexnums) + pp.Literal("H")
        ).setResultsName("value")
        float_number = pp.Combine(
            pp.Optional(pp.Literal("-")) + pp.Word(pp.nums) + pp.Word(".", pp.nums)
        ).setResultsName("value")

        # Comment.
        self.comment = pp.Literal(";") + pp.Group(
            pp.ZeroOrMore(pp.Word(pp.printables))
        ).setResultsName(self.comment_id)

        # Register.
        self.register = pp.Group(
            pp.Word(pp.alphas, pp.alphanums).setResultsName("name")
        ).setResultsName(self.register_id)

        # Immediate.
        immediate = pp.Group(
            (binary_number | octal_number | decimal_number | hex_number | float_number)
        ).setResultsName(self.immediate_id)

        # Instructions.
        mnemonic = pp.Word(
            pp.alphas, pp.alphanums
        ).setResultsName("mnemonic")
        operand_first = pp.Group(
            self.register ^ immediate
        )
        operand_rest = pp.Group(
            self.register ^ immediate
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
            result = self.process_operand(self.comment.parseString(line, parseAll=True).asDict())
            instruction_form.comment = " ".join(result[self.comment_id])
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

    def parse_instruction(self, instruction):
        """
        Parse instruction in asm line.

        :param str instruction: Assembly line string.
        :returns: `dict` -- parsed instruction form
        """
        result = self.instruction_parser.parseString(instruction, parseAll=True).asDict()
        operands = []
        # Add operands to list
        # Check first operand
        if "operand1" in result:
            operands.append(self.process_operand(result["operand1"]))
        # Check second operand
        if "operand2" in result:
            operands.append(self.process_operand(result["operand2"]))
        # Check third operand
        if "operand3" in result:
            operands.append(self.process_operand(result["operand3"]))
        # Check fourth operand
        if "operand4" in result:
            operands.append(self.process_operand(result["operand4"]))
        return_dict = InstructionForm(
            mnemonic=result["mnemonic"].split(",")[0],
            operands=operands,
            comment_id=" ".join(result[self.comment_id]) if self.comment_id in result else None,
        )

        return return_dict

    def process_operand(self, operand):
        """Post-process operand"""
        if self.immediate_id in operand:
            return self.process_immediate(operand[self.immediate_id])
        if self.register_id in operand:
            return self.process_register(operand[self.register_id])
        return operand

    def process_register(self, operand):
        return RegisterOperand(
            name=operand["name"],
        )

    def process_immediate(self, immediate):
        """Post-process immediate operand"""
        new_immediate = ImmediateOperand(value=immediate["value"])
        new_immediate.value = self.normalize_imd(new_immediate)
        return new_immediate

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
