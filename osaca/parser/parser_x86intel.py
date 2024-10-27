#!/usr/bin/env python3

import pyparsing as pp

from osaca.parser import BaseParser
from osaca.parser.instruction_form import InstructionForm
from osaca.parser.identifier import IdentifierOperand

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
            pp.Optional(pp.Literal("-")) + pp.Word(pp.nums) +
            pp.Optional(pp.Word(".", pp.nums))
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

    def process_operand(self, operand):
        """Post-process operand"""
        return operand

    def normalize_imd(self, imd):
        """Normalize immediate to decimal based representation"""
        if isinstance(imd, IdentifierOperand):
            return imd
        if imd.value is not None:
            if isinstance(imd.value, str):
                if '.' in imd.value:
                    return float(imd.value)
                # Now parse depending on the base.
                base = 10
                if imd.value[-1] == 'B':
                    base = 2
                elif imd.value[-1] == 'O':
                    base = 8
                elif imd.value[-1] == 'H':
                    base = 16
                value = 0
                for c in imd.value[:-1]:
                    value = value * base + int(c, base)
                return value
            else:
                return imd.value
        # identifier
        return imd

