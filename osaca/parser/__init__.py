"""
Collection of parsers supported by OSACA.

Only the parsers below will be exported, so please add new parsers to __all__.
"""

from .base_parser import BaseParser
from .parser_x86att import ParserX86ATT
from .parser_x86intel import ParserX86Intel
from .parser_AArch64 import ParserAArch64
from .instruction_form import InstructionForm
from .operand import Operand

__all__ = [
    "Operand",
    "InstructionForm",
    "BaseParser",
    "ParserX86ATT",
    "ParserX86Intel",
    "ParserAArch64",
    "get_parser",
]


def get_parser(isa, dialect):
    if isa.lower() == "x86":
        return ParserX86ATT() if dialect == "ATT" else ParserX86Intel()
    elif isa.lower() == "aarch64":
        return ParserAArch64()
    else:
        raise ValueError("Unknown ISA {!r}.".format(isa))
