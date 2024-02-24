"""
Collection of parsers supported by OSACA.

Only the parser below will be exported, so please add new parsers to __all__.
"""
from .base_parser import BaseParser
from .parser_x86att import ParserX86ATT
from .parser_AArch64 import ParserAArch64
from .instruction_form import InstructionForm
from .operand import Operand

__all__ = [
    "Operand",
    "InstructionForm",
    "BaseParser",
    "ParserX86ATT",
    "ParserAArch64",
    "get_parser",
]


def get_parser(isa):
    if isa.lower() == "x86":
        return ParserX86ATT()
    elif isa.lower() == "aarch64":
        return ParserAArch64()
    else:
        raise ValueError("Unknown ISA {!r}.".format(isa))
