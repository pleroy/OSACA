"""
Collection of parsers supported by OSACA.

Only the parser below will be exported, so please add new parsers to __all__.
"""
from .attr_dict import AttrDict
from .base_parser import BaseParser
from .parser_x86att import ParserX86ATT
from .parser_AArch64v81 import ParserAArch64v81

__all__ = ['AttrDict', 'BaseParser', 'ParserX86ATT', 'ParserAArch64v81']
