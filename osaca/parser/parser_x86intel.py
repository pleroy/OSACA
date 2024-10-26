#!/usr/bin/env python3

from osaca.parser import BaseParser

class ParserX86Intel(BaseParser):
    _instance = None

    # Singleton pattern, as this is created very many times
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ParserX86Intel, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        super().__init__()
        self.isa = "x86"
