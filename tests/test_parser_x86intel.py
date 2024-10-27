#!/usr/bin/env python3
"""
Unit tests for x86 Intel assembly parser
"""

import os
import unittest

from pyparsing import ParseException

from osaca.parser import ParserX86Intel, InstructionForm
from osaca.parser.register import RegisterOperand
from osaca.parser.immediate import ImmediateOperand


class TestParserX86Intel(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.parser = ParserX86Intel()
        with open(self._find_file("triad_x86_intel.asm")) as f:
            self.triad_code = f.read()

    ##################
    # Test
    ##################

    def test_comment_parser(self):
        self.assertEqual(self._get_comment(self.parser, "; some comments"), "some comments")
        self.assertEqual(self._get_comment(self.parser, "\t\t;AA BB CC \t end \t"), "AA BB CC end")
        self.assertEqual(
            self._get_comment(self.parser, "\t;; comment ;; comment"),
            "; comment ;; comment",
        )

    def test_normalize_imd(self):
        imd_binary = ImmediateOperand(value="1001111B")
        imd_octal = ImmediateOperand(value="117O")
        imd_decimal = ImmediateOperand(value="79")
        imd_hex = ImmediateOperand(value="4fH")
        imd_float = ImmediateOperand(value="-79.34")
        self.assertEqual(
            self.parser.normalize_imd(imd_binary),
            self.parser.normalize_imd(imd_octal),
        )
        self.assertEqual(
            self.parser.normalize_imd(imd_octal),
            self.parser.normalize_imd(imd_decimal),
        )
        self.assertEqual(
            self.parser.normalize_imd(imd_decimal),
            self.parser.normalize_imd(imd_hex),
        )
        self.assertEqual(self.parser.normalize_imd(ImmediateOperand(value="-79")), -79)
        self.assertEqual(self.parser.normalize_imd(imd_float), -79.34)

    ##################
    # Helper functions
    ##################
    def _get_comment(self, parser, comment):
        return " ".join(
            parser.process_operand(parser.comment.parseString(comment, parseAll=True).asDict())[
                "comment"
            ]
        )

    @staticmethod
    def _find_file(name):
        testdir = os.path.dirname(__file__)
        name = os.path.join(testdir, "test_files", name)
        assert os.path.exists(name)
        return name


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestParserX86Intel)
    unittest.TextTestRunner(verbosity=2).run(suite)
