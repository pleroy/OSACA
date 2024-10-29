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

    def test_label_parser(self):
        self.assertEqual(self._get_label(self.parser, "main:")[0].name, "main")
        self.assertEqual(self._get_label(self.parser, "$$B1?10:")[0].name, "$$B1?10")
        self.assertEqual(
            self._get_label(self.parser, "$LN9:\tcall\t__CheckForDebuggerJustMyCode")[0].name,
            "$LN9"
        )
        self.assertEqual(
            self._get_label(self.parser, "$LN9:\tcall\t__CheckForDebuggerJustMyCode")[1],
            InstructionForm(
                mnemonic="call",
                operands=[
                    {"identifier": {"name": "__CheckForDebuggerJustMyCode"}},
                ],
                directive_id=None,
                comment_id=None,
                label_id=None,
                line=None,
                line_number=None,
            )
        )
        with self.assertRaises(ParseException):
            self._get_label(self.parser, "\t.cfi_startproc")

    def test_parse_instruction(self):
        instr1 = "\tsub\trsp, 296\t\t\t\t; 00000128H"
        instr2 = "  fst ST(3)\t; Good ol' x87."
        instr3 = "\tmulsd\txmm0, QWORD PTR [rdx+rcx*8]"
        instr4 = "\tmov\teax, DWORD PTR cur_elements$[rbp]"
        instr5 = "\tmov\tQWORD PTR [rsp+24], r8"

        parsed_1 = self.parser.parse_instruction(instr1)
        parsed_2 = self.parser.parse_instruction(instr2)
        parsed_3 = self.parser.parse_instruction(instr3)
        parsed_4 = self.parser.parse_instruction(instr4)
        parsed_5 = self.parser.parse_instruction(instr5)

        self.assertEqual(parsed_1.mnemonic, "sub")
        self.assertEqual(parsed_1.operands[0].name, "rsp")
        self.assertEqual(parsed_1.operands[1].value, 296)
        self.assertEqual(parsed_1.comment, "00000128H")

        self.assertEqual(parsed_2.mnemonic, "fst")
        self.assertEqual(parsed_2.operands[0].name, "ST(3)")
        self.assertEqual(parsed_2.comment, "Good ol' x87.")

        self.assertEqual(parsed_3.mnemonic, "mulsd")
        self.assertEqual(parsed_3.operands[0].name, "xmm0")
        self.assertEqual(parsed_3.operands[1].value, 296)

        self.assertEqual(parsed_4.mnemonic, "mov")
        self.assertEqual(parsed_4.operands[0].name, "eax")
        self.assertEqual(parsed_4.operands[1].value, 296)

        self.assertEqual(parsed_5.mnemonic, "mov")
        self.assertEqual(parsed_5.operands[0].name, "rsp")
        self.assertEqual(parsed_5.operands[1].name, "r8")

    def test_parse_line(self):
        line_comment = "; -- Begin  main"
        line_instruction = "\tret\t0"

        instruction_form_1 = InstructionForm(
            mnemonic=None,
            operands=[],
            directive_id=None,
            comment_id="-- Begin main",
            label_id=None,
            line="; -- Begin  main",
            line_number=1,
        )
        instruction_form_2 = InstructionForm(
            mnemonic="ret",
            operands=[
                {"immediate": {"value": 0}},
            ],
            directive_id=None,
            comment_id=None,
            label_id=None,
            line="\tret\t0",
            line_number=2,
        )

        parsed_1 = self.parser.parse_line(line_comment, 1)
        parsed_2 = self.parser.parse_line(line_instruction, 2)

        self.assertEqual(parsed_1, instruction_form_1)
        self.assertEqual(parsed_2, instruction_form_2)

    def test_parse_register(self):
        register_str_1 = "rax"
        register_str_2 = "r9"
        register_str_3 = "xmm1"
        register_str_4 = "ST(4)"

        parsed_reg_1 = RegisterOperand(name="rax")
        parsed_reg_2 = RegisterOperand(name="r9")
        parsed_reg_3 = RegisterOperand(name="xmm1")
        parsed_reg_4 = RegisterOperand(name="ST(4)")

        self.assertEqual(self.parser.parse_register(register_str_1), parsed_reg_1)
        self.assertEqual(self.parser.parse_register(register_str_2), parsed_reg_2)
        self.assertEqual(self.parser.parse_register(register_str_3), parsed_reg_3)
        self.assertEqual(self.parser.parse_register(register_str_4), parsed_reg_4)
        self.assertIsNone(self.parser.parse_register("foo"))

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

    def _get_label(self, parser, label):
        return parser.process_operand(parser.label.parseString(label, parseAll=True).asDict())

    @staticmethod
    def _find_file(name):
        testdir = os.path.dirname(__file__)
        name = os.path.join(testdir, "test_files", name)
        assert os.path.exists(name)
        return name


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestParserX86Intel)
    unittest.TextTestRunner(verbosity=2).run(suite)
