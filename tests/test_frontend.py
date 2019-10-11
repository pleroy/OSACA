#!/usr/bin/env python3
"""
Unit tests for OSACA Frontend
"""

import os
import unittest

from osaca.frontend import Frontend
from osaca.parser import ParserAArch64v81, ParserX86ATT
from osaca.semantics.hw_model import MachineModel
from osaca.semantics.kernel_dg import KernelDG
from osaca.semantics.semantics_appender import SemanticsAppender


class TestFrontend(unittest.TestCase):
    MODULE_DATA_DIR = os.path.join(
        os.path.dirname(os.path.split(os.path.abspath(__file__))[0]), 'osaca/data/'
    )

    @classmethod
    def setUpClass(self):
        # set up parser and kernels
        self.parser_x86 = ParserX86ATT()
        self.parser_AArch64 = ParserAArch64v81()
        with open(self._find_file('kernel-x86.s')) as f:
            code_x86 = f.read()
        with open(self._find_file('kernel-AArch64.s')) as f:
            code_AArch64 = f.read()
        self.kernel_x86 = self.parser_x86.parse_file(code_x86)
        self.kernel_AArch64 = self.parser_AArch64.parse_file(code_AArch64)

        # set up machine models
        self.machine_model_csx = MachineModel(
            path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'csx.yml')
        )
        self.machine_model_tx2 = MachineModel(
            path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'vulcan.yml')
        )
        self.semantics_csx = SemanticsAppender(
            self.machine_model_csx, path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'isa/x86.yml')
        )
        self.semantics_tx2 = SemanticsAppender(
            self.machine_model_tx2,
            path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'isa/aarch64.yml'),
        )
        for i in range(len(self.kernel_x86)):
            self.semantics_csx.assign_src_dst(self.kernel_x86[i])
            self.semantics_csx.assign_tp_lt(self.kernel_x86[i])
        for i in range(len(self.kernel_AArch64)):
            self.semantics_tx2.assign_src_dst(self.kernel_AArch64[i])
            self.semantics_tx2.assign_tp_lt(self.kernel_AArch64[i])

    ###########
    # Tests
    ###########

    def test_frontend_creation(self):
        with self.assertRaises(ValueError):
            Frontend()
        with self.assertRaises(ValueError):
            Frontend(arch='csx', path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'csx.yml'))
        with self.assertRaises(FileNotFoundError):
            Frontend(path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'THE_MACHINE.yml'))
        with self.assertRaises(FileNotFoundError):
            Frontend(arch='THE_MACHINE')
        Frontend(arch='zen1')

    def test_frontend_x86(self):
        dg = KernelDG(self.kernel_x86, self.parser_x86, self.machine_model_csx)
        fe = Frontend(path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'csx.yml'))
        fe.print_throughput_analysis(self.kernel_x86, show_cmnts=False)
        fe.print_latency_analysis(dg.get_critical_path())

    def test_frontend_AArch64(self):
        dg = KernelDG(self.kernel_AArch64, self.parser_AArch64, self.machine_model_tx2)
        fe = Frontend(path_to_yaml=os.path.join(self.MODULE_DATA_DIR, 'vulcan.yml'))
        fe.print_full_analysis(self.kernel_AArch64, dg, verbose=True)

    ##################
    # Helper functions
    ##################

    @staticmethod
    def _find_file(name):
        testdir = os.path.dirname(__file__)
        name = os.path.join(testdir, 'test_files', name)
        assert os.path.exists(name)
        return name


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestFrontend)
    unittest.TextTestRunner(verbosity=2).run(suite)
