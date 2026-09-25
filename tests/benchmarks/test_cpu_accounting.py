import unittest
from unittest import mock
import run
class ProcessCPU(unittest.TestCase):
    def test_user_and_system_exclude_children_and_parse_comm(self):
        # fields 3..15: state, ten intervening fields, utime, stime;
        # cutime/cstime afterwards must not contribute.
        stat = '123 (worker ) name) S ' + ' '.join(['0']*10 + ['120','30','9999','9999'])
        with mock.patch.object(run.platform, 'system', return_value='Linux'), \
             mock.patch.object(run.Path, 'read_text', return_value=stat), \
             mock.patch.object(run.os, 'sysconf', return_value=100):
            self.assertEqual(run.process_cpu_seconds(123), 1.5)
    def test_unavailable_is_not_zero(self):
        with mock.patch.object(run.platform, 'system', return_value='Darwin'):
            self.assertIsNone(run.process_cpu_seconds(123))
