# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
# SPDX-License-Identifier: GPL-2.0-or-later

"""Replay recall verification without mounts, remote clients, or root access."""

import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from packet.pktt import Pktt
from nfstest.nfs_util import NFSUtil

namespace = {'__name__': 'delegation_under_test'}
# The legacy executable has an unconditional CLI entry point. Load its
# definitions without constructing the command-line runner.
source = (Path(__file__).resolve().parents[1] / 'test/nfstest_delegation').read_text()
assert '# Entry point' in source
exec(compile(source.split('# Entry point')[0], 'nfstest_delegation', 'exec'), namespace)
DelegTest = namespace['DelegTest']

u = lambda *v: struct.pack('!' + 'I' * len(v), *v)
q = lambda v: struct.pack('!Q', v)
opaque = lambda v: u(len(v)) + v + b'\0' * (-len(v) % 4)
stateid = lambda v: u(1) + v
OPEN, DELEG, LOCK = b'O' * 12, b'D' * 12, b'L' * 12

def call(xid, program, version, payload):
    return u(xid, 0, 2, program, version, 1, 0, 0, 0, 0) + payload

def reply(xid, payload):
    return u(xid, 1, 0, 0, 0, 0) + payload

def trace(path, order):
    messages = {
        'conflict': (False, call(10, 100003, 4, u(0, 1, 1, 9, 0))),
        'recall': (True, call(0, 0x40000001, 1, u(0, 1, 0, 1, 4) + stateid(DELEG) + u(0) + opaque(b'fh'))),
        'ack': (False, reply(0, u(0, 0, 1, 4, 0))),
        'lock': (False, call(1, 100003, 4, u(0, 1, 2, 22) + opaque(b'fh') + u(12, 2, 0) + q(0) + q(100) + u(1, 0) + stateid(OPEN) + u(0) + q(1) + opaque(b'owner'))),
        'locked': (True, reply(1, u(0, 0, 2, 22, 0, 12, 0) + stateid(LOCK))),
        'return': (False, call(2, 100003, 4, u(0, 1, 2, 22) + opaque(b'fh') + u(8) + stateid(DELEG))),
        'returned': (True, reply(2, u(0, 0, 2, 22, 0, 8, 0))),
    }
    seq = {True: 100, False: 200}
    capture = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for index, key in enumerate(['conflict', 'recall'] + order):
        server, payload = messages[key]
        payload = u(0x80000000 | len(payload)) + payload
        src, dst = ('10.0.0.1', '10.0.0.2') if server else ('10.0.0.2', '10.0.0.1')
        sport, dport = (2049, 800) if server else (800, 2049)
        tcp = struct.pack('!HHIIBBHHH', sport, dport, seq[server], 1, 0x50, 0x18, 65535, 0, 0) + payload
        seq[server] += len(payload)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
        frame = b'\0' * 12 + b'\x08\0' + ip + tcp
        capture += struct.pack('<IIII', index, 0, len(frame), len(frame)) + frame
    path.write_bytes(capture)

class Replay(DelegTest):
    # Use the real recall verifier, packet decoder, OPEN search, and LOCK
    # checks. Only filesystem/client activity and unrelated I/O are stubbed.
    def __init__(self, path):
        self.clientobj = NS(nfs_version=4.1, ipaddr='10.0.0.3', proto='tcp', port=2049, umount=lambda: None)
        self.server_ipaddr, self.client_ipaddr = '10.0.0.1', '10.0.0.2'
        self.proto, self.port, self.nfs_version = 'tcp', 2049, 4.1
        self.absfile, self.filename, self.basename = '/unused', 'file', 'replay'
        self.PAGESIZE, self.lock_offset, self.lock_len = 4096, 0, 100
        self.layout, self.test_counts = None, [4096]
        self.errors, self.io = [], []
        noop = lambda *a, **kw: None
        for method in ('test_group', 'setup_test', 'dprint', 'lock_file', 'umount', 'trace_stop', 'set_nfserr_list', 'verify_open', 'find_layoutget', 'verify_close'):
            setattr(self, method, noop)
        self.trace_open = lambda: setattr(self, 'pktt', Pktt(str(path)))
        self.find_getdeviceinfo = lambda: (None, None, None)
        self.verify_io_requests = lambda *a, **kw: 0
        self.verify_io_packets = lambda *a, **kw: self.io.append(a)
        self.get_conflict_pkts = lambda *a: (NS(record=NS(index=0)), NS(NFSop=NS(delegation=NS(deleg_type=0))))
        self.open_count = 0

    def __del__(self):
        pass

    def test(self, value, message, **kw):
        if not value:
            self.errors.append(message)

    def find_open(self, **kw):
        self.open_count += 1
        if self.open_count == 1:
            return None, None, None
        if self.open_count == 2:
            self.openreply = NS(NFSop=NS(stateid=NS(seqid=1, other=OPEN)))
            return b'fh', OPEN, DELEG
        return NFSUtil.find_open(self, **kw)

class RecallWindow(unittest.TestCase):
    def test_callback_reply_orders(self):
        orders = [
            ['ack', 'lock', 'locked', 'return', 'returned'],
            ['lock', 'ack', 'locked', 'return', 'returned'],
            ['lock', 'locked', 'return', 'returned', 'ack'],
        ]
        for order in orders:
            with self.subTest(order=order), tempfile.TemporaryDirectory() as d:
                path = Path(d) / 'trace.pcap'
                trace(path, order)
                test = Replay(path)
                with patch.object(os, 'open', return_value=0):
                    test.recall_deleg_test(namespace['OPEN_WRITE'], lock=True)
                self.assertEqual(test.errors, [])
                self.assertEqual(test.io[0][2:4], (namespace['LOCK_STID'], LOCK))

    def test_missing_or_late_lock_still_fails(self):
        orders = [
            ['ack', 'return', 'returned'],
            ['ack', 'return', 'returned', 'lock', 'locked'],
        ]
        for order in orders:
            with self.subTest(order=order), tempfile.TemporaryDirectory() as d:
                path = Path(d) / 'trace.pcap'
                trace(path, order)
                test = Replay(path)
                with patch.object(os, 'open', return_value=0):
                    test.recall_deleg_test(namespace['OPEN_WRITE'], lock=True)
                self.assertIn('LOCK should be sent before returning the WRITE delegation', test.errors)

if __name__ == '__main__':
    unittest.main()
