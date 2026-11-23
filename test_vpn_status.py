import unittest

from vpn_status import Progress, encode_stage


class StatusTests(unittest.TestCase):
    def test_only_fixed_complete_frames_can_change_stage(self):
        progress = Progress()
        self.assertEqual(progress.stage, 'launch')
        progress.feed(b'SP-VPN/1 vault')
        self.assertEqual(progress.stage, 'launch')
        progress.feed(b'\n')
        self.assertEqual(progress.stage, 'vault')
        for bad in (b'password=synthetic-value\n', b'SP-VPN/1 arbitrary-secret\n',
                    b'SP-VPN/1 ready trailing-data\n', b'prefix SP-VPN/1 ready\n',
                    b'\xffSP-VPN/1 ready\n'):
            progress.feed(bad)
            self.assertEqual(progress.stage, 'vault')
        progress.feed(encode_stage('full-tunnel-required'))
        self.assertEqual(progress.stage, 'full-tunnel-required')

    def test_oversized_line_cannot_smuggle_a_suffix_frame(self):
        for length in (65, 130, 100000):
            with self.subTest(length=length):
                progress = Progress()
                progress.feed(b'x' * length + encode_stage('ready'))
                self.assertEqual(progress.stage, 'launch')
                self.assertLessEqual(len(progress.pending), 64)
                progress.feed(encode_stage('negotiating'))
                self.assertEqual(progress.stage, 'negotiating')

    def test_encoder_rejects_unknown_or_injected_values(self):
        for value in ('credential-value', 'ready\nSP-VPN/1 vault', '', None):
            with self.assertRaises(ValueError):
                encode_stage(value)

    def test_chunk_boundaries_do_not_change_parsing(self):
        data = encode_stage('bootstrap') + encode_stage('peer-resolution')
        for size in range(1, len(data) + 1):
            progress = Progress()
            for offset in range(0, len(data), size):
                progress.feed(data[offset:offset+size])
            self.assertEqual(progress.stage, 'peer-resolution')
