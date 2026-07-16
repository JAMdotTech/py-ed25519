# Python ED25519 Bindings
#
# Copyright 2018-2020 Stichting Polkascan (Polkascan Foundation).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
import sys
import sysconfig
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

import ed25519_zebra


TEST_SEED = bytes.fromhex(
    "31625bbf7c317c00d063f829c483c360737fab5210cdbb2d14c328165b15d180",
)


def exercise_crypto_concurrently(barrier, seed, worker_id):
    barrier.wait()
    private_key, public_key = ed25519_zebra.ed_from_seed(seed)
    derived_public_key = ed25519_zebra.ed_public_from_secret(private_key)

    for iteration in range(100):
        message = f"worker-{worker_id}-iteration-{iteration}".encode()
        signature = ed25519_zebra.ed_sign(private_key, message)
        if not ed25519_zebra.ed_verify(signature, message, public_key):
            return False

    return public_key == derived_public_key


class MyTestCase(unittest.TestCase):
    def test_sign_and_verify_message(self):

        message = b"test"

        # Get private and public key from seed
        private_key, public_key = ed25519_zebra.ed_from_seed(TEST_SEED)

        # Generate signature
        signature = ed25519_zebra.ed_sign(private_key, message)

        # Verify message with signature
        self.assertTrue(ed25519_zebra.ed_verify(signature, message, public_key))

    def test_verify_signature(self):
        public_key = bytes.fromhex('fd8c9f401e9b5db50685be590b4f8e5a10d4abfef9a532ee903f125fd11f129c')

        signature = bytes.fromhex('33185bf9e8f6b354751ef7c7a7c692b3d51d5096e52c4c08e8b307f804d025f3'
                                  'f14a060b8c1ad11f92fe0be4cae2c620d86d6012f90d071fb8dbadac2774df02')

        # Verify message with signature
        self.assertTrue(ed25519_zebra.ed_verify(signature, b"test", public_key))

    def test_verify_invalid_public_key(self):
        public_key = bytes(1)

        signature = bytes.fromhex('33185bf9e8f6b354751ef7c7a7c692b3d51d5096e52c4c08e8b307f804d025f3'
                                  'f14a060b8c1ad11f92fe0be4cae2c620d86d6012f90d071fb8dbadac2774df02')

        # Verify message with signature
        self.assertFalse(ed25519_zebra.ed_verify(signature, b"test", public_key))

    def test_verify_invalid_signature(self):
        # Get private and public key from seed
        private_key, public_key = ed25519_zebra.ed_from_seed(TEST_SEED)

        # Verify message with signature
        self.assertFalse(ed25519_zebra.ed_verify(bytes(32), b"test", public_key))

    def test_invalid_seed_length(self):
        self.assertRaises(ValueError, ed25519_zebra.ed_from_seed, bytes(1))

    def test_sign_invalid_private_key_length(self):
        with self.assertRaises(ValueError):
            ed25519_zebra.ed_sign(bytes(1), b"test")

    def test_public_from_private(self):
        private_key = bytes(32)
        public_key = ed25519_zebra.ed_public_from_secret(private_key)
        self.assertEqual(bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"), public_key)

    def test_concurrent_signing_and_verification(self):
        if sysconfig.get_config_var("Py_GIL_DISABLED") == 1:
            self.assertFalse(sys._is_gil_enabled())

        worker_count = 16
        barrier = threading.Barrier(worker_count)
        seed = bytes(range(32))

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = executor.map(
                exercise_crypto_concurrently,
                [barrier] * worker_count,
                [seed] * worker_count,
                range(worker_count),
            )

        self.assertTrue(all(results))

    @unittest.skipUnless(
        sysconfig.get_config_var("Py_GIL_DISABLED") == 1,
        "requires a free-threaded Python build",
    )
    def test_import_does_not_enable_gil(self):
        result = subprocess.run(
            [
                sys.executable,
                "-X",
                "gil=0",
                "-c",
                "import ed25519_zebra, sys; assert not sys._is_gil_enabled()",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
