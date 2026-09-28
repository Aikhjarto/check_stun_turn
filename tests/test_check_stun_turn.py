"""Tests for check_stun_turn: RFC 5769 test vectors and a mock STUN/TURN server on localhost.

Run with: python3 -m unittest discover -s tests
"""

import base64
import hashlib
import hmac
import importlib.machinery
import importlib.util
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

PLUGIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "check_stun_turn")
_loader = importlib.machinery.SourceFileLoader("check_stun_turn", PLUGIN)
_spec = importlib.util.spec_from_loader("check_stun_turn", _loader)
cc = importlib.util.module_from_spec(_spec)
_loader.exec_module(cc)

REALM = "mock.realm"
USER = "alice"
PASSWORD = "s3cret"
SECRET = "sharedsecret"
RELAY = ("198.51.100.7", 50000)


def run(*args):
    """Run the plugin like a monitoring system does: (exit code, output lines)."""
    result = subprocess.run([sys.executable, PLUGIN] + list(args), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, timeout=30)
    return result.returncode, result.stdout.splitlines()


def xor_address(host, port):
    raw = bytes(a ^ b for a, b in zip(socket.inet_aton(host), struct.pack("!I", cc.MAGIC_COOKIE)))
    return b"\0\x01" + struct.pack("!H", port ^ (cc.MAGIC_COOKIE >> 16)) + raw


def error(method, transaction, code, reason, extra=()):
    value = struct.pack("!HBB", 0, code // 100, code % 100) + reason.encode()
    return cc.encode(method | cc.ERROR, [(cc.ERROR_CODE, value), (cc.SOFTWARE, b"mock-turn")] + list(extra),
                     transaction)


class MockServer:
    """STUN/TURN server with a scenario: ok, stale, quota, open or silent."""

    def __init__(self, scenario="ok", transport="udp", tls_context=None):
        self.scenario = scenario
        self.transport = transport
        self.tls_context = tls_context
        self.log = []
        self.stale_sent = False
        kind = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        self.socket = socket.socket(socket.AF_INET, kind)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        if transport != "udp":
            self.socket.listen(5)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def close(self):
        self.socket.close()

    def password_for(self, username):
        if ":" in username:
            return base64.b64encode(hmac.new(SECRET.encode(), username.encode(), hashlib.sha1).digest()).decode()
        return PASSWORD if username == USER else None

    def integrity_ok(self, data, username):
        password = self.password_for(username)
        if password is None:
            return False
        position = data.find(struct.pack("!HH", cc.MESSAGE_INTEGRITY, 20))
        header = data[:2] + struct.pack("!H", position - 20 + 24) + data[4:20]
        key = hashlib.md5(("%s:%s:%s" % (username, REALM, password)).encode()).digest()
        return data[position + 4:position + 24] == hmac.new(key, header + data[20:position], hashlib.sha1).digest()

    def answer(self, data):
        request = cc.Response(data)
        method = request.type & 0x3EEF
        transaction = request.transaction
        username = request.text(cc.USERNAME)
        challenge = [(cc.REALM, REALM.encode()), (cc.NONCE, b"n1")]
        allocated = [(cc.XOR_RELAYED_ADDRESS, xor_address(*RELAY)), (cc.LIFETIME, struct.pack("!I", 600)),
                     (cc.SOFTWARE, b"mock-turn")]

        if method == cc.BINDING:
            return cc.encode(cc.BINDING | cc.SUCCESS, [(cc.XOR_MAPPED_ADDRESS, xor_address("192.0.2.1", 32853)),
                                                      (cc.SOFTWARE, b"mock-turn")], transaction)
        if self.scenario == "open" and method == cc.ALLOCATE:
            return cc.encode(cc.ALLOCATE | cc.SUCCESS, allocated, transaction)
        if username is None and method != cc.REFRESH:
            return error(method, transaction, 401, "Unauthorized", challenge)
        if username is not None and not self.integrity_ok(data, username):
            self.log.append("rejected %s" % username)
            return error(method, transaction, 401, "Unauthorized", challenge)
        if self.scenario == "stale" and not self.stale_sent and method == cc.ALLOCATE:
            self.stale_sent = True
            return error(method, transaction, 438, "Stale Nonce", [(cc.REALM, REALM.encode()), (cc.NONCE, b"n2")])
        if self.scenario == "quota" and method == cc.ALLOCATE:
            return error(method, transaction, 486, "Allocation Quota Reached")
        if method == cc.ALLOCATE:
            self.log.append("allocated %s nonce %s" % (username, request.text(cc.NONCE)))
            return cc.encode(cc.ALLOCATE | cc.SUCCESS, allocated, transaction)
        if method == cc.REFRESH:
            self.log.append("refresh %d" % struct.unpack("!I", request.attributes[cc.LIFETIME])[0])
            return cc.encode(cc.REFRESH | cc.SUCCESS, [(cc.LIFETIME, struct.pack("!I", 0))], transaction)
        return error(method, transaction, 400, "Bad Request")

    def serve(self):
        try:
            if self.transport == "udp":
                while True:
                    data, peer = self.socket.recvfrom(65536)
                    if self.scenario != "silent":
                        self.socket.sendto(self.answer(data), peer)
            while True:
                connection, _ = self.socket.accept()
                if self.tls_context:
                    try:
                        connection = self.tls_context.wrap_socket(connection, server_side=True)
                    except (ssl.SSLError, OSError):
                        connection.close()
                        continue
                buffer = b""
                while True:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
                    while len(buffer) >= 20 and len(buffer) >= 20 + struct.unpack("!H", buffer[2:4])[0]:
                        size = 20 + struct.unpack("!H", buffer[2:4])[0]
                        message, buffer = buffer[:size], buffer[size:]
                        connection.sendall(self.answer(message))
                connection.close()
        except OSError:
            pass


class Rfc5769(unittest.TestCase):
    """The test vectors of RFC 5769."""

    def test_long_term_message_integrity(self):
        expected = bytes.fromhex(
            "000100602112a44278ad3433c6ad72c029da412e"
            "00060012e3839ee38388e383aae38383e382afe382b90000"
            "0015001c662f2f3439396b39353464364f4c33346f4c39465354767936347341"
            "0014000b6578616d706c652e6f726700"
            "00080014f67024656dd64a3e02b8e0712e85c9a28ca89666")
        username, realm, nonce = "マトリックス", "example.org", "f//499k954d6OL34oL9FSTvy64sA"
        key = hashlib.md5(("%s:%s:%s" % (username, realm, "TheMatrIX")).encode()).digest()
        message = cc.encode(cc.BINDING, [(cc.USERNAME, username.encode()), (cc.NONCE, nonce.encode()),
                                         (cc.REALM, realm.encode())],
                            bytes.fromhex("78ad3433c6ad72c029da412e"), key)
        self.assertEqual(message, expected)

    def test_ipv4_xor_mapped_address(self):
        response = cc.Response(bytes.fromhex(
            "0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220"
            "002000080001a147e112a643000800142b91f599fd9e90c38c7489f92af9ba53f06be7d7"
            "80280004c07d4c96"))
        self.assertTrue(response.success)
        self.assertEqual(response.address(cc.XOR_MAPPED_ADDRESS), "192.0.2.1:32853")
        self.assertEqual(response.text(cc.SOFTWARE), "test vector")

    def test_ipv6_xor_mapped_address(self):
        response = cc.Response(bytes.fromhex(
            "010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220"
            "002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9"
            "00080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c"))
        self.assertEqual(response.address(cc.XOR_MAPPED_ADDRESS), "[2001:db8:1234:5678:11:2233:4455:6677]:32853")


class MockTestCase(unittest.TestCase):
    scenario = "ok"
    transport = "udp"

    def setUp(self):
        self.server = MockServer(self.scenario, self.transport)
        self.addCleanup(self.server.close)
        self.secret_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.secret_dir)

    def check(self, mode, *args):
        return run(mode, "-H", "127.0.0.1", "-p", str(self.server.port), "-T", self.transport, "-t", "3", *args)

    def secret_file(self, content):
        path = os.path.join(self.secret_dir, "secret")
        with open(path, "w") as handle:
            handle.write(content)
        return path


class Stun(MockTestCase):
    def test_binding(self):
        code, lines = self.check("stun")
        self.assertEqual(code, cc.OK)
        self.assertEqual(len(lines), 1)
        self.assertRegex(lines[0], r"^STUN OK - mock-turn answered over UDP in [0-9.]+s, "
                                   r"mapped address 192\.0\.2\.1:32853 \| time=[0-9.]+s;1;3;0$")

    def test_response_time_threshold(self):
        code, lines = self.check("stun", "-w", "0", "-c", "10")
        self.assertEqual(code, cc.WARNING)
        self.assertIn("time=", lines[0])
        self.assertTrue(lines[0].endswith(";0;10;0"))

    def test_one_sided_thresholds_are_plain_numbers(self):
        code, lines = self.check("stun", "-w", "~:5", "-c", "~:")
        self.assertEqual(code, cc.OK)
        self.assertRegex(lines[0], r"time=[0-9.]+s;5;;0$")


class StunOverTcp(Stun):
    transport = "tcp"

    def test_binding(self):
        code, lines = self.check("stun")
        self.assertEqual(code, cc.OK)
        self.assertIn("answered over TCP", lines[0])


class Turn(MockTestCase):
    def test_challenge_without_credentials(self):
        code, lines = self.check("turn")
        self.assertEqual(code, cc.OK)
        self.assertIn("asks for authentication (realm mock.realm)", lines[0])
        self.assertEqual(self.server.log, [])

    def test_long_term_credentials_allocate_and_release(self):
        code, lines = self.check("turn", "-u", USER, "-P", PASSWORD)
        self.assertEqual(code, cc.OK)
        self.assertIn("allocated relay 198.51.100.7:50000 for 600s in realm mock.realm", lines[0])
        self.assertEqual(self.server.log, ["allocated alice nonce n1", "refresh 0"])

    def test_password_file(self):
        code, lines = self.check("turn", "-u", USER, "-f", self.secret_file(PASSWORD + "\n"))
        self.assertEqual(code, cc.OK)

    def test_static_auth_secret(self):
        code, lines = self.check("turn", "-S", self.secret_file(SECRET))
        self.assertEqual(code, cc.OK)
        username = self.server.log[0].split()[1]
        expiry, name = username.split(":")
        self.assertEqual(name, "check_stun_turn")
        self.assertTrue(expiry.isdigit())

    def test_static_auth_secret_with_user(self):
        code, lines = self.check("turn", "-s", SECRET, "-u", "monitor")
        self.assertEqual(code, cc.OK)
        self.assertTrue(self.server.log[0].split()[1].endswith(":monitor"))

    def test_wrong_password_is_unknown(self):
        code, lines = self.check("turn", "-u", USER, "-P", "wrong")
        self.assertEqual(code, cc.UNKNOWN)
        self.assertIn("rejected the credentials", lines[0])

    def test_wrong_secret_is_unknown(self):
        code, lines = self.check("turn", "-s", "not-the-secret")
        self.assertEqual(code, cc.UNKNOWN)

    def test_user_without_password_is_unknown(self):
        code, lines = self.check("turn", "-u", USER)
        self.assertEqual(code, cc.UNKNOWN)


class TurnStaleNonce(MockTestCase):
    scenario = "stale"

    def test_retries_with_the_new_nonce(self):
        code, lines = self.check("turn", "-u", USER, "-P", PASSWORD)
        self.assertEqual(code, cc.OK)
        self.assertEqual(self.server.log, ["allocated alice nonce n2", "refresh 0"])


class TurnQuota(MockTestCase):
    scenario = "quota"

    def test_refused_allocation_is_critical(self):
        code, lines = self.check("turn", "-u", USER, "-P", PASSWORD)
        self.assertEqual(code, cc.CRITICAL)
        self.assertIn("486 Allocation Quota Reached", lines[0])


class TurnOpenRelay(MockTestCase):
    scenario = "open"

    def test_open_relay_is_a_warning(self):
        code, lines = self.check("turn")
        self.assertEqual(code, cc.WARNING)
        self.assertIn("open relay", lines[0])


class Silent(MockTestCase):
    scenario = "silent"

    def test_no_answer_is_critical(self):
        code, lines = run("stun", "-H", "127.0.0.1", "-p", str(self.server.port), "-t", "1")
        self.assertEqual(code, cc.CRITICAL)
        self.assertIn("no answer", lines[0])


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to create a test certificate")
class Tls(unittest.TestCase):
    def setUp(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory)
        cert, key = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "2", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server = MockServer("ok", "tls", context)
        self.addCleanup(self.server.close)

    def test_untrusted_certificate_is_critical(self):
        code, lines = run("stun", "-H", "127.0.0.1", "-p", str(self.server.port), "-T", "tls", "-t", "3")
        self.assertEqual(code, cc.CRITICAL)
        self.assertIn("TLS certificate of 127.0.0.1 is not valid", lines[0])

    def test_insecure_skips_the_certificate(self):
        code, lines = run("stun", "-H", "127.0.0.1", "-p", str(self.server.port), "-T", "tls", "-k", "-t", "3")
        self.assertEqual(code, cc.OK)
        self.assertIn("answered over TLS", lines[0])


class CommandLine(unittest.TestCase):
    def test_usage_errors_are_unknown(self):
        for args in ([], ["stun"], ["bogus", "-H", "x"], ["stun", "-H", "x", "-p", "abc"], ["stun", "-H", "x", "-T", "sctp"]):
            with self.subTest(args=args):
                self.assertEqual(run(*args)[0], cc.UNKNOWN)

    def test_version_and_help_exit_zero(self):
        self.assertEqual(run("--version")[0], cc.OK)
        self.assertEqual(run("turn", "--help")[0], cc.OK)

    def test_invalid_threshold_is_unknown(self):
        code, lines = run("stun", "-H", "127.0.0.1", "-w", "abc")
        self.assertEqual(code, cc.UNKNOWN)
        self.assertIn("invalid threshold", lines[0])

    def test_unresolvable_host_is_critical(self):
        code, lines = run("stun", "-H", "no-such-host.invalid", "-t", "3")
        self.assertEqual(code, cc.CRITICAL)
        self.assertIn("cannot resolve", lines[0])


if __name__ == "__main__":
    unittest.main()
