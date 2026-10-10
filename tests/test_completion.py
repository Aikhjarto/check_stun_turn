"""Tests for the bash completion in completions/check_stun_turn."""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLUGIN = os.path.join(ROOT, "check_stun_turn")
COMPLETION = os.path.join(ROOT, "completions", "check_stun_turn")
MODES = ("stun", "turn")


def complete(*words, command="check_stun_turn", cwd=None):
    """The candidates bash offers for the last of words, which may be empty."""
    words = (command,) + words
    script = 'source "$1"; shift; COMP_WORDS=("$@"); COMP_CWORD=$(($# - 1)); ' \
             '$(complete -p "$1" | sed -E "s/.*-F ([^ ]+) .*/\\1/"); printf "%s\\n" "${COMPREPLY[@]}"'
    result = subprocess.run(["bash", "-c", script, "bash", COMPLETION] + list(words),
                            capture_output=True, text=True, check=True, cwd=cwd)
    return [line for line in result.stdout.split("\n") if line]


def help_words(*args):
    """The option strings and modes --help lists."""
    text = subprocess.run([PLUGIN] + list(args) + ["--help"], capture_output=True, text=True,
                          check=True).stdout
    words = set()
    for line in text.split("\n"):
        match = re.match(r"\s{2}(-[^\s,]+(?:, -[^\s,]+)*)", line)
        if match:
            words.update(match.group(1).split(", "))
        match = re.match(r"\s{4}([a-z]+)\s", line)
        if match:
            words.add(match.group(1))
    return words


@unittest.skipUnless(shutil.which("bash"), "bash is not installed")
class CompletionTests(unittest.TestCase):
    def test_syntax(self):
        subprocess.run(["bash", "-n", COMPLETION], check=True)

    def test_offers_exactly_the_modes_and_options_of_help(self):
        self.assertEqual(set(complete("")), help_words())
        self.assertTrue(set(MODES) <= help_words())

    def test_offers_exactly_the_options_of_the_mode_help(self):
        for mode in MODES:
            self.assertEqual(set(complete(mode, "")), help_words(mode), mode)

    def test_mode_prefix(self):
        self.assertEqual(complete("s"), ["stun"])
        self.assertEqual(complete("-V", "t"), ["turn"])

    def test_option_prefix(self):
        self.assertEqual(complete("stun", "--cert-"), ["--cert-warning", "--cert-critical"])
        self.assertEqual(complete("turn", "--sec"), ["--secret", "--secret-file"])
        self.assertEqual(complete("stun", "--sec"), [])

    def test_files(self):
        with tempfile.TemporaryDirectory() as directory:
            open(os.path.join(directory, "turn.secret"), "w").close()
            self.assertEqual(complete("turn", "-f", "tur", cwd=directory), ["turn.secret"])
            self.assertEqual(complete("turn", "--secret-file", "=", "tur", cwd=directory),
                             ["turn.secret"])

    def test_transport(self):
        self.assertEqual(complete("stun", "-T", ""), ["udp", "tcp", "tls"])
        self.assertEqual(complete("turn", "--transport", "=", "t"), ["tcp", "tls"])

    def test_no_candidates_for_values(self):
        for option in ("-w", "--critical", "--cert-warning", "-P", "-s", "--port", "--timeout"):
            self.assertEqual(complete("turn", option, ""), [], option)
            self.assertEqual(complete("turn", option, "=", ""), [], option)

    def test_unknown_mode(self):
        self.assertEqual(complete("bogus", ""), [])


if __name__ == "__main__":
    unittest.main()
