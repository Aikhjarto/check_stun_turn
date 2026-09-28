# check_stun_turn

A Nagios/Icinga plugin for STUN/TURN servers such as
[coturn](https://github.com/coturn/coturn) or [eturnal](https://eturnal.net/),
written in Python 3 with the standard library only.

| Mode | Answers | Default thresholds |
|---|---|---|
| `stun` | Does the server answer a STUN binding request, with which address and how fast? | `-w 1 -c 3` (seconds) |
| `turn` | Does the TURN service answer, and does it allocate a relay for valid credentials? | `-w 2 -c 5` (seconds) |

## Usage

```sh
check_stun_turn stun -H turn.example.com
check_stun_turn turn -H turn.example.com
check_stun_turn turn -H turn.example.com -S /etc/icinga2/turn.secret
check_stun_turn stun -H turn.example.com -T tls
```

```
STUN OK - Coturn-4.6.1 'Gorst' answered over UDP in 0.026s, mapped address 192.0.2.10:37527 | time=0.026s;1;3;0
TURN OK - Coturn-4.6.1 'Gorst' allocated relay 198.51.100.7:50000 for 600s in realm turn.example.com, 0.061s over UDP | time=0.061s;2;5;0
```

| Option | Meaning |
|---|---|
| `-H` | Host name or address of the server (required) |
| `-p` | Port (default: 3478, 5349 with `-T tls`) |
| `-T` | Transport: `udp` (default), `tcp` or `tls` |
| `-4`, `-6` | Use IPv4 or IPv6 only |
| `-t` | Timeout in seconds (default: 10) |
| `-w`, `-c` | Thresholds for the response time in seconds |
| `-k` | Do not verify the TLS certificate |
| `--sni` | Server name for TLS (default: the host name) |
| `--cert-warning`, `--cert-critical` | Days before the TLS certificate expires to warn and alert (default: 30 and 14) |

Over UDP, requests are retransmitted as RFC 8489 describes, starting after
0.5 s and doubling the wait until the timeout. DTLS is not supported.

### stun

Sends a binding request and reports the server software and the address the
server sees the monitoring host at.

### turn

Requests a relay allocation. Without credentials, the server has to answer
with an authentication challenge: that proves the TURN service is alive and
asks for authentication. A server that allocates a relay without credentials
is an open relay, which the check reports as a WARNING.

With credentials, the check authenticates, allocates a relay and releases it
again at once. That also covers the authentication backend and the relay port
range. Two kinds of credentials work:

- a TURN user with `-u` and `-P`, `-f` or `$TURN_PASSWORD[_FILE]`
- the shared secret of the TURN REST API (coturn's `static-auth-secret`, used
  by Nextcloud Talk, Jitsi and others) with `-s`, `-S` or `$TURN_SECRET[_FILE]`.
  The check derives short-lived credentials from it, for the user given with
  `-u` (default `check_stun_turn`).

Never pass a password or secret with `-P` or `-s` in a service definition:
command lines are visible to every user via `ps`. Put it in a file that only
the monitoring user can read.

### TLS

With `-T tls` both modes check the certificate as well: an invalid or expired
certificate is CRITICAL, and one expiring within `--cert-critical` or
`--cert-warning` days is CRITICAL or WARNING. coturn reads its certificate
only at startup, so a renewed certificate needs a restart of coturn, or it
keeps serving the old one until it expires.

## Output and exit codes

Every check prints exactly one line: the status, a summary and the performance
data. `0` OK, `1` WARNING, `2` CRITICAL, `3` UNKNOWN. An unreachable server, a
refused allocation and an invalid certificate are CRITICAL; rejected
credentials and a wrong command line are UNKNOWN.

## Tests

```sh
python3 -m unittest discover -s tests
```

The tests need nothing but Python 3 and localhost. They check the STUN
encoding against the test vectors of RFC 5769 and run the plugin against a
mock STUN/TURN server over UDP, TCP and TLS: binding, challenge, allocation
with long-term credentials and with a shared secret, stale nonce, refused
allocation, open relay, wrong credentials, no answer and command line errors.
The TLS tests create a throwaway certificate with `openssl` and are skipped
without it.

## License

GPL-2.0-or-later, see [LICENSE](LICENSE).
