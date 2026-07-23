"""Telnet-level regression tests driven over the console connection.

Unlike the declarative command-cases (which are plain text), these tests need
to send raw telnet IAC negotiation bytes, so they drive the server directly
rather than through the YAML harness.

Background: the server proactively requests NAWS (window size) at connect with
IAC DO NAWS.  It historically answered every client WILL NAWS with another DO
NAWS (and every DO NAWS with another WILL NAWS).  A client that in turn
re-answers each of those -- a common naive telnet stack -- produces an
unbounded DO/WILL negotiation loop that floods an otherwise idle connection
with packets (very visible over TLS, where each frame is its own record).  The
fix makes the DO/WILL handshake idempotent per direction; these tests guard it.
"""

import test_util

IAC = 0xff
DONT = 0xfe
DO = 0xfd
WONT = 0xfc
WILL = 0xfb
SB = 0xfa
SE = 0xf0
TELOPT_NAWS = 0x1f

DO_NAWS = bytes([IAC, DO, TELOPT_NAWS])
WILL_NAWS = bytes([IAC, WILL, TELOPT_NAWS])


class TelnetNawsTest(test_util.ServerTestBase):
    """Drive the raw telnet handshake ourselves, then log in as One (#1)."""

    async def _drive(self, prelude):
        """Start the server, send `prelude` (raw bytes) ahead of the login,
        then connect and emit a marker so the read is bounded.  Returns all
        bytes received up to and including the connect prompt."""
        await self._start_server()
        out = await self._write_and_await_prompt(
            prelude + self.connect_string, self.connect_prompt)
        await self._finish()
        return out

    def test_will_naws_does_not_loop(self):
        """Answering the server's DO NAWS with WILL NAWS -- repeatedly, as a
        naive client would -- must not make the server re-DO each one.  We send
        eight WILL NAWS and never react to the replies; a fixed server answers
        at most one of them, a looping server answers all eight."""
        out = test_util._asyncio_run(self._drive(WILL_NAWS * 8))
        count = out.count(DO_NAWS)
        # One DO NAWS is sent proactively at connect; at most one more should
        # acknowledge the client's WILL.  Anything near eight means regression.
        self.assertLessEqual(
            count, 3,
            "server emitted {} DO NAWS for 8 WILL NAWS (loop?)".format(count))

    def test_do_naws_does_not_loop(self):
        """Symmetric case: a client that answers our WILL NAWS with DO NAWS
        must not make the server re-WILL each one."""
        out = test_util._asyncio_run(self._drive(DO_NAWS * 8))
        count = out.count(WILL_NAWS)
        self.assertLessEqual(
            count, 2,
            "server emitted {} WILL NAWS for 8 DO NAWS (loop?)".format(count))

    def test_window_size_still_captured(self):
        """The whole point of the NAWS handshake is capturing screen size, so
        make sure the fix didn't break the SB subnegotiation path: enable NAWS,
        send a 120x40 window size, then read it back via the MUF WIDTH/HEIGHT
        prims for our own descriptor."""
        width, height = 120, 40
        naws = WILL_NAWS + bytes(
            [IAC, SB, TELOPT_NAWS, 0, width, 0, height, IAC, SE])
        program = (
            b"@program cmd-size.muf\n"
            b"i\n"
            b": main pop "
            b'"SIZE=" descr width intostr strcat "x" strcat '
            b"descr height intostr strcat "
            b"me @ swap notify ;\n"
            b".\n"
            b"c\n"
            b"q\n"
            b"@action cmd-size=here\n"
            b"@link cmd-size=cmd-size.muf\n"
        )

        async def run():
            await self._start_server()
            # Negotiate NAWS and send the window size before logging in; the
            # size is stored on the descriptor, which survives the login.
            await self._write_and_await_prompt(
                naws + self.connect_string, self.connect_prompt)
            out = await self._write_and_await_prompt(
                program + b"cmd-size\n" + self.done_command_command,
                self.done_command_prompt)
            await self._finish()
            return out

        out = test_util._asyncio_run(run())
        self.assertIn(b"SIZE=120x40", out)
