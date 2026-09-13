"""Terminal input: single-keypress kill-switch + confirmation prompt.

The core challenge: the agent needs BOTH
  (a) an instant single-keypress kill-switch, and
  (b) a human "type 'yes'" confirmation gate.

Both read stdin, so naive implementations RACE (the kill-switch thread
steals bytes from input(), or vice-versa). This module solves that by having
exactly ONE reader thread own stdin:

  * On a TTY (POSIX), it puts the terminal into cbreak mode (disable line
    buffering + echo) so single keypresses arrive immediately, then
    dispatches every byte:
        - abort keys (q / x / ESC)   -> trigger the kill-switch,
        - anything else              -> appended to a line buffer,
    and it manually echoes printable characters so typed text is visible.
  * On non-TTY (piped stdin, e.g. `echo yes | ...` or CI), it skips raw mode
    and falls back to plain input() for confirmation, and disables the
    keypress kill-switch (Ctrl+C still works).

This avoids pulling in a heavyweight global key-logger (pynput/keyboard) —
exactly the kind of broad input hook a security tool should not require.
"""
from __future__ import annotations

import os
import queue
import sys
import threading
from typing import Callable, List, Optional

ABORT_KEYS = {"q", "x", "Q", "X", "\x1b"}  # ESC + q/x


class KillSwitch:
    """Instant abort flag + cleanup callbacks."""

    def __init__(self) -> None:
        self._aborted = threading.Event()
        self._callbacks: List[Callable[[], None]] = []

    @property
    def aborted(self) -> bool:
        return self._aborted.is_set()

    def abort(self, reason: str = "kill-switch pressed") -> None:
        if self._aborted.is_set():
            return
        self._aborted.set()
        print(f"\n[!] KILL-SWITCH ({reason}) — aborting agent and destroying sandbox...")
        for cb in list(self._callbacks):
            try:
                cb()
            except Exception as exc:  # cleanup must never mask the abort
                print(f"    (cleanup callback failed: {exc})")

    def on_abort(self, cb: Callable[[], None]) -> None:
        self._callbacks.append(cb)

    def reset(self) -> None:
        self._aborted.clear()


class TerminalInput:
    """Single stdin reader dispatching to kill-switch + confirmation."""

    def __init__(self, killswitch: KillSwitch) -> None:
        self.ks = killswitch
        self._tty = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False
        self._lines: "queue.Queue[str]" = queue.Queue()
        self._line: List[str] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._old_termios = None

    # --- raw/cbreak mode management ----------------------------------
    def _enter_raw(self) -> None:
        """Disable canonical mode + echo on POSIX TTYs so keys arrive instantly."""
        if not self._tty or os.name == "nt":
            return
        try:
            import termios
            import tty

            self._old_termios = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        except Exception:
            self._old_termios = None

    def _restore_raw(self) -> None:
        if self._old_termios is not None:
            try:
                import termios

                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_termios)
            except Exception:
                pass
            self._old_termios = None

    # --- reader thread -----------------------------------------------
    def _poll_loop(self) -> None:
        while not self.ks.aborted:
            try:
                ch = self._read_one()
            except Exception:
                break  # stdin closed
            if ch is None:
                continue
            if ch in ABORT_KEYS:
                self.ks.abort()
                break
            # Printable / line characters go to the confirmation buffer.
            if ch in ("\n", "\r"):
                with self._lock:
                    self._lines.put("".join(self._line).strip())
                    self._line = []
                sys.stdout.write("\n")
                sys.stdout.flush()
            else:
                with self._lock:
                    self._line.append(ch)
                if ch.isprintable():
                    sys.stdout.write(ch)
                    sys.stdout.flush()
                elif ch in ("\x7f", "\b"):  # backspace
                    with self._lock:
                        if self._line:
                            self._line.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()

    def _read_one(self) -> Optional[str]:
        if os.name == "nt":
            import msvcrt

            if not msvcrt.kbhit():
                self.ks._aborted.wait(0.05)
                return None
            return msvcrt.getwch()
        import select

        r, _, _ = select.select([sys.stdin], [], [], 0.1)
        if not r:
            return None
        return sys.stdin.read(1)

    # --- public API --------------------------------------------------
    def start(self) -> None:
        if not self._tty:
            return  # piped stdin: no keypress kill-switch (Ctrl+C still works)
        if self._thread and self._thread.is_alive():
            return
        self._enter_raw()
        self._thread = threading.Thread(target=self._poll_loop, name="term-input", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._restore_raw()

    def prompt(self, message: str) -> str:
        """Blocking confirmation prompt.

        TTY path: uses the single reader thread (cbreak, echoed).
        Non-TTY path: plain input() (works with pipes / scripts).
        Returns the trimmed line, or '' on EOF/abort.
        """
        if not self._tty:
            try:
                return input(message).strip()
            except (EOFError, KeyboardInterrupt):
                return ""
        sys.stdout.write(message)
        sys.stdout.flush()
        try:
            return self._lines.get(timeout=120)
        except queue.Empty:
            return ""
        except KeyboardInterrupt:
            return ""


# Module-level singletons.
KILLSWITCH = KillSwitch()
TERMINAL = TerminalInput(KILLSWITCH)
