"""Secret-handling helpers: wipeable buffers, a no-echo password reader, process hardening."""
import contextlib
import ctypes
import getpass
import os
import resource
import sys

try:                                   # POSIX terminal control
    import termios
except ImportError:                    # pragma: no cover
    termios = None

MAX_READ = 1024                        # bytes accepted from the terminal (validation rejects far less)
_PR_SET_DUMPABLE = 4


def wipe(buf) -> None:
    if not isinstance(buf, bytearray) or not buf:
        return
    n = len(buf)
    try:
        view = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(view, 0, n)
        del view                       # release the export so the bytearray stays resizable
    except Exception:
        buf[:] = bytes(n)


@contextlib.contextmanager
def secret(buf):
    try:
        yield buf
    finally:
        wipe(buf)


def harden_process() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
        except Exception:
            pass


def read_password(prompt: str = "Password: ") -> bytearray:
    fd = None
    old = None
    if termios is not None:
        try:
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
        except (AttributeError, ValueError, OSError, termios.error):
            fd = None
    if fd is None or old is None:
        return bytearray(getpass.getpass(prompt).encode("utf-8"))

    new = termios.tcgetattr(fd)
    new[3] &= ~(termios.ECHO | termios.ICANON)       
    new[6][termios.VMIN] = 1
    new[6][termios.VTIME] = 0
    buf = bytearray()
    sys.stderr.write(prompt)
    sys.stderr.flush()
    try:
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
        while True:
            ch = os.read(fd, 1)
            if ch in (b"\n", b"\r"):
                break
            if ch in (b"", b"\x04"):                 
                if not buf:
                    raise EOFError
                break
            if ch in (b"\x7f", b"\x08"):             
                while buf and (buf[-1] & 0xC0) == 0x80:
                    buf.pop()
                if buf:
                    buf.pop()
                continue
            if ch == b"\x15":                        
                wipe(buf)
                buf.clear()
                continue
            if len(buf) < MAX_READ:
                buf += ch
        return buf
    except BaseException:
        wipe(buf)
        raise
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, old)
        sys.stderr.write("\n")
        sys.stderr.flush()
