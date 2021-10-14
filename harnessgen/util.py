import sys
import struct
import string
import signal

printable = set(string.printable.encode())


def strings(data: bytes):
    found_str = b""
    while True:
        if not data:
            break
        for char in data:
            if char in printable:
                found_str += bytes([char])
            elif len(found_str) >= 4:
                yield found_str
                break
        break
    yield b''


def u32(b, off=0):
    return struct.unpack("<I", b[off:off+4])[0]


def p32(x):
    return struct.pack("<I", x)


def exit_gracefully(original_sigint):
    # code from: https://stackoverflow.com/questions/18114560/python-catch-ctrl-c-command-prompt-really-want-to-quit-y-n-resume-execution
    def _exit_gracefully(signum, frame):
        # restore the original signal handler as otherwise evil things will happen
        # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
        signal.signal(signal.SIGINT, original_sigint)

        try:
            if input("\nReally quit? (y/n)> ").lower().startswith('y'):
                sys.exit(1)

        except KeyboardInterrupt:
            print("Ok ok, quitting")
            sys.exit(1)

        # restore the exit gracefully handler here
        signal.signal(signal.SIGINT, _exit_gracefully)
    return _exit_gracefully
