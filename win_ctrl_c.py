"""
Send Ctrl+C to a console process on Windows, the same as pressing it in the
server's window (the server then saves the game state and exits).

    python win_ctrl_c.py <pid>

app.py runs this as its own short-lived process: a process has to leave its
own console and attach to the target's before it can send the event there.
"""

import ctypes
import sys

CTRL_C_EVENT = 0


def main():
    pid = int(sys.argv[1])
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.FreeConsole()
    if not kernel32.AttachConsole(pid):
        sys.exit(f"Could not attach to the console of process {pid} (error {ctypes.get_last_error()})")
    # Process group 0 means every process on that console, which now includes
    # this helper, so make it ignore the event itself.
    kernel32.SetConsoleCtrlHandler(None, True)
    if not kernel32.GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0):
        sys.exit(f"Could not send Ctrl+C (error {ctypes.get_last_error()})")
    kernel32.FreeConsole()


if __name__ == "__main__":
    main()
