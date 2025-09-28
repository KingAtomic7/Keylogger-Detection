# consensual_simulator.py
# Safe simulator: records text that a consenting user types into the program.
# This is NOT a system-wide keylogger, does NOT run in background, and only records
# input while the program is actively running and the user consents.

import time
import pathlib
import sys

LOGFILE = pathlib.Path(__file__).parent / "consensual_simulator_log.txt"

def prompt_consent():
    print("CONSENT REQUIRED")
    print("This simulator will record anything you type after you confirm consent.")
    print("It does NOT capture system-wide keystrokes and will only run while this program is active.")
    print()
    resp = input("Type 'I CONSENT' to continue, or anything else to abort: ").strip()
    return resp == "I CONSENT"

def run_simulator():
    if not prompt_consent():
        print("Consent not given. Exiting safely.")
        return
    print()
    print("Simulator running. Type lines and press Enter. Type '/exit' to finish.")
    print("Your input will be appended to: {}".format(LOGFILE))
    with LOGFILE.open("a", encoding="utf-8") as f:
        f.write("--- New session at {} ---\n".format(time.asctime()))
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line.strip() == "/exit":
                print("Exiting simulator session.")
                break
            # record the line (explicit user input)
            f.write(line + "\n")
            f.flush()
            print("(recorded)")

if __name__ == "__main__":
    run_simulator()
