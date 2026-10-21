"""Deliberately insecure sample used to test the code-audit pipeline.
Each function carries a classic, static-analysis-detectable flaw. Not real code.
"""
import os
import subprocess
import sqlite3


def run_echo(cmd):
    os.system("echo " + cmd)  # command injection via os.system + concatenation


def evaluate(user_input):
    return eval(user_input)  # code injection via eval on untrusted input


def lookup(db_path, name):
    cur = sqlite3.connect(db_path).cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # SQL injection
    return cur.fetchall()


def spawn(x):
    return subprocess.Popen(x, shell=True)  # shell=True on caller-supplied input
