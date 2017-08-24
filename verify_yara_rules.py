#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Author: marirs
Description: Look at files in a given path for yara rules, and dedupe them based on rule name
Version: 0.1
Requirements: python 2.7 & yara-python, re2 (for regex performance)
Changelog: 0.1: initial commit
"""
from __future__ import print_function

import os
import io
import sys
import argparse

try:
    import re2 as re
except ImportError:
    import re

try:
    import yara
except:
    exit("[!] No yara module found. Install yara-python (pip install yara-python)")

sys.dont_write_bytecode = True

__version__ = 0.1
__author__ = "marirs@gmail.com"
__license__ = "GPL"
__file__ = "verify_yara_rules.py"

imre = re.compile(r"(^import\s+.*?$)", re.MULTILINE | re.DOTALL)
yare = re.compile(r"(^[\s+private\/\*]*rule\s[0-9a-zA-Z_\@\#\$\%\^\&\(\)\-\=\:\s]+\{.*?condition.*?\s\})", re.MULTILINE | re.DOTALL)

def chk_yara_import(Import):
    """
    Checks if the yara module exists or not!
    :param Import: yara import
    :return: returns true if exists else false
    """
    try:
        yara.compile(source=Import)
    except:
        return False

    return True

if __name__ == "__main__":
    print ("Yara Rules verify - v{}".format(__version__))
    print ("by: {}\n".format(__author__))
    parser = argparse.ArgumentParser(description='verify yara rules')
    parser.add_argument('-f', '--file', help='yara file to compile', required=True)
    args = parser.parse_args()

    if args.file:
        if not os.path.isfile(args.file):
            exit("[!] {} does not exist! provide a valid file to verify.".format(args.file))   

    yara_file = args.file

    with io.open(yara_file, "r", encoding="utf-8") as rule_file:
         # Read from rule file
        try:
            content = rule_file.read()
        except Exception, err:
            exit ("\n[!] {}: {}".format(rule_file, err))

    yara_rules = yare.findall(content)
    imports = set(imre.findall(content))
    print ("[*] Total rules in file: {}".format(len(yara_rules)))
    if imports:
        print ("[*] Checking yara import modules...")
        for module in imports:
            print (" -> {}: {}".format(module,"You dont have this module!" if not chk_yara_import(module) else "PASS"))
        print("-"*35)

    print ("[*] Verifying rules in file: \"{}\"".format(yara_file))
    try:
        yara.compile(yara_file)
        print (" -> \"{}\" compiled well.".format(yara_file))
    except Exception, err:
        print (" -> {}".format(err))
