#!/usr/bin/env python
""" Export lustre nodemap information as yaml

    Usage:
        nodemap.py
    
    WARNING: This does not handle nested lists/dicts at the moment, only name.subname.[...].parameter=value lines
"""
from __future__ import print_function
__version__ = "0.0"

import subprocess, pprint, sys

def cmd(args):
    proc = subprocess.Popen(args, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) # need shell else lctl not found
    #proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    return stdout, stderr

def lctl_get_param(item, output):
    s, e = cmd("sudo lctl get_param '{item}'".format(item=item)) # need quoting around `item` to avoid shell expansion of ".*" !
    lines = s.strip().split('\n')
    for line in lines:
        if line: # skip empty liens
            parts = line.split('.')
            if parts[0] == 'nodemap':
                param, value = parts[-1].split('=')
                r = output
                for p in parts[:-1]:
                    r = r.setdefault(p, {})
                r[param] = value
            else:
                print('WARNING: skipping line', line, file=sys.stderr) # FIXME: 
    return output
    
def main():
    output = {}
    lctl_get_param("nodemap.*", output)
    s, e = cmd("lctl nodemap_info",) # need quoting to avoid shell expansion!
    nodemaps = [n.split('.')[-1] for n in s.strip().split('\n')]
    #print(nodemaps)
    for nmap in nodemaps:
        lctl_get_param("nodemap.{nmap}.*".format(nmap=nmap), output)

    print('----- OUTPUT ----')
    pprint.pprint(output)
    
if __name__ == '__main__':
    main()
