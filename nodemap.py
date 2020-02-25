#!/usr/bin/env python
""" Export lustre nodemap information as yaml

    Usage:
        nodemap.py
    
    WARNING: This does not handle nested lists/dicts at the moment, only name.subname.[...].parameter=value lines
"""
from __future__ import print_function
__version__ = "0.0"

import subprocess, pprint, sys, re, ast

def cmd(args):
    proc = subprocess.Popen(args, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) # need shell else lctl not found
    stdout, stderr = proc.communicate()
    return stdout, stderr

def lctl_get_param(item, output):
    s, e = cmd("sudo lctl get_param '{item}'".format(item=item)) # need quoting around `item` to avoid shell expansion of ".*" !
    lines = s.strip().split('\n')
    accumulate = []
    for line in lines:
        #print(line)
        if line: # skip empty lines
            #print('line:', line)
            if '=' in line:
                
                # handle accumulated value lines from *previous* object:
                if accumulate:
                    prev_value = r[param] + ''.join(accumulate) # sometimes previous key=value ended"=[" so always prefix that
                    quoted_prev_value = re.sub(r'\s?([^\s:]+):\s?([^\s,]+)', r"'\1':'\2'", prev_value) # add quoting around dict values and keys
                    # turn it into python:
                    try:
                        py_prev_value = ast.literal_eval(quoted_prev_value)
                    except:
                        print('ERROR: failed when parsing', quoted_prev_value)
                        raise
                    accumulate = []
                    r[param] = py_prev_value

                # handle normal lines:
                parts = line.split('.')
                param, value = parts[-1].split('=')
                r = output
                for p in parts[:-1]:
                    r = r.setdefault(p, {})
                r[param] = value


            else:
                accumulate.append(line)
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
