#!/usr/bin/env python
""" Export lustre nodemap information as yaml

    Usage:
        nodemap.py export
        nodemap.py diff yaml
"""
from __future__ import print_function
__version__ = "0.0"

import subprocess, pprint, sys, re, ast, difflib

# pyyaml:
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

def cmd(args):
    proc = subprocess.Popen(args, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) # need shell else lctl not found
    stdout, stderr = proc.communicate()
    return stdout, stderr

def lctl_get_param(item, output):
    """ TODO:
        NB output gets modified!
        format: nested dicts, values may be nested list/dicts (including empty ones) or strings.
    """
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
                    
                    # store and reset:
                    r[param] = py_prev_value
                    accumulate = []

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
    
def get_nodemap_info():
    """ TODO: """
    output = {}
    lctl_get_param("nodemap.*", output)
    s, e = cmd("lctl nodemap_info",) # need quoting to avoid shell expansion!
    nodemaps = [n.split('.')[-1] for n in s.strip().split('\n')]
    #print(nodemaps)
    for nmap in nodemaps:
        lctl_get_param("nodemap.{nmap}.*".format(nmap=nmap), output)
    to_int(output)

    return output

def to_int(data, key_or_idx=None):
    """ Change ints-as-strs in nested python lists/dicts to ints
    
        NB: modifies data in place and returns None
    """
    if key_or_idx is None:
        value = data
    else:
        value = data[key_or_idx]
    if isinstance(value, list):
        for idx, v in enumerate(value):
            to_int(value, idx)
    elif isinstance(value, dict):
        for k, v in value.iteritems():
            to_int(value, k)
    elif isinstance(value, str):
        if value.isdigit():
            data[key_or_idx] = int(value)
        return

def main():
    if len(sys.argv) == 2:
        if sys.argv[1] == 'export':
            output = get_nodemap_info()
            yaml_out = dump(output, Dumper=Dumper)
            print(yaml_out)
    if len(sys.argv) == 3:
        if sys.argv[1] == 'diff':
            with open(sys.argv[-1]) as f:
                # load it so we know its valid yaml and sorted:
                data = load(f.read(), Loader=Loader)
                left = dump(data).split('\n')
            right = get_nodemap_info()
            right = dump(right).split('\n')
            for diff in difflib.context_diff(left, right):
                print(diff)

    else:
        print('ERROR: invalid commandline, help follows:')
        print(__doc__)
    
if __name__ == '__main__':
    main()
