#!/usr/bin/env python
""" Export live lustre nodemap information as yaml.

    Usage:
        nodemap.py export
        nodemap.py diff FILE_A [FILE_B]
        nodemap.py import FILE

    The first form prints the current lustre nodemap configuration to stdout as yaml.
    The second form WHAT'S OUTPUT??

    
    In the yaml output:
    - Simple values (i.e. which aren't themselves mappings or lists) are either ints or strings.
    - Lists and mappings are sorted to ensure predictable output.

    WIP:
        nodemap.py import FILE
        nodemap.py diff FILE_A [FILE_B]

    TODO: by default (?) ignore nodemap.*.exports, nodemap.*.sepol
    TODO: provide stdin for import?
    TODO: provide functions to change things
    TODO: have to work out how to get nodemaps themseles in there!
    TODO: import will need sudo!

    note nodemap.*.ranges will change if instances are recreated, but that's ok from an ansible PoV.

    TODO: internal canonical form means:
    - process keys in sorted order (have to do this at each operation as using normal dicts
    - lists are sorted (b/c lustre essentially treats them as unordered)
    - simple values (i.e. not dicts or lists) are either str or int - latter needs to be explicitly converted

"""
from __future__ import print_function
__version__ = "0.0"

import subprocess, pprint, sys, re, ast, difflib, datetime, os

# pyyaml:
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

SAME, CHANGE, ADD, DELETE = range(4)

def cmd(cmdline):
    """ Run a space-separated command and return its stdout/stderr.

        Uses shell, blocks until subprocess returns.
    """
    proc = subprocess.Popen(cmdline, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) # need shell else lctl not found
    stdout, stderr = proc.communicate()
    return stdout, stderr

def lctl_get_param(item, output):
    """ Get a lustre parameter.

        A wrapper for `lctl get_param`.
    
        Args:
            item: str, path to parameter to query - see `lctl get_param --help`
            output: dict which will be modified with results, may be empty.
        
        The output dict is a nested datastructure containing dicts, lists (either of which may be empty), strs or ints.
        Dict keys are always strs. The structure of this (i.e. the nested keys) follows the path-line structure of lctl
        parameters. The same dict may be passed to this function multiple times to build up results from several parameters.
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
                dotted_param, _ , value = line.partition('=')
                parts = dotted_param.split('.')
                parents = parts[:-1]
                param = parts[-1]
                r = output
                for p in parents:
                    r = r.setdefault(p, {})
                r[param] = value

            else:
                accumulate.append(line)
    return output
    
def load_live():
    """ Load live nodemap information.
    
        Returns a nested datastructure in normalised form.
    """
    output = {}
    lctl_get_param("nodemap.*", output)
    s, e = cmd("lctl nodemap_info",) # need quoting to avoid shell expansion!
    nodemaps = [n.split('.')[-1] for n in s.strip().split('\n')]
    #print(nodemaps)
    for nmap in nodemaps:
        lctl_get_param("nodemap.{nmap}.*".format(nmap=nmap), output)
    to_int(output)
    deep_sort(output)

    return output

def load_from_file(path):
    """ Load nodemap info from a file.
    
        Returns a nested datastructure in normalised form.
    """
    with open(path) as f:
        nodemap = load(f.read(), Loader=Loader)
        deep_sort(nodemap)
        # to_int() not needed as file will have been saved with ints
    return nodemap

def deep_sort(data):
    """ In-place sort of any lists in a nested dict/list datastructure. """
    if isinstance(data, list):
        data.sort()
        for item in data:
            deep_sort(item)
    elif isinstance(data, dict):
        for item in data.itervalues():
            deep_sort(item)
    return None

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

def flatten(data):
    stack = [([], data)]
    currkey = []
    result = []
    while stack:
        keyparts, data = stack.pop(0)
        #print('keyparts:', keyparts)
        for k in sorted(data.keys()):
            if isinstance(data[k], dict):
                stack.append((keyparts + [k], data[k]))
                #print('stack append', keyparts + [k])
            else:
                result.append((keyparts + [k], data[k]))
                #print('results append', keyparts + [k])
    return result

def diff(left, right):
    """ TODO """


    # print(sorted(left['nodemap'].keys()))
    # print(sorted(right['nodemap'].keys()))
    # exit()

    # for lnodemaps in left['nodemap'].keys():
    #     pr

    # left_flat = flatten(left)
    # right_flat = flatten(right)


    stack = [(left, right)]
    result = {}
    while stack:
        left, right = stack.pop(0)
        for k in sorted(set(left.keys()).union(right.keys())):
            if k in left and k not in right:
                result[k] = (left[k], None) # delete
            elif k in right and k not in left:
                # add: depends on whether value is a dict or not
                #if isinstance(right[k], dict):
                #    TODO
                #else:
                    result[k] = (None, right[k])
            elif left[k] != right[k]:
                # change: depends on whether value is a dict or not
                if isinstance(left[k], dict): # assume right is too!
                    stack.append((left[k], right[k]))
                    result[k] = {}
                    result = result[k]
                else:
                    result[k] = (left[k], right[k])
            else:
                result[k]
    return result

# changes for nodemap.*:
def nodemap_active(new):
    # can just overwrite old value
    print("lctl nodemap_activate new")

#     admin_nodemap: lctl nodemap_modify --name NAME --property admin --value VALUE
#     squash_gid: lctl nodemap_modify --name NAME --property squash_gid --value VALUE
#     squash_uid lctl nodemap_modify --name NAME --property squash_uid --value VALUE
#     trusted_nodemap: lctl nodemap_modify --name NAME --property trusted --value VALUE
#     deny_unknown: lctl nodemap_modify --name NAME --property deny_unknown --value VALUE
def nodemap_property(nodemap_name, property, value):
    # can just overwrite old value
    print("lctl nodemap_modify --name {nodemap_name} --property {property} --value {new}".format(nodemap_name=nodemap_name, property=property, value=value))

#     fileset: lctl nodemap_set_fileset --name NAME --fileset VALUE
def nodemap_fileset(nodemap_name, value):
    print("lctl nodemap_set_fileset --name {nodemap} --fileset {new}".format(nodemap_name=nodemap_name, value=value))

# NAME: lctl nodemap_add / _del NAME
#     (property ones are always set, just possibly to a default value)

#     audit_mode: IGNORE
#     exports: IGNORE 
#     id: IGNORE 
#     map_mode: IGNORE
#     sepol: IGNORE
    
#     (this is also always set, just might be to '')
    
#     idmap: TODO
#     ranges: TODO    


# def diff_to_yaml(diff):
#     """ take a diff sequence and generate pseudo-yaml output """

#     # can assume keyparts are sorted, b/c inputs to diff will be
#     current = []
#     for d in diff:
#         keyparts, left, right = d
#         if left is None:
#             symbol = '-'
#             out = right
#         elif right is None:
#             symbol = '+'
#             out = left
#         else:
#             symbol = '?'
#             out = right
#         print(symbol, '.'.join(keyparts), ':')
#         out_yaml_lines = dump(out).split('\n')
#         out_formatted = ['%s %s' % (symbol, s) for s in out_yaml_lines]
#         print('\n'.join(out_formatted))
        
#         # # count number of matching parts
#         # for i in range(len(keyparts)): # TODO: what if current < keyparts:
#         #     if len(current) == 0 or i == (len(current) - 1):
#         #         break
#         #     elif keyparts[i] != current[i]:
#         #         break
#         # start = keyparts[:i]
#         # from_end = i - len(keyparts)
#         # end = keyparts[from_end:]
#         # indent = len('.'.join(start))
#         # print(' ' * indent + '.'.join(end))
#         # current = keyparts

#     # nah so behaviour has to depend on whether the value is a dict or not

def main():

    if len(sys.argv) < 2:
        print('ERROR: invalid commandline, help follows:')
        print(__doc__)
        exit(1)

    live_nodemap = load_live()
    if sys.argv[1] == 'export':
        live_yaml = dump(live_nodemap, Dumper=Dumper, default_flow_style=False)
        print(live_yaml)
    # DEBUG
    elif sys.argv[1] == 'debug':
        for v in flatten(live_nodemap):
            print(v)
        exit()
    elif sys.argv[1] == 'diff':
        if len(sys.argv) == 4:
            nodemap_a = load_from_file(sys.argv[2])
            nodemap_b = load_from_file(sys.argv[3])
        elif len(sys.argv) == 3:
            nodemap_a = live_nodemap
            nodemap_b = load_from_file(sys.argv[2])
        differences = diff(nodemap_a, nodemap_b)
        pprint.pprint(differences)
        #diff_to_yaml(differences)
        #print(difference)

    elif sys.argv[1] == 'import':
        import_nodemap = load_from_file(sys.argv[2])
        for difference in diff(live_nodemap, import_nodemap):
            print(difference)
    else:
        exit('incorrect command-line')
    
if __name__ == '__main__':
    main()
