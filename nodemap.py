#!/usr/bin/env python
""" Export live lustre nodemap information as yaml.

    Usage:
        nodemap.py export
        nodemap.py diff FILE_A [FILE_B]
        nodemap.py import FILE
        nodemap.py --help
        nodemap.py --version

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

    TODO: note restrictions on NID ranges for import?

"""
from __future__ import print_function
__version__ = "0.0"

import subprocess, pprint, sys, re, ast, difflib, datetime, os,  socket, struct

# pyyaml:
from yaml import load, dump # TODO: use safe_load
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

SAME, CHANGE, ADD, DELETE = range(4)

def ips(start, end):
    """ Given two IPv4 dot-decimal strings, return a sequence of all IP addresses in that range (inclusive of start and end) """
    # Modified from https://stackoverflow.com/a/17641585/916373
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end + 1)]

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

def partition(left, right):
    """ Given two dicts, return a tuple of sorted keys:
        (left_only, both, right_only)
    """
    leftkeys, rightkeys = set(left.keys()), set(right.keys())
    return (sorted(leftkeys - rightkeys), sorted(leftkeys & rightkeys), sorted(rightkeys - leftkeys))

def diff(left, right):
    """ Find differences between nested dicts `left` and `right`.

        Returns a sequence of (keyparts, action, value) where TODO:.
        i.e. unchanged keys/values are not referenced.

        Note that `value` is the old value for deleted keys.

        Modified values are represented as a DELETE followed by an ADD.
    """
    stack = [([], left, right)]
    results = []
    while stack:
        keyparts, left, right = stack.pop()
        if isinstance(left, dict) and isinstance(right, dict):
            leftkeys, rightkeys = set(left.keys()), set(right.keys())
            for k in sorted(leftkeys | rightkeys):
                if k in leftkeys and k not in rightkeys:
                    results.append((keyparts + [k], 'DEL', None))
                    stack.append((keyparts + [k], left[k], {}))
                elif k in rightkeys and k not in leftkeys:
                    results.append((keyparts + [k], 'ADD', None))
                    stack.append((keyparts + [k], {}, right[k]))
                else:
                    if left[k] != right[k]:
                    #print('both, left != right', type(left[k]), type(right[k]))
                    #results.append((keyparts + [k], 'DEL', left[k]))
                    #results.append((keyparts + [k], 'ADD', right[k]))
                        stack.append((keyparts + [k], left[k], right[k]))
        else:
            if left != right:
                results.append((keyparts, 'DEL', left))
                results.append((keyparts, 'ADD', right))
    return results
        
    
# changes for nodemap.*:
nodemap_actions = {'nodemap_activate':"lctl nodemap_activate {new}", # can just overwrite old value
                   'nodemap_add':"lctl nodemap_add {name}",
                   'nodemap_del':"lctl nodemap_del {name}",
                   'set_fileset':"lctl nodemap_set_fileset --name {nodemap} --fileset {new}",
                   'nodemap_modify':"lctl nodemap_modify --name {nodemap} --property {property} --value {new}",
                   'change_idmap':"lctl nodemap_{mode}_idmap --name {nodemap} --idtype {idtype} --idmap {client_id}:{fs_id}",
                   'change_range':"lctl nodemap_{mode}_range --name {nodemap} --range {nid}",
                   
}
NODEMAP_MODIFY = 'admin_nodemap squash_gid squash_uid trusted_nodemap deny_unknown'.split()
NODEMAP_IGNORE = 'audit_mode exports id map_mode sepol'.split()
    
#     idmap: TODO
#     ranges: TODO    

def change(diff):
    """ NB: this is more nodemap-specific, e.g. knows that when nodemap don't need to recurse into parameters, just delete the whole thing.
    """

    if diff.keys() != ['nodemap']:
        raise ValueError("expected only key 'nodemap', got %s" % diff.keys())
    
    func = print # TODO: DEBUG:

    nodemaps = diff['nodemap']
    for nodemap in nodemaps:
        if nodemap == 'active':
            old, new = nodemaps[nodemap]
            func(nodemap_actions['nodemap_activate'].format(new=new))
        else:
            if isinstance(nodemaps[nodemap], tuple): # have an add or deletion
                print('DEBUG: in old/new path')
                old, new = nodemaps[nodemap]
                if new is None: # delete
                    func(nodemap_actions['nodemap_del'].format(name=nodemap))
                elif old is None: # add
                    func(nodemap_actions['nodemap_add'].format(name=nodemap))
                else:
                    raise ValueError('unexpected case for %s: %r' % (nodemap, nodemaps[nodemap]))
            else:
                new = nodemaps[nodemap]
            # now deal with properties:
            if new is not None: # don't need to handle parameters on deleted nodemaps
                print('DEBUG: in new path')
                for param_name in new:
                    if isinstance(new[param_name], tuple): # changing existing nodemap
                        new_value = new[param_name][1]
                    else: # adding new nodemap
                        new_value = new[param_name]
                    if param_name == 'fileset':
                        func(nodemap_actions['set_fileset'].format(nodemap=nodemap, new=new_value))
                    elif param_name in NODEMAP_MODIFY:
                        func(nodemap_actions['nodemap_modify'].format(nodemap=nodemap, property=param_name, new=new_value))
                    elif param_name in NODEMAP_IGNORE:
                        pass # TODO: include verbose and ignore options?
                    elif param_name == 'idmap':
                        if isinstance(new[param_name], tuple): 
                            # cheat - just delete all old ones
                            for old_idmap in new[param_name][0]:
                                func(nodemap_actions['change_idmap'].format(mode='del', nodemap=nodemap, **old_idmap))
                            new_idmaps = new[param_name][1]
                        else:
                            new_idmaps = new[param_name]
                        # now add new ones
                        for new_idmap in new_idmaps:
                            func(nodemap_actions['change_idmap'].format(mode='add', nodemap=nodemap, **new_idmap))
                    elif param_name == 'ranges':
                        if isinstance(new[param_name], tuple): 
                            # cheat - just delete all old ones
                            for old_rng in new[param_name][0]:
                                start_addr, _, netname = old_rng['start_nid'].partition('@')
                                end_addr = old_rng['end_nid'].partition('@')[0] # net name must be the same
                                for addr in ips(start_addr, end_addr):
                                    func(nodemap_actions['change_range'].format(mode='del', nodemap=nodemap, nid='{addr}@{netname}'.format(addr=addr, netname=netname)))
                            new_ranges = new[param_name][1]
                        else:
                            new_ranges = new[param_name]
                        for new_rng in new_ranges:
                            start_addr, _, netname = new_rng['start_nid'].partition('@')
                            end_addr = new_rng['end_nid'].partition('@')[0] # net name must be the same
                            for addr in ips(start_addr, end_addr):
                                func(nodemap_actions['change_range'].format(mode='add', nodemap=nodemap, nid='{addr}@{netname}'.format(addr=addr, netname=netname)))

def diff_to_yaml(diff, keyparts=None, marker=''):
    """ Return a multi-line string of pseudo-yaml from a nested dict produced by `diff()`.
    
        Output is like a yaml version of the original dicts, except that deletions are prefixed with '<'
        and additions with '>'. Note that:
            - Modified values are shown as a deletion and addition.
            - Keys present in both "left" and "right" sides (i.e. needed for changes at deeper nesting levels) are not prefixed with anything.
    """

    keyparts = [] if keyparts is None else keyparts
    indent = '  '
    lines = []
    for k in diff:
        if isinstance(diff[k], dict):
            lines.append(indent * len(keyparts) + '%s:' % k) # key
            lines.append(diff_to_yaml(diff[k], keyparts=keyparts + [k])) # value
        elif isinstance(diff[k], tuple): # is a left/right pair:
            left, right = diff[k]
            if isinstance(left, dict):
                lines.append('<' + ' ' * len(keyparts) + '%s:' % k) # key
                lines.append(diff_to_yaml(left, keyparts=keyparts + [k], marker='<')) # value
            elif left is not None:
                lines.append('<' + indent * len(keyparts) + '%s: %s' % (k, left)) # key and value
            if isinstance(right, dict):
                lines.append('>' + indent * len(keyparts) + '%s:' % k)
                lines.append(diff_to_yaml(right, keyparts=keyparts + [k], marker='>'))
            elif right is not None:
                lines.append('>' + indent * len(keyparts) + '%s: %s' % (k, right))
        else:
            lines.append(marker + indent * len(keyparts) + '%s: %s' % (k, diff[k]))
    return '\n'.join(lines)
            
def exit_bad_cli():
    exit('ERROR: invalid command line.\n\n%s\n' % __doc__.split('\n\n')[1])

def main():

    if len(sys.argv) < 2:
        exit_bad_cli()
    elif sys.argv[1] == 'export' and len(sys.argv) == 2:
        live_nodemap = load_live()
        live_yaml = dump(live_nodemap, Dumper=Dumper, default_flow_style=False)
        print(live_yaml)
    elif sys.argv[1] == 'diff' and len(sys.argv) in (3, 4):
        nodemap_a = load_live() if len(sys.argv) == 3 else load_from_file(sys.argv[2])
        nodemap_b = load_from_file(sys.argv[-1])
        differences = diff(nodemap_a, nodemap_b)
        pprint.pprint(differences)
        #print(diff_to_yaml(differences))
    elif sys.argv[1] == 'import' and len(sys.argv) in (3, 4): # NB 4-arg form only for testing!!
        nodemap_a = load_live() if len(sys.argv) == 3 else load_from_file(sys.argv[2])
        nodemap_b = load_from_file(sys.argv[-1])
        differences = diff(nodemap_a, nodemap_b)
        # TODO: replace with diff_to_yaml
        #pprint.pprint(differences)
        print(diff_to_yaml(differences))
        print('----')
        change(differences)
    
    elif sys.argv[1] == '--version' and len(sys.argv) == 2:
        print(__version__)
    elif sys.argv[1] == '--help' and len(sys.argv) == 2:
        print(__doc__)
    else:
        exit_bad_cli()
    
if __name__ == '__main__':
    main()
