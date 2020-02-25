#!/usr/bin/env python
""" Export live lustre network information as yaml in a minimal format suitable for `lnetctl import`.

    Usage:
        lnet.py export
        lnet.py diff FILE
    
    This essentially strips unneeded/transient info such as stats etc from `lnetctl export` output.
    Note the format the lustre manual describes for the `import` command is NOT actually the same as
    is produced by the `otuput` command, although tests show the `import` command will accept either.
    The format used here matches the exported format, as that contains more info (such as NIDs) which
    while not *required* for lnet operation will allow unexpected configuration changes to be identified.

    There is also the `lnetctl show` command, but this does not export route information.

    NB: Needs sudo rights!
"""

from __future__ import print_function
__version__ = "0.0"

import sys, subprocess, pprint, datetime, os, difflib

# pyyaml:
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# define fields we want:
ROUTES_FIELDS = ('gateway', 'hop', 'net')         # hop not  required (=> -1) but useful for diff?
LOCAL_NI_FIELDS = ('interfaces', 'nid', 'status') # status not required but diff? How do we set "down"?

def cmd(args):
    proc = subprocess.Popen(args, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) # need shell else lnetctl not found
    stdout, stderr = proc.communicate()
    return stdout, stderr

def get_lnet_info():
    """ TODO """
    # read the system's state as yaml:
    sout, serr = cmd('sudo lnetctl export')
    if serr is not None:
        raise Exception(serr)
    
    # convert to a python datastructure:
    data = load(sout, Loader=Loader)
    
    # filter:
    output = {'net':[], 'route':[]}
    for route in data['route']:
        output['route'].append(dict((k, v) for (k, v) in route.iteritems() if k in ROUTES_FIELDS))
    for net in data['net']:
        if net['net type'] != 'lo':
            outnet = {'net type':net['net type'],
                      'local NI(s)':[],}
            for local_ni in net['local NI(s)']:
                outnet['local NI(s)'].append(dict((k, v) for (k, v) in local_ni.iteritems() if k in LOCAL_NI_FIELDS))
            output['net'].append(outnet)
    
    return output

def main():

    # get system info:
    live_data = get_lnet_info()
    live_time = datetime.datetime.now().isoformat()
    live_yaml = dump(live_data, Dumper=Dumper)        

    if len(sys.argv) == 2 and sys.argv[1] == 'export':
        print(live_yaml)
    
    elif len(sys.argv) == 3 and sys.argv[1] == 'diff':
        
        # use file as "from":
        saved_path = sys.argv[-1]
        saved_time = datetime.datetime.fromtimestamp(os.path.getmtime(saved_path)).isoformat()
        with open(saved_path) as f:
            # load it so we know its valid yaml and sorted:
            saved_data = load(f.read(), Loader=Loader)
            saved_yaml = dump(saved_data)
        
        # diff:
        for diff in difflib.unified_diff(saved_yaml.split('\n'), live_yaml.split('\n'), saved_path, 'live', saved_time, live_time):
            print(diff)
        
    else:
        print('ERROR: invalid commandline, help follows:')
        print(__doc__)
        exit(1)
    

    
    


if __name__ == '__main__':
    main()
