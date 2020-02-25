#!/usr/bin/env python
""" Export lustre network information as yaml in the same format can be imported as lnet.conf
    i.e this is basically the same as the "net" and "route" sections of `lnetctl export`
    Note `lnetctl show` does not show routing info.

    Note the format for "import" described in the lustre manual is NOT the same as the exported format,
    although the manual says the exported format is suitable for import! This leaves us guessing a bit ...
    this uses the exported format, as that contains more info, which is probably unnecessary (e.g. NIDs) but gives us
    a better chance of catching misconfigurations.

    TODO:

    NB: needs sudo rights!
"""

from __future__ import print_function
__version__ = "0.0"

import sys, subprocess, pprint

# pyyaml:
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# define a singleton like None
class All():
    pass

ROUTES_FIELDS = ('gateway', 'hop', 'net')         # NB hop can actually be ommited => -1 but again better to define?
LOCAL_NI_FIELDS = ('interfaces', 'nid', 'status') # NB status isn't really a requied field but would be useful for diff? How do we set down?



def cmd(args):
    proc = subprocess.Popen(args, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE) # need shell else lctl not found
    stdout, stderr = proc.communicate()
    return stdout, stderr

def main():
    sout, serr = cmd('sudo lnetctl export')
    if serr is not None:
        raise Exception(serr)

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
    pprint.pprint(output)


if __name__ == '__main__':
    main()
