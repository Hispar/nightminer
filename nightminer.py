# The MIT License (MIT)
#
# Copyright (c) 2014 Richard Moore
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


# What is this?
#
# NightMiner is meant to be a simple, one-file implementation of a stratum CPU
# miner for CryptoCurrency written in Python favouring understandability
# over performance.
#
# It was originally designed for scrypt-based coins, and has been extended to
# include support for sha256d.
#
# Try running nightminer with the -P and -d to see protocol and debug details
#
# Required reading:
#   Block Hashing Algorithm - https://litecoin.info/Block_hashing_algorithm
#   Stratum Mining Protocol - http://mining.bitcoin.cz/stratum-mining/
#   Scrypt Algorithm        - http://www.tarsnap.com/scrypt/scrypt.pdf
#   Scrypt Implementation   - https://code.google.com/p/scrypt/source/browse/trunk/lib/crypto/crypto_scrypt-ref.c

import sys

import logging

from algos import set_scrypt_library
from algos.script import SCRYPT_LIBRARY
from nightminer.constants import USER_AGENT, VERSION, ALGORITHMS, ALGORITHM_SCRYPT, SCRYPT_LIBRARIES, LEVEL_DEBUG
import argparse

# CLI for cpu mining
from nightminer.miner import Miner
from nightminer.tests.test_subscription import test_subscription

logging.basicConfig(filename='miner.log', level=logging.DEBUG)

if __name__ == '__main__':

    # Parse the command line
    parser = argparse.ArgumentParser(description="CPU-Miner for Cryptocurrency using the stratum protocol")

    parser.add_argument('-o', '--url', help='stratum mining server url (eg: stratum+tcp://foobar.com:3333)')
    parser.add_argument('-u', '--user', dest='username', default='', help='username for mining server',
                        metavar="USERNAME")
    parser.add_argument('-p', '--pass', dest='password', default='', help='password for mining server',
                        metavar="PASSWORD")

    parser.add_argument('-O', '--userpass', help='username:password pair for mining server',
                        metavar="USERNAME:PASSWORD")

    parser.add_argument('-a', '--algo', default=ALGORITHM_SCRYPT, choices=ALGORITHMS,
                        help='hashing algorithm to use for proof of work')

    parser.add_argument('-B', '--background', action='store_true', help='run in the background as a daemon')

    parser.add_argument('-q', '--quiet', action='store_true', help='suppress non-errors')
    parser.add_argument('-P', '--dump-protocol', dest='protocol', action='store_true', help='show all JSON-RPC chatter')
    parser.add_argument('-d', '--debug', action='store_true', help='show extra debug information')

    parser.add_argument('-v', '--version', action='version',
                        version='%s/%s' % (USER_AGENT, '.'.join(str(v) for v in VERSION)))

    options = parser.parse_args(sys.argv[1:])

    message = None

    # Get the username/password
    username = options.username
    password = options.password

    if options.userpass:
        if username or password:
            message = 'May not use -O/-userpass in conjunction with -u/--user or -p/--pass'
        else:
            try:
                (username, password) = options.userpass.split(':')
            except Exception as e:
                message = 'Could not parse username:password for -O/--userpass'

    # Was there an issue? Show the help screen and exit.
    if message:
        parser.print_help()
        print(message)
        sys.exit(1)

    # Set the logging level
    DEBUG = False
    if options.debug:
        DEBUG = True
    if options.protocol:
        DEBUG_PROTOCOL = True
    if options.quiet:
        QUIET = True

    if DEBUG:
        for library in SCRYPT_LIBRARIES:
            set_scrypt_library(library)
            test_subscription()

        # Set us to a faster library if available
        set_scrypt_library()
        if options.algo == ALGORITHM_SCRYPT:
            logging.debug('Using scrypt library %r' % SCRYPT_LIBRARY)

    # The want a daemon, give them a daemon
    if options.background:
        import os

        if os.fork() or os.fork():
            sys.exit()

    # Heigh-ho, heigh-ho, it's off to work we go...
    if options.url:
        logging.info('start miner')
        miner = Miner(options.url, username, password, algorithm=options.algo)
        miner.serve_forever()
