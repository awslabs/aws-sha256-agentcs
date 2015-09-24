#!/usr/bin/env python
#
#   Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import os
import sys
import logging
import uascan_lib

if __name__ == '__main__':
    debug = False
    try:
        if len(sys.argv) <= 1:
            sys.stderr.write('UserAgent SHA256 Compatibility Scanner - App 2\n'
                             '==============================================\n'
                             'This application is intended to provide an application example\n'
                             'that will read a list of single line User Agent strings from a\n'
                             'file and process them for compatibility.\n\n'
                             'This application requires input of a UserAgent from:\n'
                             '    1) A file, which is specified on the command line.\n'
                             '\n')
            sys.stderr.write('    Example: {0} {1}\n\n'.format(sys.argv[0], 'uafile.txt'))
            sys.stderr.write('Note: Blank lines are considered to be valid user agents. If this is\n'
                             '      not desired please remove any blank lines prior to processing.\n\n')
            exit(1)

        ua_file = ' '.join(sys.argv[1:])

        # debug_enabled   : True = Output Debug Information           | False = No Debug Information
        # identify_unknown: True = Output If UA was identified or not | False = Don't output if UA was identified
        debug_enabled = False
        identify_unknown = False
        # Initialize UserAgent Scanner class
        ua_scanner = uascan_lib.UAscanner(debug=debug_enabled, identify_unknown=identify_unknown)

        # We'll setup this applications logging separate from the above class.
        app_logger = logging.getLogger('UAScannerApp2')
        app_logger.setLevel(logging.DEBUG)
        app_logger.addHandler(logging.NullHandler())
        app_logger_stream = logging.StreamHandler()
        app_logger_stream.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
        if debug_enabled:
            app_logger_stream.setLevel(logging.DEBUG)
        else:
            app_logger_stream.setLevel(logging.ERROR)
        app_logger.addHandler(app_logger_stream)

        log_filein = open(ua_file, "r")
        while not log_filein.tell() == os.fstat(log_filein.fileno()).st_size:
            line_in = log_filein.readline().strip('\n')
            line_in = line_in.split(' ')
            line_string = ' '.join(line_in[1:])
            app_logger.debug('DEBUG UA String: {0}'.format(line_string))
            sys.stdout.write('{0}\n'.format(ua_scanner.uacheck_string(line_string)))
        log_filein.close()
    except KeyboardInterrupt:
        # In case someone wants to CTRL+C, no need to print the stacktrace, just stop.
        # We will not consider a user's CTRL+C an error.
        exit(0)
