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
import time
import logging
import uascan_lib

""" Take a UserAgent string and test if it may support SHA256, and output the result as a integer between 0 and 2.

:param package: string | (Free form UserAgent)
:type package: Application
:rtype: integer | (0-1)

Valid Input: Any free form UserAgent string
Valid Output: 0 - Supported, 1 - Support Unknown, 2 - Not Supported
"""


def get_cmdline():
    if len(sys.argv) > 1:
        # This will join the arguments if it was not provided as a single argument
        ua_string = ' '.join(sys.argv[1:])
        return ua_string
    else:
        return None


def get_stdin():
    # Let's get input from Pipe, if no input for 1 second, we exit.
    timeout_seconds = 1
    end_time = int(round(time.time() + timeout_seconds))
    while True:
        line = sys.stdin.read()
        if line != '':
            lines = line.replace('\r', '\n').replace('\n\n', '\n').split('\n')
            return lines
        else:
            if int(round(time.time())) >= end_time:
                return None
    return None


if __name__ == '__main__':

    try:
        # debug_enabled   : True = Output Debug Information           | False = No Debug Information
        # identify_unknown: True = Output If UA was identified or not | False = Don't output if UA was identified
        debug_enabled = False
        identify_unknown = False
        # Initialize UserAgent Scanner class
        ua_scanner = uascan_lib.UAscanner(debug=debug_enabled, identify_unknown=identify_unknown)

        # We'll setup this applications logging separate from the above class.
        app_logger = logging.getLogger('UAScannerApp1')
        app_logger.setLevel(logging.DEBUG)
        app_logger.addHandler(logging.NullHandler())
        app_logger_stream = logging.StreamHandler()
        app_logger_stream.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
        if debug_enabled:
            app_logger_stream.setLevel(logging.DEBUG)
        else:
            app_logger_stream.setLevel(logging.ERROR)
        app_logger.addHandler(app_logger_stream)

        app_logger.debug('Processing command line')
        cmdline = get_cmdline()
        if cmdline is not None:
            app_logger.debug('Command line input detected')
            # If the user provided us commandline input, we will only test that.
            sys.stdout.write('{0}\n'.format(ua_scanner.uacheck_string(cmdline)))
            exit(0)
        else:
            if os.isatty(0):
                app_logger.debug('TTY detected on STDIN, we do not support user typed input. Printing help.')

                # We have a TTY, the user would need to hand key input. This will not work.
                sys.stderr.write('UserAgent SHA256 Compatibility Scanner - App 1\n'
                                 '==============================================\n'
                                 'This application is intended to provide an application example\n'
                                 'that will either single line User Agent strings from the\n'
                                 'command line, or read one or more single line User Agent\n'
                                 'strings from STDIN.\n\n'
                                 'This application requires input of a UserAgent either:\n'
                                 '    1) On the Commandline\n'
                                 '    2) From a Pipe\n'
                                 '\n')
                sys.stderr.write('Example 1:\n    {0} {1}\n\n'.format(
                    sys.argv[0], "'Mozilla/5.0 (Windows NT 6.3) Firefox/36.0'"))
                sys.stderr.write('Example 2:\n    echo -n {1} | {0}\n\n'.format(
                    sys.argv[0], "'Mozilla/5.0 (Windows NT 6.3) Firefox/36.0'"))
                sys.stderr.write('Example 3:\n    cat useragents.txt | {0}\n\n'.format(sys.argv[0]))
                sys.stderr.write('Note: Blank lines are considered to be valid user agents. If this is\n'
                                 '      not desired please remove any blank lines prior to processing\n\n')
                exit(0)
            else:
                # We have a pipe, read the input and process each individually.
                # If the pipe has no data input for 1 second, we exit.
                while True:
                    ua_lines = get_stdin()
                    if ua_lines is None:
                        exit(0)
                    else:
                        for ua in ua_lines:
                            sys.stdout.write('{0}\n'.format(ua_scanner.uacheck_string(ua)))
    except IOError:
        # This is needed to avoid a stacktrace should someone cut out stdout while we're working, like...
        # cat ua_agents.txt | uascan_lib.py | head -n 2
        # We do not consider this type of usage an error so we will not treat it as one.
        exit(0)
    except KeyboardInterrupt:
        # In case someone wants to CTRL+C, no need to print the stacktrace, just stop.
        # We will not consider a user's CTRL+C an error.
        exit(0)
