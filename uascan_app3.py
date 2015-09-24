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
import re
import sys
import logging
import uascan_lib

if __name__ == '__main__':
    debug = False
    # S3 Log Format Regex
    s3log_regex = re.compile(r'^(.*?) (.*?) \[(.*?)\] (.*?) (.*?) (.*?) (.*?) (.*?) "(.*?)" (.*?) (.*?) (.*?) (.*?) (.*?) (.*?) "(.*?)" "(.*?)" (.*)$')

    # S3 Server Log Access Format: http://docs.aws.amazon.com/AmazonS3/latest/dev/LogFormat.html
    #     1: Canonical user ID of bucket owner
    #     2: Bucket Processed (or object copied too)
    #     2: Date/Time %d/%b/%Y:%H:%M:%S %z
    #     3: Remote IP
    #     4: Canonical user ID of requester, or "Anonymous"
    #     5: Request ID
    #     6: Operation
    #     7: Object Key
    #     8: Request-URI
    #     9: HTTP status
    #    10: Error Code
    #    11: Bytes Sent
    #    12: Object Size
    #    13: Total Time
    #    14: Turn-Around Time
    #    15: Referrer
    #    16: User-Agent
    #    17: Version Id
    try:
        if len(sys.argv) <= 1:
            sys.stderr.write('UserAgent SHA256 Compatibility Scanner - App 3\n'
                             '==============================================\n'
                             'This application is intended to provide an application example\n'
                             'that will read an S3 access log file. It will extract the\n'
                             'User Agent string from each line and process them for compatibility.\n\n'
                             'This application requires input of:\n'
                             '    1) a S3 access log file, which is specified on the command line.\n'
                             '\n')
            sys.stderr.write('    Example: {0} {1}\n\n'.format(sys.argv[0], 's3_access.log'))
            sys.stderr.write('Note: Blank lines are considered invalid and will be skipped.\n\n')
            exit(1)

        ua_file = ' '.join(sys.argv[1:])

        # debug_enabled   : True = Output Debug Information           | False = No Debug Information
        # identify_unknown: True = Output If UA was identified or not | False = Don't output if UA was identified
        debug_enabled = False
        identify_unknown = False
        # Initialize UserAgent Scanner class
        ua_scanner = uascan_lib.UAscanner(debug=debug_enabled, identify_unknown=identify_unknown)

        # We'll setup this applications logging separate from the above class.
        app_logger = logging.getLogger('UAScannerApp3')
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
            line_regexed = s3log_regex.match(line_in)
            # If line_regexed is None then our regex did not match.
            if line_regexed is not None:
                # Extract the groups captured by the regex
                line_regex_group = s3log_regex.match(line_in).groups()
                log_bucket = line_regex_group[2]
                log_ip = line_regex_group[3]
                log_ua = line_regex_group[16]

                app_logger.debug('DEBUG UA String: {0}'.format(log_ua))
                sys.stdout.write('{0}\n'.format(ua_scanner.uacheck_string(log_ua)))
        log_filein.close()
    except KeyboardInterrupt:
        # In case someone wants to CTRL+C, no need to print the stacktrace, just stop.
        # We will not consider a user's CTRL+C an error.
        exit(0)
