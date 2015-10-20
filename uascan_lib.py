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

import re
import os
import sys
import time
import logging
import urllib
import user_agents

""" Take a UserAgent string and test if it may support SHA256, and output the result as a integer between 0 and 2.

:param package: string | (Free form UserAgent)
:type package: Application
:rtype: integer | (0-1)

Valid Input: Any free form UserAgent string
Valid Output: 0 - Supported, 1 - Support Unknown, 2 - Not Supported

"""


class UAscanner(object):

    def __init__(self, debug=False, debug_version=False, debug_handle_stream=True, verbose=0, identify_unknown=False):
        self.debug = debug
        self.verbose = verbose
        self.debug_version = debug_version
        self.identify_unknown = identify_unknown
        self.nullagents = ('', 'null', '(null)', '[null]', '{null}')

        self.logger = logging.getLogger('UAScanner')
        self.logger.setLevel(logging.DEBUG)
        self.logger.addHandler(logging.NullHandler())

        if debug_handle_stream is True:
            # Set debug_handlestream to False if you want to manage the debug output stream within
            # your application instead of allowing UAScanner to manage it.
            my_logger_stream = logging.StreamHandler()
            if debug is True:
                # We will print debug message if requested
                my_logger_stream.setLevel(logging.DEBUG)
            else:
                # Default is to not print debug messages
                my_logger_stream.setLevel(logging.ERROR)
            my_logger_stream.setFormatter(logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(my_logger_stream)

        self.useragents_support_unsupported = []
        # These are supported applications, CDNs, and bot's that we created regexs to identify.
        self.useragents_support_supported = [
            'aws-internal', 'S3_Console', 'Amazon_CloudFront', 'Akamai_Edge', 'Google_ImageBot',
            'Google_ADsBot', 'CloudFlare_AlwaysOnline', 'Facebook_Platform', 'image_coccoc',
            'MSNBot_Media', 'Exabot', 'Slackbot', 'Slack_ImgProxy', 'Slackbot_LinkExpanding',
            'ElasticBeanstalk']

        # These bots are identified by user-agents library.
        # Move these to regex FIXME
        self.useragents_support_supported_bots = ['bingbot', 'FacebookBot', 'Slurp', 'LinkedInBot', 'TwitterBot',
                                                  'Googlebot']
        self.useragents_support_unknown = [
            'Boto', 'aws-sdk-js', 'aws-sdk-nodejs', 'aws-sdk-go']

        self.vms_java = ['OpenJDK_64-Bit_Server_VM',
                         'IBM_J9_VM',
                         'OpenJDK_Client_VM',
                         'OpenJDK_Server_VM',
                         'Oracle_JRockit(R)',
                         'TwitterJDK_64-Bit_Server_VM',
                         'JVM']

        self.vms_hotspot = ['Java_HotSpot(TM)_64-Bit_Client_VM',
                            'Java_HotSpot(TM)_64-Bit_Server_VM',
                            'Java_HotSpot(TM)_Client_VM',
                            'Java_HotSpot(TM)_Server_VM']

        self.vms_dalvik = ['Dalvik']

        # mvr = Minimum Version Required
        self.vm_mvr_java = '1.6.0_29'
        self.vm_mvr_hotspot = '21'
        self.vm_mvr_dalvik = '1.4'
        self.os_mvr_windowsphone = '7'
        self.os_mvr_macosx = '10.5'
        self.os_mvr_ios = '3'
        self.os_mvr_android = '2.3'
        self.os_mvr_blackberryos = '5'
        self.os_mvr_blackberrytabletos = '2.3'
        self.os_mvr_linux2 = '2'
        self.os_mvr_linux3 = '3'
        self.os_mvr_linux4 = '4'

        # These are all browsers based off of Chrome
        self.chrome_browsers = ['Chrome', 'Chromium', 'Chrome Mobile', 'Chrome Mobile iOS',
                                'Iron', 'Comodo Dragon']

        # These are all browsers based off of Firefox
        self.firefox_browsers = ['Firefox', 'Firefox Alpha', 'Firefox Beta', 'Firefox Mobile', 'Iceweasel',
                                 'Swiftfox', 'Swiftweasel', 'Waterfox', 'TenFourFox']

        # These browsers are special and we will handle if SHA256 is supported for each one.
        # Here the Browser may only exist on Supported OS or OS Support may not be needed or
        # it may depend on an external resource we can not identify like OpenSSL.
        self.browsers_nonstandard = ['Silk', 'SeaMonkey', 'Thunderbird', 'BlackBerry', 'Konqueror',
                                     'Lightning', 'Outlook'] + self.chrome_browsers + self.firefox_browsers

        self.browser_depends_on_os = ['Silk', 'Lightning']

        self.ua_support_true = 0
        self.ua_support_unknown = 1
        self.ua_support_false = 2
        self.ua_regexs = self.get_regexs()
        if not self.test_version_test():
            self.logger.error("VERSION CHECK TEST FAILED....ABORTING...")
            exit(1)

    @staticmethod
    def get_regexs():
        # Here we will load up known regexes for apps not known by the browser ua lib.
        ua_regex_list = list()

        # AWS SDKs
        ua_regex_list.append({
            'name': 'Boto',
            'regex': re.compile(r'^.*(Boto)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'vm': 2, 'vm_ver': 3, 'os': 4, 'os_ver': 5}
        })
        ua_regex_list.append({
            'name': 'Boto3',
            'regex': re.compile(r'^.*(Boto3)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'vm': 2, 'vm_ver': 3, 'os': 4, 'os_ver': 5}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-android',
            'regex': re.compile(r'^.*(aws-sdk-android)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)\/(\w*)(?=(?=\s((?:[a-zA-Z][a-zA-Z]*))(?=_((?:[a-zA-Z][a-zA-Z]*)))?)?).*$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3, 'java_vm': 4, 'java_vm_ver': 5, 'java_ver': 6,
                       'lang': 7, 'region': 8}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-android',
            'regex': re.compile(r'^.*(aws-sdk-android)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)\s+(.*).*$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3, 'java_vm': 4, 'java_vm_ver': 5, 'lang': 6}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-java',
            'regex': re.compile(r'^.*(aws-sdk-java)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)\/(.*)\s+(.*)\/(.*).*$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3, 'java_vm': 4, 'java_vm_ver': 5, 'java_ver': 6,
                       'app': 7, 'app_ver': 8}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-java',
            'regex': re.compile(r'^.*(aws-sdk-java)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)\/(.*)?(?=(?=\s((?:[a-zA-Z][a-zA-Z]*))(?=_((?:[a-zA-Z][a-zA-Z]*)))?)?).*$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3, 'java_vm': 4, 'java_vm_ver': 5, 'java_ver': 6,
                       'lang': 7, 'region': 8}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-java',
            'regex': re.compile(r'^.*(aws-sdk-java)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*).*$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3, 'java_vm': 4, 'java_vm_ver': 5}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-iOS',
            'regex': re.compile(r'^.*(aws-sdk-iOS)\/(.*)\s+(.*)\/(.*)\s+(.*?)[_\s{0,1}].*?(.*?)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3, 'lang': 4, 'region': 5}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-iOS',
            'regex': re.compile(r'^.*(aws-sdk-iOS)\/(.*)\s+(.*)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'os': 2, 'os_ver': 3}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-ruby2',
            'regex': re.compile(r'^.*?(aws-sdk-ruby2)\/(.*?)\s+(.*?)\/(.*?).*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-ruby',
            'regex': re.compile(r'^.*?(aws-sdk-ruby)\/(.*?)\s+(.*)\/(.*?)\s+(.*).*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-dotnet-ios',
            'regex': re.compile(r'^.*?(aws-sdk-dotnet-ios)\/(.*?)\s+\.NET\s+(.*?)\/(.*?)\s+\.NET\s+(Framework)\/(.*?)\s+(OS)\/(.*?)\s+.*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-dotnet-35',
            'regex': re.compile(r'^.*?(aws-sdk-dotnet-35)\/(.*?)\s+\.NET\s+(.*?)\/(.*?)\s+\.NET\s+(Framework)\/(.*?)\s+(OS)\/(.*?)\s+.*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-dotnet-45',
            'regex': re.compile(r'^.*?(aws-sdk-dotnet-45)\/(.*?)\s+\.NET\s+(.*?)\/(.*?)\s+\.NET\s+(Framework)\/(.*?)\s+(OS)\/(.*?)\s+.*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-dotnet',
            'regex': re.compile(r'^.*?(aws-sdk-dotnet)\/(.*?)\s+\.NET\s+(.*?)\/(.*?)\s+\.NET\s+(Framework)\/(.*?)\s+(OS)\/(.*?)\s+.*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-js',
            'regex': re.compile(r'^.*(aws-sdk-js)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-go',
            'regex': re.compile(r'^.*(aws-sdk-go)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-php',
            'regex': re.compile(r'^.*?(aws-sdk-php)\/(.*?)\s+(.*).*?$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'aws_sdk_detail': 2}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-php2',
            'regex': re.compile(r'^.*?(aws-sdk-php2)\/(.*?)\s+(.*).*?$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'aws_sdk_detail': 2}
        })
        ua_regex_list.append({
            'name': 'aws-sdk-nodejs',
            'regex': re.compile(r'^.*(aws-sdk-nodejs)\/(.*)\s+(.*)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'platform': 2, 'platform_ver': 3}
        })

        # AWS Applications/Services
        ua_regex_list.append({
            'name': 'aws-internal',
            'regex': re.compile(r'^(.*)(aws-internal)\/(.*).*?$'),
            'format': {'guid': 0, 'aws_sdk': 1, 'aws_sdk_ver': 2}
        })
        ua_regex_list.append({
            'name': 'AWS_CLI',
            'regex': re.compile(r'^.*(aws-cli)\/(.*)\s+(.*)\/(.*)\s+(.*)\/(.*)$'),
            'format': {'aws_sdk': 0, 'aws_sdk_ver': 1, 'vm': 2, 'vm_ver': 3, 'os': 4, 'os_ver': 5}
        })
        ua_regex_list.append({
            'name': 'S3_Console',
            'regex': re.compile(r'^.*(S3Console)\/(.*).*$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'ElasticBeanstalk',
            'regex': re.compile(r'^(ElasticBeanstalk)-.*$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'S3_Browser',
            'regex': re.compile(r'^.*(S3 Browser)\s+(.*)\s+.*$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'AWSToolkitPackage',
            'regex': re.compile(r'^.*?(AWSToolkitPackage)\.(.*?)\/(.*?)\s+\.NET\s+(.*?)\/(.*?)\s+\.NET\s+(Framework)\/(.*?)\s+(OS)\/(.*?)\s+.*?$'),
            'format': {'application': 0, 'version': 1}
        })

        # CDNs
        ua_regex_list.append({
            'name': 'Akamai_Edge',
            'regex': re.compile(r'^(.*)(Akamai) (Edge).*$'),
            'format': {'type': 0, 'company': 1, 'group': 2}
        })
        ua_regex_list.append({
            'name': 'Amazon_CloudFront',
            'regex': re.compile(r'^(.*)(Amazon) (CloudFront).*$'),
            'format': {'type': 0, 'company': 1, 'group': 2}
        })

        # Bots
        ua_regex_list.append({
            'name': 'image_coccoc',
            'regex': re.compile(r'^.*?(image.coccoc)\/(.*?);.*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'CloudFlare_AlwaysOnline',
            'regex': re.compile(r'^.*(CloudFlare-AlwaysOnline)\/(.*);.*$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'Google_ImageBot',
            'regex': re.compile(r'^.*(Googlebot-Image)\/(.*).*$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'Google_ADsBot',
            'regex': re.compile(r'^.*(AdsBot-Google)\s+(\(.*\)).*$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'MSNBot_Media',
            'regex': re.compile(r'^.*?(msnbot-media)\/(.*?)\s+(.*?)$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'Exabot',
            'regex': re.compile(r'^.*?(Exabot)\/(.*?)\s+(.*?)$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'Facebook_Platform',
            'regex': re.compile(r'^.*(facebookplatform)\/(.*)\s+.*$'),
            'format': {'application': 0, 'version': 1}
        })

        # Slackbot Details: https://api.slack.com/robots
        ua_regex_list.append({
            'name': 'Slackbot_LinkExpanding',
            'regex': re.compile(r'^.*?(Slackbot-LinkExpanding) (.*?)\s+(.*?)$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'Slack_ImgProxy',
            'regex': re.compile(r'^.*?(Slack-ImgProxy) (.*?)\s+(.*?)$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'Slackbot',
            'regex': re.compile(r'^.*?(Slackbot) (.*?)\((.*?)\)$'),
            'format': {'application': 0, 'version': 1}
        })

        # Client applications
        ua_regex_list.append({
            'name': 'CloudBerry_Client',
            'regex': re.compile(r'^.*?(CloudBerryLab\.Base\.HttpUtil\.Client)\s+(.*?)\s+(\(.*?\)).*?$'),
            'format': {'application': 0, 'version': 1}
        })
        ua_regex_list.append({
            'name': 'JetS3t',
            'regex': re.compile(r'^.*(JetS3t)\/(.*)\s+\((.*)\/(.*);\s+(.*);\s+(.*);\s+(.*)\s+(.*)\).*$'),
            'format': {'application': 0, 'version': 1, 'os': 2, 'os_ver': 3, 'arch': 4, 'lang': 5,
                       'java_vm': 6, 'java_vm_ver': 7}
        })
        return ua_regex_list

    @staticmethod
    def nullstring_cleanup(ua):
        return re.sub('[\s+]', '', ua.lower())

    @staticmethod
    def get_major_ver(this_ver):
        this_major_ver = this_ver
        if '.' in this_ver:
            this_major_ver_dict = this_ver.split('.')
            if len(this_major_ver_dict) >= 1:
                this_major_ver = this_major_ver_dict[0]
        return this_major_ver

    @staticmethod
    def get_ev(ua_reg, ua_lis, ua_var):
        # Get Existential Variable.
        # Much like Schrodinger's cat, this variable may or may not exist
        if 'format' in ua_reg:
            if ua_var in ua_reg['format']:
                if len(ua_lis) >= ua_reg['format'][ua_var]:
                    return ua_lis[ua_reg['format'][ua_var]]
        return None

    def unknown_null(self, ua):
        ual = self.nullstring_cleanup(ua)
        # To see if this maybe a null UA we're going to lower and filter out any 'whitespace' chars.
        if ual in self.nullagents:
            # If our UA is blank, all spaces, null or (null) then it is unknown.
            return True
        else:
            return False

    def test_ua(self, ua):
        ua = urllib.unquote_plus(ua)
        if self.unknown_null(ua):
            # We won't run our own regexes on null UAs
            return None, None, None, ua
        else:
            for ua_regex in self.ua_regexs:
                res = ua_regex['regex'].match(ua)
                if res:
                    return ua_regex['name'], ua_regex, res.groups(), ua
            return None, None, None, ua

    def test_version(self, this_version, supported_version):
        match = self.ua_support_unknown

        if self.debug_version:
            self.logger.debug("VDBG DEBUG TEST1A: {0}".format(this_version))
            self.logger.debug("VDBG DEBUG TEST2A: {0}".format(supported_version))

        # Remove all non numberic/period/underscore characters
        # We have no definitive way to compare words or special characters like numbers.
        this_version = re.sub('[^0-9|.|_]+', '', this_version)
        supported_version = re.sub('[^0-9|.|_]+', '', supported_version)

        # Replace all non-numeric characters (except '.') with '.'
        this_version = re.sub('[^0-9|.]+', '.', this_version)
        supported_version = re.sub('[^0-9|.]+', '.', supported_version)

        # Cleanup, remove any double '..' in the version strings from our previous work.
        this_version = re.sub('\.\.', '\.', this_version)
        supported_version = re.sub('\.\.', '\.', supported_version)

        if this_version == '' or supported_version == '':
            return match

        # Remove any trailing (and repeated trailing - or .)
        this_version = this_version.rstrip('-.')

        while len(supported_version) >= 1:
            if supported_version[len(supported_version)-1] != '-':
                break
            else:
                supported_version = supported_version.rstrip('-')

        while len(supported_version) >= 1:
            if supported_version[len(supported_version)-1] != '.':
                break
            else:
                supported_version = supported_version.rstrip('.')

        if this_version == '' or supported_version == '':
            return match

        if self.debug_version:
            self.logger.debug("VDBG DEBUG TEST1B: {0}".format(this_version))
            self.logger.debug("VDBG DEBUG TEST2B: {0}".format(supported_version))

        non_decimal = re.compile(r'[^\d.]+')
        this_version_digits = non_decimal.sub('', this_version)
        supported_version_digits = non_decimal.sub('', supported_version)
        if this_version == this_version_digits and supported_version_digits == supported_version:
            this_versions = this_version_digits.split('.')
            supported_versions = supported_version_digits.split('.')
            for a in xrange(0, len(this_versions)):
                try:
                    this_versions[a] = int(this_versions[a])
                except ValueError:
                    return match
            for a in xrange(0, len(supported_versions)):
                try:
                    supported_versions[a] = int(supported_versions[a])
                except ValueError:
                    return match

            count = 0
            this_len = len(this_versions)
            supported_len = len(supported_versions)
            last_ver = this_len if this_len <= supported_len else supported_len
            for a in xrange(0, last_ver):
                if self.debug_version:
                    self.logger.debug('VDBG A')
                if this_versions[a] > supported_versions[a]:
                    if self.debug_version:
                        self.logger.debug('VDBG B1')
                    match = self.ua_support_true
                    break
                elif this_versions[a] < supported_versions[a]:
                    if self.debug_version:
                        self.logger.debug('VDBG B2')
                    match = self.ua_support_false
                    break
                elif this_versions[a] == supported_versions[a]:
                    if self.debug_version:
                        self.logger.debug('VDBG B3')
                    count += 1
                else:
                    if self.debug_version:
                        self.logger.debug('VDBG C')
                    if this_len == supported_len:
                        if self.debug_version:
                            self.logger.debug('VDBG D')
                        if a < last_ver:
                            if self.debug_version:
                                self.logger.debug('VDBG E')
                            if this_versions[a + 1] >= supported_versions[a + 1]:
                                if self.debug_version:
                                    self.logger.debug('VDBG F')
                                count += 1
                    else:
                        if this_versions[a] >= supported_versions[a]:
                            if this_len < supported_len:
                                if supported_versions[a + 1] == 0:
                                    if self.debug_version:
                                        self.logger.debug('VDBG G')
                                    match = self.ua_support_true
                                    break
                                else:
                                    if self.debug_version:
                                        self.logger.debug('VDBG H')
                                    match = self.ua_support_false
                                    break
                            else:
                                if this_versions[a + 1] >= 0:
                                    if self.debug_version:
                                        self.logger.debug('VDBG I')
                                    match = self.ua_support_true
                                    break
                                else:
                                    if self.debug_version:
                                        self.logger.debug('VDBG J')
                                    match = self.ua_support_false
                                    break
                        else:
                            if self.debug_version:
                                self.logger.debug('VDBG K')
                                self.logger.debug("VDBG COUNT: {0}".format(count))
                            match = self.ua_support_false
                            break

            if count == supported_len and count == this_len:
                match = self.ua_support_true
            else:
                if match == self.ua_support_unknown:
                    if self.debug_version:
                        self.logger.debug('VDBG K {0} {1} {2}'.format(count + 1, this_len, supported_len))
                        self.logger.debug('VDBG K {0} {1} {2}'.format(count + 1, len(this_versions),
                                                                      len(supported_versions)))
                    if supported_len <= this_len:
                        if self.debug_version:
                            self.logger.debug('VDBG L')
                        if this_versions[count] >= 0:
                            if self.debug_version:
                                self.logger.debug('VDBG M TRUE')
                            match = self.ua_support_true
                        else:
                            if self.debug_version:
                                self.logger.debug('VDBG N FALSE')
                            match = self.ua_support_false
                    else:
                        if self.debug_version:
                            self.logger.debug('VDBG 0')
                            print 'O'
                        if supported_versions[count] > 0:
                            if self.debug_version:
                                self.logger.debug('VDBG P FALSE')
                            match = self.ua_support_false
                        else:
                            if self.debug_version:
                                self.logger.debug('VDBG Q TRUE')
                                print "Q TRUE"
                            match = self.ua_support_true
            if self.debug_version:
                self.logger.debug('VDBG DEBUG {0} {1} = {2}[{3}] ? {4}[{5}]'.format(
                    match, count, this_version, this_len, supported_version, supported_len))
        return match

    def test_version_test(self):
        test_data = [
            {'ver_set': '3',            'ver_req': '3.5.6',        'result': 2},
            {'ver_set': '3.5.7',        'ver_req': '3.5.6',        'result': 0},
            {'ver_set': '3.4',          'ver_req': '3.5.6',        'result': 2},
            {'ver_set': '3.5.7',        'ver_req': '3.5',          'result': 0},
            {'ver_set': '3.5.7',        'ver_req': '3.6',          'result': 2},
            {'ver_set': '3.5.7',        'ver_req': '3',            'result': 0},
            {'ver_set': '3.5.7',        'ver_req': '3.5.6',        'result': 0},
            {'ver_set': '4.0.4',        'ver_req': '2.3',          'result': 0},
            {'ver_set': '3.5.7',        'ver_req': '3.0.9',        'result': 0},
            {'ver_set': '3.5.7',        'ver_req': '3.5.0',        'result': 0},
            {'ver_set': '3.5.7',        'ver_req': '3.6.0',        'result': 2},
            {'ver_set': '38',           'ver_req': '38.0.2125',    'result': 0},
            {'ver_set': '1.3.0_5-test', 'ver_req': '1.3.0_7-bobs', 'result': 2},
            {'ver_set': '1.4.1_5-test', 'ver_req': '1.4.0_7-bobs', 'result': 0},
            {'ver_set': '1.4.1_-test',  'ver_req': '1.4.0_7-bobs', 'result': 0},
        ]
        tests = 0
        for this_test in test_data:
            this_test_result = self.test_version(this_test['ver_set'], this_test['ver_req'])
            tests += 1 if this_test_result is this_test['result'] else 0
            if self.debug_version:
                self.logger.debug('TEST: {0} | {1} ? {2} = {3} == {4}'.format(tests,
                                                                              this_test['ver_set'],
                                                                              this_test['ver_req'],
                                                                              this_test_result,
                                                                              this_test['result']))
        if self.debug_version:
            self.logger.debug('TEST RESULTS: {0} {1}'.format(tests, len(test_data)))

        if tests != len(test_data):
            return False
        else:
            return True

    def is_supported(self, supported_os, supported_browser):
        if supported_os == self.ua_support_true and supported_browser == self.ua_support_true:
            # If Browser and OS Support SHA256, this one is good to go.
            supported = self.ua_support_true
        elif supported_os == self.ua_support_unknown and supported_browser == self.ua_support_unknown:
            # If both are unknown
            supported = self.ua_support_unknown
        elif supported_os != self.ua_support_false and supported_browser != self.ua_support_false:
            # If either the OS or the Browser is unknown but neither is false then it is unknown
            supported = self.ua_support_unknown
        else:
            # Browser and OS do not support SHA256, this one is most likely bad.
            supported = self.ua_support_false
        return supported

    def output_status_ua(self, supported, unknown, ua_name, ua_string):
        if self.identify_unknown is True:
            if unknown:
                identify_unknown = '{0} '.format('T')
            else:
                identify_unknown = '{0} '.format('F')
        else:
            identify_unknown = ''

        ua_name = ua_name.replace(' ', '_')
        if self.verbose > 0:
            return '{0} {1}{2} [{3}]'.format(supported, identify_unknown, ua_name, ua_string)
        else:
            return '{0} {1}{2}'.format(supported, identify_unknown, ua_name)

    def extract_javavm_namever(self, ua_dict, ua_regex):
        # Normally the Java VM name and Version are separate. java_vm and java_ver
        # However, some Dalvik versions are part of the VM name
        # i.e.: java_vm = 'Dalvik/1.4' / java_ver = ''
        java_vm = ''
        java_ver = ''
        dalvik_vm_namever = False
        if not 'java_vm' in ua_regex['format']:
            return java_vm, java_ver

        # We matched something with a Java like VM
        java_vm = ua_dict[ua_regex['format']['java_vm']]

        if java_vm in self.vms_java:
            # If this exist for a java_vm then it is likely the vm version.
            if 'java_ver' in ua_regex['format']:
                # Most Java VMs keep their actual version here, Hotspot and Dalvik may not
                java_ver = ua_dict[ua_regex['format']['java_ver']]
            else:
                # If java_ver didn't exist then we'll use java_vm_ver, which is sometimes the java_vm_ver
                if 'java_vm_ver' in ua_regex['format']:
                    java_ver = ua_dict[ua_regex['format']['java_vm_ver']]
        elif java_vm in self.vms_hotspot or java_vm in self.vms_dalvik:
            if java_vm in self.vms_dalvik:
                if '/' in java_vm:
                    # If this is a Dalvik VM, the version may be in the vm_name
                    java_vm, java_ver = java_vm.split('/')
                    dalvik_vm_namever = True
            if not dalvik_vm_namever:
                # If the version was not in the VM name.
                # Most Dalvik and Hotspot VMs use java_vm_ver instead of java_ver
                if 'java_vm_ver' in ua_regex['format']:
                    java_ver = ua_dict[ua_regex['format']['java_vm_ver']]
                else:
                    if 'java_ver' in ua_regex['format']:
                        java_ver = ua_dict[ua_regex['format']['java_ver']]

        return java_vm, java_ver

    def java_version_get(self, java_vm, java_ver, ua_dict, java_vm_min_ver):
        # This is a convenience function, rather than repeating the following in multiple locations
        supported = self.test_version(java_ver, self.vm_mvr_dalvik)
        self.logger.debug('JAVAA: {0}'.format(ua_dict))
        self.logger.debug('JAVAB: VM={0} {1} ? {2} = {3}'.format(java_vm, java_ver, java_vm_min_ver, supported))
        return supported

    def get_ua_supported_status_string(self, mytuple):
        ua_name, ua_regex, ua_dict, ua_s = mytuple
        supported = self.ua_support_unknown
        supported_os = self.ua_support_unknown
        supported_browser = self.ua_support_unknown

        # Let's filter previously matched regex's before we check for a browser.
        self.logger.debug('REGEX UA_NAME: {0}'.format(ua_name))
        if ua_name is not None:
            if ua_name == 'aws-sdk-java':
                # Process aws-sdk-java version including those using Java/Hotspot/Dalvik VMs
                java_vm, java_ver = self.extract_javavm_namever(ua_dict, ua_regex)
                if java_vm == '' or java_ver == '':
                    # If we don't know the version we can't know if it is supported
                    # support defaults to unknown
                    pass
                elif java_vm in self.vms_java:
                    supported = self.java_version_get(java_vm, java_ver, ua_dict, self.vm_mvr_java)
                elif java_vm in self.vms_hotspot:
                    # Hotspot 20 = Java 1.6.0 Update 25 / Update 29 is needed for SHA2
                    # Hotspot 21 = Java 1.7.0
                    supported = self.java_version_get(java_vm, java_ver, ua_dict, self.vm_mvr_hotspot)
                elif java_vm in self.vms_dalvik:
                    supported = self.java_version_get(java_vm, java_ver, ua_dict, self.vm_mvr_dalvik)
                else:
                    pass
            elif ua_name == 'aws-sdk-android':
                # Process aws-sdk-android Dalvik version
                java_vm, java_ver = self.extract_javavm_namever(ua_dict, ua_regex)
                if java_vm == '' or java_ver == '':
                    # If we don't know the version we can't know if it is supported
                    # support defaults to unknown
                    pass
                else:
                    supported = self.java_version_get(java_vm, java_ver, ua_dict, self.vm_mvr_dalvik)
            elif ua_name == 'aws-sdk-iOS':
                apple_ios = ['iPhone-OS']
                os_name = self.get_ev(ua_regex, ua_dict, 'os')
                os_ver = self.get_ev(ua_regex, ua_dict, 'os_ver')
                if os_name is not None and os_ver is not None:
                    if os_name in apple_ios:
                        supported = self.test_version(os_ver, '3')
            elif ua_name in self.useragents_support_supported:
                supported = self.ua_support_true
            elif ua_name in self.useragents_support_unsupported:
                supported = self.ua_support_false
            else:
                supported = self.ua_support_unknown

            # Return the status for these known user agents here
            return self.output_status_ua(supported, True, ua_name, ua_s)
        else:
            self.logger.debug("NO_REGEX NAME: {0}".format(ua_name))
            self.logger.debug("NO_REGEX UA: {0}".format(ua_s))

        # Filter out any blank or empty user agents, they are unknown.
        if not ua_s.strip():
            return self.output_status_ua(supported, True, 'Empty_UserAgent', ua_s)

        # Filter out any user agents containing only null, they are unknown.
        null_agent = self.nullstring_cleanup(ua_s)
        if null_agent in self.nullagents:
            return self.output_status_ua(supported, True, 'Null_UserAgent', ua_s)

        ua_browser = user_agents.parse(ua_s)
        browser_name = ua_browser.browser.family
        browser_ver = ua_browser.browser.version_string
        os_name = ua_browser.os.family
        os_ver = ua_browser.os.version_string

        ua_name = browser_name

        if 'Windows' in os_name and 'Windows' != os_name and 'Windows Phone' not in os_name:
            # ua_browser outputs Windows "OS Name/Ver" as "Windows 8.1/", we'll fix that here.
            os_split = os_name.split(' ', 1)
            if len(os_split) >= 1:
                os_name = os_split[0]
            if len(os_split) == 2:
                os_ver = os_split[1]
        elif 'Windows Phone' in os_name:
            # "Windows Phone 8" presents a similar issue to that above.
            os_split = os_name.split(' ', 2)
            if len(os_split) >= 2:
                os_name = ' '.join(os_split[0:1])
            if len(os_split) >= 3:
                os_ver = os_split[2]
        else:
            pass
        os_major_ver = self.get_major_ver(os_ver)

        agent_os_identified = True

        # Validate OS Support
        if os_name == 'Windows':
            # XP is unknown without the SP info
            win_support_major_true = ['7', '8', 'RT', 'Vista', '10']
            win_support_major_false = ['3', '95', '98', 'CE', 'ME', 'NT' '2000']
            if len(os_major_ver) >= 1:
                if os_major_ver in win_support_major_true:
                    supported_os = self.ua_support_true
                if os_major_ver in win_support_major_false:
                    supported_os = self.ua_support_false

        elif os_name == 'Windows Phone':
            supported_os = self.test_version(os_ver, self.os_mvr_windowsphone)

        elif os_name == 'Mac OS X':
            supported_os = self.test_version(os_ver, self.os_mvr_macosx)

        elif os_name == 'iOS':
            supported_os = self.test_version(os_ver, self.os_mvr_ios)

        elif os_name == 'Android':
            supported_os = self.test_version(os_ver, self.os_mvr_android)

        elif os_name == 'BlackBerry OS':
            supported_os = self.test_version(os_ver, self.os_mvr_blackberryos)

        elif os_name == 'BlackBerry Tablet OS':
            supported_os = self.test_version(os_ver, self.os_mvr_blackberrytabletos)

        elif os_name == 'Chrome OS':
            supported_os = self.ua_support_true

        elif os_name == 'webOS' or os_name == 'Symbian':
            supported_os = self.ua_support_false

        elif os_name == 'Linux':
            # We can not identify if Linux is truly supported due to it's reliance on OpenSSL,
            # and the ability to update the kernel independantly of the rest of the distribution.
            supported_os = self.ua_support_unknown
        else:
            agent_os_identified = False

        agent_browser_identified = True
        # We do not know about these, they will be created as Unknown.
        # This is only to maintain this list. We are not explicitly using it.
        # browsers_unknown = ['Lunascape', 'Lynx']

        # We'll start with application that are independent of the OS for support, or where
        # the version of the application depends on a specific version of the OS.
        if browser_name in self.browser_depends_on_os:
            # Depends on OS
            supported_browser = supported_os

        elif browser_name in self.useragents_support_supported_bots:
            # We'll assume various major Web Bots will be supported.
            supported = supported_browser = self.ua_support_true

        elif browser_name == 'SeaMonkey':
            # Seamonkey uses Mozilla NSS for SSL. Seamonkey's first version was in 2006.
            # NSS 3.8+ is SHA256 Certificate Compatible was released in 2003.
            supported = supported_browser = self.ua_support_true

        elif browser_name == 'Netscape':
            # 7.1 or higher supports SHA256, relies on NSS
            supported = supported_browser = self.test_version(browser_ver, '7.1')

        elif browser_name == 'Edge':
            # This is used by Apps running on an and using Apple OS's built in Web calls
            supported = supported_browser = supported_os

        elif browser_name == 'CFNetwork':
            # This is used by Apps running on an and using Apple OS's built in Web calls
            supported = supported_browser = supported_os

        elif browser_name in self.firefox_browsers:
            # Firefox and Mozilla use Mozilla NSS for SSL, Firefox 1.0+ uses NSS 3.8+
            # NSS 3.8+ is SHA256 Certificate Compatible
            supported = supported_browser = self.test_version(browser_ver, '1.5')

        elif browser_name == 'Thunderbird':
            # Firefox and Mozilla use Mozilla NSS for SSL, Firefox 1.0+ uses NSS 3.8+
            # NSS 3.8+ is SHA256 Certificate Compatible
            supported = supported_browser = self.test_version(browser_ver, '5')

        elif browser_name == 'BlackBerry':
            if os_name == 'BlackBerry WebKit':
                supported = supported_browser = supported_os
            else:
                blackberry_support_true = ['8520', '8530', '8900', '8910', '8980', '9000', '9700', '9650', '9630',
                                           '9520', '9550', '9500', '9530', '9780', '9788', '9100', '9105', '9670',
                                           '9300', '9330', '9800', '9320', '9220', '9350', '9360', '9370', '9380',
                                           '9850', '9860', '9810', '9981', '9720', '9900', '9930', '9790']
                blackberry_support_false = ['7100', '7250', '8100', '8310', '8320', '8800', '8820', '8830', '8100',
                                            '8110', '8120', '8130', '8220', '8230', '8300', '8310', '8320', '8330',
                                            '8350', '7200', '7500', '7700', '5000', '6000', '850', '857', '950',
                                            '957']
                if browser_ver in blackberry_support_true:
                    supported_browser = self.ua_support_true
                if browser_ver in blackberry_support_false:
                    supported_browser = self.ua_support_false
                supported = self.is_supported(supported_os, supported_browser)

        else:
            # Here's we'll process browsers that have a dependency on OS support for their support.
            if browser_name == 'Android':
                supported_browser = self.test_version(os_ver, '2.3')

            elif browser_name == 'Outlook':
                supported_browser = self.test_version(os_ver, '2003')

            elif browser_name == 'Opera':
                supported_browser = self.test_version(browser_ver, '6')

            elif browser_name == 'Konqueror':
                # 3.5.6 or higher supports SHA256, relies on OpenSSL
                supported_browser = self.test_version(browser_ver, '3.5.6')

            elif browser_name == 'Safari' or browser_name == 'Mobile Safari':
                supported_browser = self.test_version(browser_ver, '3')

            elif browser_name == 'IE' or browser_name == 'IE Mobile':
                supported_browser = self.test_version(browser_ver, '6')

            elif browser_name in self.chrome_browsers:
                # Chrome 0-37 depends on OS, 38+ is independent of OS
                supported_browser = self.test_version(browser_ver, '38')
                if supported_browser == self.ua_support_false:
                    supported_browser = self.ua_support_unknown

                if supported_browser == self.ua_support_unknown and supported_os == self.ua_support_true:
                    supported = self.ua_support_true
                elif supported_browser == self.ua_support_unknown and supported_os == self.ua_support_unknown:
                    supported = self.ua_support_unknown
                elif supported_browser == self.ua_support_true:
                    supported = self.ua_support_true
                else:
                    supported = self.ua_support_false

            # Anything that has unknown support will be '1'
            elif browser_name not in self.browsers_nonstandard and browser_name != 'Other':
                # Unless handled in an Application's check above, at this point we will assume
                # that the application may depend on the OS for support.
                #
                # We'll deal with Chrome/OS in it's section above, as it is previously reliant
                # on the OS, but the newer versions are not.
                agent_browser_identified = False
            else:
                # This browser agent was unidentified we will assume it uses OS support.
                agent_browser_identified = False

            # Finally we'll see if the application coupled with the OS are supported as a package
            supported = self.is_supported(supported_os, supported_browser)

        self.logger.debug('ALL: {0}/{1}/{2} {3}/{4} {5}/{6} [{7}]'.format(
            supported, supported_os, supported_browser, os_name, os_ver, browser_name, browser_ver, ua_browser))
        self.logger.debug('DICT: {0}'.format(ua_dict))
        self.logger.debug('BROWSER: {0} {1}/{2}'.format(supported_browser, browser_name, browser_ver))
        self.logger.debug('OS: {0} {1}/{2}'.format(supported_os, os_name, os_ver))
        self.logger.debug('BOTH: {0}/{1}/{2} {3}/{4} {5}/{6}'.format(
            supported, supported_os, supported_browser, os_name, os_ver, browser_name, browser_ver))

        # If we were unable to identify the browser or the OS then we will mention that in debug here.
        if agent_os_identified is True:
            agent_identified = 'OS_TRUE'
        else:
            agent_identified = 'OS_FALSE'
        if agent_browser_identified is True:
            agent_identified = '{0},{1}'.format(agent_identified, 'BROWSER_TRUE')
        else:
            agent_identified = '{0},{1}'.format(agent_identified, 'BROWSER_FALSE')

        if agent_browser_identified is True and agent_os_identified is True:
            agent_unknown = True
        else:
            agent_unknown = False

        self.logger.debug('UA STRING IS_ID ({0}) ({1}): {2}'.format(agent_identified, ua_name, ua_s))

        return self.output_status_ua(supported, agent_unknown, ua_name, ua_s)

    def uacheck_string(self, my_useragent):
        return self.get_ua_supported_status_string(self.test_ua(my_useragent))

    def uacheck_args(self, my_useragent):
        my_string = self.get_ua_supported_status_string(self.test_ua(my_useragent))
        my_string = my_string.split(' ')
        if len(my_string) >= 2:
            # We're only outputting the Supported flag, and a 1 word descriptor of the browser
            return my_string[0], my_string[1]
        else:
            # Something went wrong, we should have a minimum of 2 arguments.
            return None, None
