# AWS SHA256 Compatibility Scanner

The **AWS SHA256 Compatibility Scanner** helps users to identify if their applications or user base are affected by the SHA1 Deprecation taking place this year. It works by parsing the UserAgent string of the application and attempting to determine the application name, application version, os name, and os version. It then uses this information to check against a known list of applications and operating systems that are known either to support or not support SHA256 certificates. It outputs a single line per UserAgent, the output can be used to identify if a specific application is either '**supported**', '**not supported**', or if '**support is unknown**'.

You can read about the [Amazon Web Services][aws] S3 SHA1 Deprecation here: [AWS S3 SHA1 Deprecation Detail][AWSSSHA1Deprecation]

* [Repository][AWSSHA256CS-Repository]
* [Issues][AWSSHA256CS-Issues]

## Getting Started
#### Sign up for AWS ####
Before you begin, you may need an AWS account. Please see the [AWS Account and Credentials][aws-signup-instructions] section of the developer guide for information about how to create an AWS account and retrieve your AWS credentials.

#### Minimum requirements ####
**Python 2.7+**
**pyyaml**
**ua-parser**
**user-agents**

#### Installation of required packages ####
**user-agents** is hosted on [PyPI/user-agents][pypi-user-agents] and [GitHub/user-agents][github-user-agents]
**ua-parser** is hosted on [PyPI/ua-parser][pypi-ua-parser] and on GitHub as [GitHub/uap-python][github-uap-python] and [GitHub/uap-core][github-uap-core]
**pyyaml** is hosted on [PyPI/pyyaml][pypi-pyyaml] and [PyYaml.org][pypi-hosted]

and they can be installed as shown here:

    pip install pyyaml ua-parser user-agents

Alternatively, you can also get the latest source code from each project's `Github` and install them manually.

#### Downloading this Application and Library ####
1. The recommended way to get the code is to use 'git clone https://github.com/awslabs/aws-sha256-agentcs.git' to clone this repository to your local machine.
2. Enter the local repository folder with 'cd ecs-task-kite'
3. You are now ready to begin using this library and the included applications.

#### Using The Included Applications ####

This repository includes:

3 Example Applications
* uascan_app1.py: Takes either a single User Agent on the command line, or one or more entries from an STDIN Pipe
* uascan_app2.py: Takes a command line argument specifying a file that contains one or more User Agents entries
* uascan_app3.py: Takes a command line argument specifying an S3 Access Log file, that contains one or more entries

Each of the applications will output help on how to run them if executed with no arguments.

1 User Agent Scanning Library
* uascan_lib.py : This is the library that does the majority of processing to determine if a User Agent supports SHA256

Examples on how to use and call this library directly can be found in the above listed applications.

## Features

* Scanner functionality is implemented as a class library that can be used within other applications
* Application example that can take a 'User Agent' from the command line or one or more from STDIN
* Application example that can take a list of 'User Agents' from a file
* Application example that can take an S3 Access Log from a file, and scan each entry's User Agent
* Supports debug output for more detail about each application's support

## Important Note: Up To Date Browser Regexes
This library makes use of ua-parser. The ua-parser regex files in PyPi may not be the latest versions.
The latest versions are recommended for maximium User Agent compatibility.
The latest ua-parser 'regexes.yaml' file can be downloaded from: [GitHub/uap-core][github-uap-core]

To determine where your current ua-parser 'regexes.yaml' resides do the following:
% python
> % import ua_parser
> % print ua_parser.__file__
>/Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/__init__.pyc
> % exit()

We can then see where the regex files exist by looking in the folder that the library exist in:
> % ls /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.*
> /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.json
> /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.yaml

The existing regex files can be updated using the following example:

> % cp /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.yaml /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.yaml.bak
> % cp /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.json /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.json.bak
> % cp regexes.yaml /Users/myuser/Library/Python/2.7/lib/python/site-packages/ua_parser/regexes.yaml

* Note: The ua-parser library requires either regexes.yaml or regexes.json to exist. It will default to prefering the Yaml file, if the Yaml regex file is missing it will use the JSON regex file. Typically both of these files contain the same regexes.

## Supported Versions

1.0.0  - Initial Release

[AWSSSHA1Deprecation]: http://github.com/awslabs/aws-sha256-agentcs/blob/master/SHA1%20Deprecation%20Background.txt
[AWSSHA256CS-Repository]: http://github.com/awslabs/aws-sha256-agentcs/
[AWSSHA256CS-Issues]: http://github.com/awslabs/aws-sha256-agentcs/issues
[aws]: http://aws.amazon.com/
[aws-signup-instructions]: http://docs.aws.amazon.com/AWSSdkDocsJava/latest/DeveloperGuide/getting-started-signup.html
[pypi-user-agents]: http://pypi.python.org/pypi/user-agents/
[github-user-agents]: http://github.com/selwin/python-user-agents
[pypi-ua-parser]: http://pypi.python.org/pypi/ua-parser
[github-uap-python]: http://github.com/ua-parser/uap-python
[github-uap-core]: http://github.com/ua-parser/uap-core
[pypi-pyyaml]: http://pypi.python.org/pypi/PyYAML
[pypi-hosted]: http://pyyaml.org/browser/pyyaml