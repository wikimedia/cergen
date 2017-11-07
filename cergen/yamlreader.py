#
# NOTE:
#
# This file was directly copied from 
# https://github.com/ImmobilienScout24/yamlreader/blob/adc4f9e033a74127ccfaf5d9ddae412504a5b4bb/src/main/python/yamlreader/yamlreader.py
# in order to not have an external dependency on yamlreader.
#
#
# Copyright 2017 Schlomo Schapiro schlomo.schapiro@immobilienscout24.de
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# flake8: noqa

from __future__ import print_function, absolute_import, unicode_literals, division

from yaml import MarkedYAMLError, safe_load, safe_dump
import glob
import os
import logging
import six


class NoDefault(object):
    def __str__(self):
        return "No default data"


NO_DEFAULT = NoDefault()


class YamlReaderError(Exception):
    pass


def data_merge(a, b):
    """merges b into a and return merged result
    based on http://stackoverflow.com/questions/7204805/python-dictionaries-of-dictionaries-merge
    and extended to also merge arrays and to replace the content of keys with the same name
    NOTE: tuples and arbitrary objects are not handled as it is totally ambiguous what should happen"""
    key = None
    # ## debug output
    # sys.stderr.write("DEBUG: %s to %s\n" %(b,a))
    try:
        if a is None or isinstance(a, (six.string_types, float, six.integer_types)):
            # border case for first run or if a is a primitive
            a = b
        elif isinstance(a, list):
            # lists can be only appended
            if isinstance(b, list):
                # merge lists
                a.extend(b)
            else:
                # append to list
                a.append(b)
        elif isinstance(a, dict):
            # dicts must be merged
            if isinstance(b, dict):
                for key in b:
                    if key in a:
                        a[key] = data_merge(a[key], b[key])
                    else:
                        a[key] = b[key]
            else:
                raise YamlReaderError('Cannot merge non-dict "%s" into dict "%s"' % (b, a))
        else:
            raise YamlReaderError('NOT IMPLEMENTED "%s" into "%s"' % (b, a))
    except TypeError as e:
        raise YamlReaderError('TypeError "%s" in key "%s" when merging "%s" into "%s"' % (e, key, b, a))
    return a


def yaml_load(source, defaultdata=NO_DEFAULT):
    """merge YAML data from files found in source
    Always returns a dict. The YAML files are expected to contain some kind of
    key:value structures, possibly deeply nested. When merging, lists are
    appended and dict keys are replaced. The YAML files are read with the
    yaml.safe_load function.
    source can be a file, a dir, a list/tuple of files or a string containing
    a glob expression (with ?*[]).
    For a directory, all *.yaml files will be read in alphabetical order.
    defaultdata can be used to initialize the data.
    """
    logger = logging.getLogger(__name__)
    logger.debug("initialized with source=%s, defaultdata=%s", source, defaultdata)
    if defaultdata is NO_DEFAULT:
        data = None
    else:
        data = defaultdata
    files = []
    if type(source) is not str and len(source) == 1:
        # when called from __main source is always a list, even if it contains only one item.
        # turn into a string if it contains only one item to support our different call modes
        source = source[0]
    if type(source) is list or type(source) is tuple:
        # got a list, assume to be files
        files = source
    elif os.path.isdir(source):
        # got a dir, read all *.yaml files
        files = sorted(glob.glob(os.path.join(source, "*.yaml")))
    elif os.path.isfile(source):
        # got a single file, turn it into list to use the same code
        files = [source]
    else:
        # try to use the source as a glob
        files = sorted(glob.glob(source))
    if files:
        logger.debug("Reading %s\n", ", ".join(files))
        for yaml_file in files:
            try:
                with open(yaml_file) as f:
                    new_data = safe_load(f)
                logger.debug("YAML LOAD: %s", new_data)
            except MarkedYAMLError as e:
                logger.error("YAML Error: %s", e)
                raise YamlReaderError("YAML Error: %s" % str(e))
            if new_data is not None:
                data = data_merge(data, new_data)
    else:
        if defaultdata is NO_DEFAULT:
            logger.error("No YAML data found in %s and no default data given", source)
            raise YamlReaderError("No YAML data found in %s" % source)

    return data


def __main():
    import optparse
    parser = optparse.OptionParser(usage="%prog [options] source...",
                                   description="Merge YAML data from given files, dir or file glob",
                                   version="%" + "prog %s" % __version__,
                                   prog="yamlreader")
    parser.add_option("--debug", dest="debug", action="store_true", default=False,
                      help="Enable debug logging [%default]")
    options, args = parser.parse_args()
    if options.debug:
        logger = logging.getLogger()
        loghandler = logging.StreamHandler()
        loghandler.setFormatter(logging.Formatter('yamlreader: %(levelname)s: %(message)s'))
        logger.addHandler(loghandler)
        logger.setLevel(logging.DEBUG)

    if not args:
        parser.error("Need at least one argument")
    try:
        print(safe_dump(yaml_load(args, defaultdata={}),
                        indent=4, default_flow_style=False, canonical=False))
    except Exception as e:
        parser.error(e)

if __name__ == "__main__":
    __main()