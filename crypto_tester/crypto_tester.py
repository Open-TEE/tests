'''
/*****************************************************************************
** Copyright 2014 Hannu Lahtinen hannu.lahtinen@student.tut.fi              **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
**                                                                          **
** Crypto tester. Python application that parses nist.gov test vectors,     **
** creates temporary files and feeds them to an Open-TEE project            **
** ClientApplication and reports the results.                               **
**                                                                          **
** This file was created as part of an assignment work                      **
** for course "Turvallinen ohjelmointi part 2" in                           **
** Tampere University of Technology                                         **
*****************************************************************************/
'''
import sys
from urllib2 import urlopen, URLError, HTTPError
from urlparse import urlparse
from binascii import unhexlify
import os
import ConfigParser
import zipfile
from subprocess import CalledProcessError, check_call
import tempfile
import ntpath
from shutil import rmtree

WINDOWS_LINE_ENDING = "\r\n"
CA_NAME = "./crypto_tester_ca"
tempDir = tempfile.mkdtemp(prefix="SHA")
config = None

'''
Removes temporary files(unless otherwise specified in config)
and exits
'''
def cleanExit():
    if config and config.getboolean("ParserConfig", "keepTemporaryFiles"):
        print "Temporary files created by this program",
        print " were not removed and are stored in directory:"
        print tempDir
    else:
        rmtree(tempDir)
        print "Temporary files were deleted"
    exit();

'''
Checks the given file is a zip
Extracts it
returns a list of extracted files
'''
def unzip(filenameOfZip):
    if not zipfile.is_zipfile(filenameOfZip):
        print filenameOfZip + " doesn't exist or isn't a real zip file"
        return
    zippedFile = zipfile.ZipFile(filenameOfZip)
    zippedFile.extractall(path=tempDir)
    zippedFile.close()
    return [ tempDir + os.sep + name for name in zippedFile.namelist() ]

'''
Downloads a file from the given url
calls cleanExit() if an exception occurs
'''
def downloadZip(url):
    try:
        zipToDownload = urlopen(url)
        zipFilename = os.path.basename(url)
        localZip = tempfile.NamedTemporaryFile(mode='wb', suffix='',
                                               prefix=zipFilename,
                                               dir=tempDir, delete=False)
        localZip.write(zipToDownload.read())
        localZip.close()
        return localZip.name
    except HTTPError, e:
        print "HTTP Error:", e.code, url
        raise
    except URLError, e:
        print "URL Error:", e.reason, url
        raise

'''
Parses a single .rsp text file from nist.gov
-Finds line that contain hash algorithm's name
-Finds input lines and stores input in a separate temporary file
-Finds input length lines and stores input length in a separate temporary file
-Finds expected output lines and stores expected output in a separate temporary file
-Checks if config defines that user input algorithm should be used
'''
def parseFile(filepath, inputLineIdentifier, lengthLineIdentifier, outputLineIdentifier):

    fileToRead = open(filepath, 'rb')
    # all the CAVS vectors I went through have CAVS11 on the first line
    # just a security measure making sure we
    if not "".join(fileToRead.readline().split()).startswith("#CAVS11"):
        print "Only CAVS11 .rsp files from nist.gov supported. File skipped:",
        print fileToRead
        fileToRead.close()
        return None

    # find algorithm from second line
    if config.getboolean("ParserConfig", "resolveAlgorithmFromFile"):
        algorithmToTest = fileToRead.readline().split()[1].lstrip('"')
    else:
        algorithmToTest = config.get("ParserConfig", "algorithm")

    # create temp files
    infile = tempfile.NamedTemporaryFile(mode='wb',suffix='.in',
                                         prefix=filepath, dir=tempDir,
                                         delete=False)
    lengthfile = tempfile.NamedTemporaryFile(mode='wb',suffix='.length',
                                             prefix=filepath, dir=tempDir,
                                             delete=False)
    outfile = tempfile.NamedTemporaryFile(mode='wb',suffix='.out',
                                          prefix=filepath, dir=tempDir,
                                          delete=False)

    # go through rest of the lines
    # parsing the information in to their temp files
    lengthOfBinString = 0;
    for line in fileToRead:
        if line.startswith(lengthLineIdentifier):
            lengthOfBinString = int(line[len(lengthLineIdentifier):]
                                    .rstrip(WINDOWS_LINE_ENDING))/8
            lengthfile.write(str(lengthOfBinString) + '\n')

        if line.startswith(inputLineIdentifier):
            if lengthOfBinString > 0:
                inputString = (line[len(inputLineIdentifier):]
                               .rstrip(WINDOWS_LINE_ENDING))
                inputString = unhexlify(inputString)
                if lengthOfBinString == len(inputString):
                    infile.write(inputString)
                else:
                    print "Error parsing file: " + filepath
                    print "Length read from file doesn't match input read from file"
                    cleanExit()
        if line.startswith(outputLineIdentifier):
            outputString = (line[len(outputLineIdentifier):]
                            .rstrip(WINDOWS_LINE_ENDING))
            outfile.write(outputString + '\n')
    infile.close()
    lengthfile.close()
    outfile.close()
    fileToRead.close()
    return dict({ 'inputFile': infile.name, 'lengthFile': lengthfile.name,
                 'expectedOutputFile': outfile.name, 'algorithm': algorithmToTest })

'''
Goes through all the text files to be parsed,
feeds them to the parseFile() -method
and creates a list of all the files to be used for testing later
'''
def parseFiles(filesToParse):
    inputLineIdentifier = config.get("ParserConfig",
                                     "inputLineIdentifier").strip('"')
    lengthLineIdentifier = config.get("ParserConfig",
                                      "lengthLineIdentifier").strip('"')
    outputLineIdentifier = config.get("ParserConfig",
                                      "outputLineIdentifier").strip('"')
    fileList = [];
    for filepath in filesToParse:
        if os.path.isfile(filepath):
            print "fileToRead: " + filepath
            if not filepath.endswith(".rsp") or "Monte" in filepath:
                print "Only SHA Long and Short Msg test vectors accepted. File skipped:"
                print filepath
                continue
            fileDict = parseFile(filepath, inputLineIdentifier,
                                 lengthLineIdentifier, outputLineIdentifier)
            if fileDict:
                fileList.append(fileDict)
        else:
            print "File not found: " + filepath
    return fileList;

'''
Calls the external CA process to run our test data
Returns 0 if the tests were succesful and an errorcode otherwise
'''
def run_test_vector(testVectorFileDict):
    caPath = os.path.dirname(config.get("ParserConfig", "CAPath").strip('"'))
    args = [caPath + os.sep + CA_NAME,
            "-i" + testVectorFileDict['inputFile'],
            "-l" + testVectorFileDict['lengthFile'],
            "-e" + testVectorFileDict['expectedOutputFile'],
            "-a" + testVectorFileDict['algorithm']]
    try:
        check_call(args, shell=False)
        return 0
    except CalledProcessError as e:
        return e.returncode
    except OSError:
	print "ClientApplication not found in: " + caPath
	raise

'''
Goes through all the arguments given by user
Directs the files to their appropriate handler methods
'''
def handleArguments(arguments):
    filesToParse = []
    localZip = ""
    for fileUri in arguments:
        parsedUri = urlparse(fileUri);
        # security measure
        # zip files from the web are only accepted if they are from nist.gov host
        if (parsedUri.netloc.endswith("nist.gov")
            and not parsedUri.query and not parsedUri.fragment):
            if parsedUri.path.endswith(".zip"):
                localZip = downloadZip(fileUri)
            else:
                print "Only zip files from nist.gov are accepted"
                continue
        elif not parsedUri.netloc:
            if fileUri.endswith(".zip"):
                localZip = fileUri
            elif fileUri.endswith(".rsp"):
                filesToParse.append(fileUri)
                continue
            else:
                print "unrecognized local file"
                continue
        else:
            print "Only nist.gov hosted zips accepted. Use full url with http://"
            continue
        if localZip:
            filesToParseFromZip = unzip(localZip)
            if filesToParseFromZip:
                filesToParse.extend(filesToParseFromZip)
            continue
        print "Unrecognized file or uri"
    return filesToParse

if __name__=='__main__':
    if len(sys.argv) < 2:
        print("Usage: %s -c<CONFIG> <ZIP_URL/PATH or TEXTFILEPATH>" % (sys.argv[0],))
        sys.exit(1)

    # parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='''Parses nist gov test vectors
                                       and feeds them to ClientApplication.''')
    parser.add_argument('-c', action='store', help='Give your own config file',
                        default='default_config.cfg')
    parser.add_argument('files', action='append', help='Files to be tested')
    arguments = parser.parse_args()

    # set config
    config = ConfigParser.ConfigParser()
    config.read(arguments.c)

    try:
        # handle the other arguments (ie filepaths/urls)
        filesToParse = handleArguments(arguments.files)

        # parse files and create temporary files to give to the test CA
        testFileList = parseFiles(filesToParse)

        # feed test files to client application
        for testVectorFileDict in testFileList:
            print "input: " + testVectorFileDict['inputFile']
            print "output: " + testVectorFileDict['expectedOutputFile']
            print "algorithm: " + testVectorFileDict['algorithm']
            returnCode = run_test_vector(testVectorFileDict)
            testVectorFileDict.update({'testReturnCode': returnCode })

        # sum up results
        if testFileList:
            print "\n\nTests finished. Files that were tested and results:"
            for testVectorFileDict in testFileList:
                print testVectorFileDict['inputFile'].rstrip('.in') + " ",
                returnCode = testVectorFileDict['testReturnCode']
                if returnCode == 0:
                    print "SUCCESFULLY TESTED!"
                else:
                    print "FAILED! Return code: " + str(returnCode)
    except:
	print "Exiting due to an exception: ", sys.exc_info()[0]
    finally:
        cleanExit()
