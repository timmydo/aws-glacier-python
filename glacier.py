#!/usr/bin/python3

# Copyright 2012 Timmy Douglas

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import hashlib
import getopt
import sys
import binascii
import socket
import hmac
import configparser
import os
import http.client
import io
import json

from urllib.parse import urlparse,parse_qs
#from email.utils import formatdate
import datetime
from time import sleep

DEFAULT_REGION='us-east-1'
DEFAULT_HOST='glacier.us-east-1.amazonaws.com'
DEFAULT_PORT=80
CONFIG_PATH='~/.awsglacier.conf'
DEFAULT_PROFILE='DEFAULT'


ONE_MB=1024*1024*1


def getConfigFilename():
    fname = os.path.expanduser(CONFIG_PATH)
    return fname

def makeProfile(config, profile):
    items = {}
    defaults = {'id': '', 'key': '', 'region': DEFAULT_REGION,
                'debug': '0', 'log': '~/.awslog', 'chunksize': '4',
                'maxtries': '20',
                'host': DEFAULT_HOST, 'port': str(DEFAULT_PORT)}
    if profile in config:
        items = config[profile]
    for key in defaults.keys():
        if key not in items:
            items[key] = defaults[key]
    config[profile] = items

def saveConfig(config, fname=None):
    if fname == None:
        fname = getConfigFilename()
    print('Saving configuration file: ' + fname)
    with open(fname, 'w') as cfgfile:
        config.write(cfgfile)

def generateConfig(fname, profile=DEFAULT_PROFILE):
    print('Generating configuration file: ' + fname)
    config = configparser.ConfigParser()
    config.read(fname)
    makeProfile(config, profile)
    saveConfig(config, fname)

def readConfig(section='DEFAULT'):
    fname = getConfigFilename()
    print('Reading configuration from: ' + fname)
    config = configparser.ConfigParser()
    config.read(fname)
    if (section not in config or 'id' not in config[section] or 'debug' not in config[section] ):
        print('Section ' + section + ' not found in config file')
        generateConfig(fname, section)
        config.read(fname)
    return config

def hexhash(data):
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def hashfile(filename, chunksize=ONE_MB):
    with open(filename, 'rb') as infile:
        return hashstream(infile, chunksize)


def hashstream(infile, chunksize=ONE_MB):
    h = hashlib.sha256()
    treehashlist = []
    while True:
        data = infile.read(chunksize)
        if len(data) == 0:
            break
        th = hashlib.sha256()
        th.update(data)
        treehashlist += [th.digest()]
        h.update(data)

    return h.digest(), treehash(treehashlist), treehashlist


def hashpair(x,y):
    h = hashlib.sha256()
    h.update(x)
    h.update(y)
    return h.digest()

def treehash(lines):
    if len(lines) == 0:
        return hashpair(b'',b'')
    while len(lines) > 1:
        lista = lines[::2]
        listb = lines[1::2]
        extra = []
        if len(lista) > len(listb):
            extra = [lista[-1]]
        pairs = zip(lista, listb)
        lines = [hashpair(x,y) for x,y in pairs] + extra
    return lines[0]
    
def getBasicDateTime():
    return datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

def getBasicDate():
    return datetime.datetime.utcnow().strftime('%Y%m%d')

def HMAC(key,msg):
    hm = hmac.new(key, msg.encode('utf-8'), digestmod=hashlib.sha256)
    return hm.digest()



class Request():
    def __init__(self, config, method, url):
        self.accessid = config['id']
        self.accesskey = config['key']
        self.region = config['region']
        self.debug = int(config['debug'])
        self.hideResponseHeaders = False
        self.method = method
        self.url = url
        self.headers = {}
        self.date = getBasicDate()
        self.time = getBasicDateTime()
        self.headers['Host'] = 'glacier.' + self.region + '.amazonaws.com'
        self.headers['x-amz-glacier-version'] = '2012-06-01'
        self.headers['x-amz-date'] = self.time
        #formatdate(timeval=None, localtime=False, usegmt=True)
        self.payload = b''

    def addContentLength(self):
        self.headers['Content-Length'] = str(len(self.payload))

    def getAuthType(self):
        return 'AWS4-HMAC-SHA256'

    def setPayloadFile(self, filename):
        with open(filename, 'rb') as fb:
            self.payload = fb.read()

        linearhash, treehash, thl = hashfile(filename)
        self.headers['x-amz-sha256-tree-hash'] = binascii.hexlify(treehash).decode('ascii')
        self.headers['x-amz-content-sha256'] = binascii.hexlify(linearhash).decode('ascii')


    def setPayloadContents(self, payload):
        self.payload = payload
        linearhash, treehash, thl = hashstream(io.BytesIO(self.payload))
        self.headers['x-amz-sha256-tree-hash'] = binascii.hexlify(treehash).decode('ascii')
        self.headers['x-amz-content-sha256'] = binascii.hexlify(linearhash).decode('ascii')



    def getStringToSign(self):
        s = self.getAuthType() + '\n'
        s += self.time + '\n'
        s += self.date + '/' + self.region + '/glacier/aws4_request' + '\n'
        s += hexhash(self.getCanonicalString().encode('ascii'))
        if self.debug:
            print('===\nString to sign:\n' + s + '===')
        return s

    def getDerivedKey(self):
        if len(self.accesskey) == 0:
            raise ValueError('Access Key not specified. Use --key or edit your configuration file.')
        kDate = HMAC(("AWS4" + self.accesskey).encode("utf-8"), self.date)
        kRegion = HMAC(kDate, self.region)
        kService = HMAC(kRegion, 'glacier')
        kSigning = HMAC(kService, "aws4_request")
        return kSigning



    def getAuthorizationLine(self):
        #do this first because it creates signedheaders
        strtosign = self.getStringToSign()
        derivedkey = self.getDerivedKey()
        sig = HMAC(derivedkey, strtosign)
        if len(self.accessid) == 0:
            raise ValueError('Access ID not specified. Use --id or edit your configuration file.')


        s = self.getAuthType() + ' Credential=' + self.accessid + '/' + self.date + '/' + self.region
        s += '/glacier/aws4_request,SignedHeaders=' + self.signedheaders
        s += ',Signature=' + binascii.hexlify(sig).decode('ascii')

        return s

    def sign(self):
        self.headers['Authorization'] = self.getAuthorizationLine()

    def getCanonicalString(self):
        urlparts = urlparse(self.url)
        querystring = parse_qs(urlparts.query)
        can_headers = {}
        ok_keys = ['content-sha256', 'content-type', 'date', 'host']

        for key in self.headers:
            lk = key.lower()
            if self.headers[key] is not None and (lk in ok_keys or lk.startswith('x-amz-')):
                can_headers[lk] = self.headers[key].strip()

        canquerystring = ''
        for key in sorted(querystring):
            val = querystring[key]
            canquerystring += '&' + key + '=' + val[0].strip() + '\n'

        if len(canquerystring) == 0:
            canquerystring = '\n'
        else:
            if (canquerystring[0] == '&'):
                canquerystring = canquerystring[1:]
            

        s = self.method + '\n'
        s += urlparts.path + '\n'
        s += canquerystring
        signedheaders = ''
        for key in sorted(can_headers.keys()):
            val = can_headers[key]
            s += key + ':' + val.strip() + '\n'
            signedheaders += key + ';'

        s += '\n' # end signed headers
        
        self.signedheaders = signedheaders[:-1]
        s += self.signedheaders + '\n'     # erase last ;


        s += hexhash(self.payload)

        if self.debug:
            print("===\nCanonical Request: \n" + s + '===')

        return s

    def send(self, config, outfile=None):
        con = http.client.HTTPConnection(config['host'], int(config['port']))
        con.set_debuglevel(self.debug)
        con.request(self.method, self.url, self.payload, self.headers)


        res = con.getresponse()
        if not self.hideResponseHeaders:
            print("\n\nStatus: " + str(res.status))
            print("Reason: " + str(res.reason))
            print("Headers: " + str(res.getheaders()))
        
        reply = None
        if outfile == None:
            reply = res.read()
            if not self.hideResponseHeaders:
                print("Reply:\n" + str(reply))
        else:
            with open(outfile, 'wb') as of:
                while True:
                    x = res.read(4096)
                    if len(x) == 0:
                        break
                    of.write(x)

        con.close()
        return res, reply


    def __str__(self):
        s = self.method + ' ' + self.url + ' HTTP/1.1\n'
        for key in self.headers.keys():
            val = self.headers[key]
            s += key + ': ' + val + '\n'

        s += '\n'

        return s
            

def vaultoperation(config, op, name):
    req = Request(config, op, '/-/vaults/' + name)
    req.addContentLength()
    req.sign()
    req.send(config)

def makevault(config, name):
    vaultoperation(config, 'PUT', name)

def deletevault(config, name):
    vaultoperation(config, 'DELETE', name)

def describevault(config, name):
    vaultoperation(config, 'GET', name)

def listvaults(config):
    req = Request(config, 'GET', '/-/vaults')
    req.addContentLength()
    req.sign()
    req.send(config)

def uploadFile(config, vault, filename, description=None):
    req = Request(config, 'POST', '/-/vaults/' + vault + '/archives')
    if description != None:
        req.headers['x-amz-archive-description'] = description

    req.setPayloadFile(filename)
    req.addContentLength()
    req.sign()
    req.send(config)

def getFilePart(filename, offset, partsize):
    with open(filename, 'rb') as fb:
        fb.seek(offset)
        return fb.read(partsize)

def listParts(config, vault, uploadid, marker=None):
    query = '/-/vaults/' + vault + '/multipart-uploads/' + uploadid
    if marker != None:
        query += '?marker=' + marker
    req = Request(config, 'GET', query)
    req.hideResponseHeaders = True
    req.addContentLength()
    req.sign()
    return req.send(config)

def findUploadedFileOffset(config, vault, uploadid):
    parts = []
    marker = None
    while True:
        res, reply = listParts(config, vault, uploadid, marker)
        partreply = json.loads(reply.decode('utf-8'))
        if 'Parts' not in partreply:
            raise KeyError('Parts not in ' + str(partreply))
        parts += partreply['Parts']
        marker = partreply['Marker']
        if marker == None:
            break

    # TODO? verify the treehashes?
    maxoffset = 0
    for item in parts:
        maxval = int(item['RangeInBytes'].split('-')[1])
        maxoffset = max(maxoffset, maxval)
    return maxoffset, parts

def treehashFromList(thl, start, end):
    start = start//1024//1024
    end = end//1024//1024
    hashparts = thl[start:end]
    return treehash(hashparts)

def checkHashes(config, vault, filename, uploadid):
    offset, parts = findUploadedFileOffset(config, vault, uploadid)
    badhashes = []
    print("Hashing file: " + str(filename))
    fullhash, treehash, thl = hashfile(filename)
    for part in parts:
        rng = [int(x) for x in part['RangeInBytes'].split('-')]
        mytreehash = binascii.hexlify(treehashFromList(thl, rng[0], rng[1])).decode('ascii')
        # ??? aws puts '01' at the beginning of their hash?
        if mytreehash not in part['SHA256TreeHash']:
            badhashes += [part]
            print("Hash mismatch: " + str(part) + "\nExpected: " + str(mytreehash)
                  + "\nAt offset: " + str(rng[0]/1024/1024) + " MB to "
                  + str(rng[1]/1024/1024) + ' MB')
    print('Checked ' + str(len(parts)) + ' hashes')
    print('Full file hash: ' + binascii.hexlify(fullhash).decode('ascii'))
    print('Full file treehash: ' + binascii.hexlify(treehash).decode('ascii'))
    return badhashes
        
def repairMultipartFile(config, vault, filename, uploadid, partsize=None):
    if partsize == None:
        partsize = int(config['chunksize'])*ONE_MB
    parts = checkHashes(config, vault, filename, uploadid)
    for part in parts:
        rng = [int(x) for x in part['RangeInBytes'].split('-')]


        offset = rng[0]
        part = getFilePart(filename, offset, partsize)

        # len(part) will work for chunks and the last chunk in the file rather than partsize
        if (rng[1] - rng[0] != len(part)):
            raise ValueError('Part size expected: ' + str(partsize) + ' found: ' + str(rng[1] - rng[0]))


        req = Request(config, 'PUT', '/-/vaults/' + vault + '/multipart-uploads/' + uploadid)
        part = getFilePart(filename, offset, partsize)
        req.headers['Content-Range'] = 'bytes ' + str(offset) + '-' + str(offset+len(part)-1) + '/*'
        req.setPayloadContents(part)

        req.addContentLength()
        req.sign()
        #req.hideResponseHeaders = True
        res, reply = req.send(config)
        if res.status != 204:
            raise ValueError('Expected 204 response from multipart PUT request @ offset '
                             + str(offset) + '\n' 
                             + str(res.reason) + '\n' 
                             + str(res.headers) + '\n'
                             + str(reply))

        print('Repaired part at offset ' + str(offset) + ' (' + str(offset//1024//1024) + ' MB)')



def multipartUploadFile(config, vault, filename, description=None, uploadid=None, partsize=None,maxtries=None):
    if partsize == None:
        partsize = int(config['chunksize'])*ONE_MB
    if maxtries == None:
        maxtries = int(config['maxtries'])

    offset = 0
    size = os.stat(filename).st_size

    # uploadid is set to the multipart upload id or None if starting for the first time
    if uploadid == None:
        req = Request(config, 'POST', '/-/vaults/' + vault + '/multipart-uploads')
        if description != None:
            req.headers['x-amz-archive-description'] = description
        req.headers['x-amz-part-size'] = str(partsize)

        req.addContentLength()
        req.sign()
        req.hideResponseHeaders = True
        res, reply = req.send(config)
        if 'x-amz-multipart-upload-id' not in res.headers:
            raise KeyError('x-amz-multipart-upload-id not in response headers')
        uploadid = res.headers['x-amz-multipart-upload-id']
        print('Starting upload of ' + filename)
        print('Upload ID: ' + str(uploadid))
    else:
        uploadid = uploadid
        offset, parts = findUploadedFileOffset(config, vault, uploadid)
        print('Resuming upload at offset: ' + str(offset) + ' (' + str(offset//1024//1024) + ' MB)')


    while offset < size:
        req = Request(config, 'PUT', '/-/vaults/' + vault + '/multipart-uploads/' + uploadid)
        part = getFilePart(filename, offset, partsize)
        req.headers['Content-Range'] = 'bytes ' + str(offset) + '-' + str(offset+len(part)-1) + '/*'
        req.setPayloadContents(part)

        req.addContentLength()
        req.sign()
        req.hideResponseHeaders = True
        try:
            res, reply = req.send(config)
            if res.status != 204:
                print('Expected 204 response from multipart PUT request @ offset '
                      + str(offset) + '\n' 
                      + str(res.reason) + '\n'
                      + str(res.headers) + '\n' 
                      + str(reply))
                maxtries -= 1
                if maxtries < 1:
                    print('Try limit exceeded...exiting')
                    return
                continue


            print('Uploaded ' + str(len(part)/1024/1024) + ' MB @ offset ' + str(offset) + ' bytes (' + str(offset//1024//1024) + ' MB)')
            offset += len(part)
        except socket.error as e:
            print('Socket error: ' + str(e))
            if maxtries < 1:
                print('Try limit exceeded...exiting')
                return
            print('Retrying...')
            sleep(1)
            maxtries -= 1

    print('Calculating hash and finishing upload of ' + filename)
    # calculate hash before creating the request otherwise it might be out of date by the time
    # we send the request
    linearhash, treehash, thl = hashfile(filename)

    req = Request(config, 'POST', '/-/vaults/' + vault + '/multipart-uploads/'+uploadid)
    req.headers['x-amz-archive-size'] = str(size)
    req.headers['x-amz-sha256-tree-hash'] = binascii.hexlify(treehash).decode('ascii')
    req.addContentLength()
    req.sign()
    res, reply = req.send(config)

    print('Uploaded ' + filename)
    if res.status != 201:
        raise ValueError('Expected 201 Created response from upload finish request')
    if 'log' in config and len(config['log']) > 0:
        path = os.path.expanduser(config['log'])
        location = uploadid
        if 'Location' in res.headers:
            location = res.headers['Location']
        with open(path, 'a') as fd:
            fd.write(str(filename) + '->' + location + '\n')
            print('Wrote upload log entry to ' + path)


def listUploads(config, vault):
    req = Request(config, 'GET', '/-/vaults/' + vault + '/multipart-uploads')
    req.addContentLength()
    req.sign()
    req.send(config)

def abortUpload(config, vault, uploadid):
    req = Request(config, 'DELETE', '/-/vaults/' + vault + '/multipart-uploads/' + uploadid)
    req.addContentLength()
    req.sign()
    req.send(config)

def deleteFile(config, vault, archiveid):
    req = Request(config, 'DELETE', '/-/vaults/' + vault + '/archives/' + archiveid)
    req.addContentLength()
    req.sign()
    req.send(config)

def createJob(config, vault, params):
    req = Request(config, 'POST', '/-/vaults/' + vault + '/jobs')
    req.setPayloadContents(json.dumps(params).encode('utf-8'))
    req.addContentLength()
    req.sign()
    req.send(config)

def listJobs(config, vault, joboutput=None):
    req = Request(config, 'GET', '/-/vaults/' + vault + '/jobs')
    req.addContentLength()
    req.sign()
    req.send(config, joboutput)

def getJobOutput(config, vault, jobid, joboutput=None):
    req = Request(config, 'GET', '/-/vaults/' + vault + '/jobs/' + jobid + '/output')
    req.addContentLength()
    req.sign()
    req.send(config, joboutput)



def usage():
    me = os.path.basename(sys.argv[0])
    print('\nUsage: ' + me + ' [options]\n');
    print('  --vault               Set the vault name for file operations later on the command line');
    print('  --description         Set the file description for file operations later');
    print('  --supload             Single part upload of a file (Not recommended)');
    print('  --upload              Multipart upload of a file');
    print('  --resume              Resume a multipart upload of a file');
    print('  --checkhashes         Check hashes on a paused multipart upload of a file');
    print('  --listuploads         List the current multipart uploads');
    print('  --listparts           List the parts of a multipart upload');
    print('  --repairparts         Repair the parts of a multipart upload');
    print('  --abortupload         Abort a multipart upload');
    print('  --delete              Delete an uploaded archive');
    print('')
    print('  --makeprofile         Make a configuration profile with the given name');
    print('  --profile             Set the config profile');
    print('  --region              Set the region in the current profile and save');
    print('  --id                  Set the aws access id in the current profile and save');
    print('  --key                 Set the aws access key/secret in the current profile and save');
    print('')
    print('  --makevault           Make a vault');
    print('  --deletevault         Delete a vault');
    print('  --deletevault         Delete a vault');
    print('  --describevault       Describe a vault');
    print('  --listvaults          List the vaults');
    print('')
    print('  --createjob           Create a job for downloading an archive or viewing a vault inventory');
    print('  --listjobs            List the jobs in a vault');
    print('  --getjob              Get the output from a job');
    print('  --joboutput           Set the output file for a job output task');
    print('  --archive             Set the archive id for an archive retrieval job');
    print('')
    print('Examples: ');
    print('')
    print('  '+ me + ' --makeprofile timmy')
    print('  '+ me + ' --profile timmy --id myid --key mykey')
    print('  '+ me + ' --profile timmy --makevault myvault')
    print('  '+ me + ' --deletevault myvault  (uses DEFAULT profile)')
    print('  '+ me + ' --describevault myvault  (uses DEFAULT profile)')
    print('  '+ me + ' --listvaults  (uses DEFAULT profile)')
    print('')
    print('  '+ me + ' --makevault test')
    print('  '+ me + ' --vault test --upload ~/examples.desktop')
    print('  '+ me + ' --vault test --delete <ArchiveId>')
    print('  '+ me + ' --vault test --listuploads')
    print('  '+ me + ' --vault test --abortupload <MultipartUploadId>')
    print('  '+ me + ' --vault test --listparts <MultipartUploadId>')
    print('  '+ me + ' --vault test --filename <filename> --resume <MultipartUploadId>')
    print('  '+ me + ' --vault test --filename <filename> --checkhashes <MultipartUploadId>')
    print('  '+ me + ' --vault test --filename <filename> --repairparts <MultipartUploadId>')
    print('')
    print('  '+ me + ' --vault test --createjob inventory-retrieval')
    print('  '+ me + ' --vault test --listjobs')
    print('  '+ me + ' --vault test --joboutput result.txt --getjob <JobId>')
    print('  '+ me + ' --vault test --archive <ArchiveId> --createjob archive-retrieval')
    print('')
    print('')

def main():
    config = readConfig()
    profile = DEFAULT_PROFILE
    vault = ''
    description = None
    joboutput = None
    archive = None
    filename = None

    options, rem = getopt.getopt(sys.argv[1:], 'h', ['help', 'description=',
                                                     'region=','id=','key=',
                                                     'makevault=', 'deletevault=',
                                                     'describevault=', 'listvaults',
                                                     'vault=', 'supload=', 'delete=',
                                                     'createjob=', 'listjobs', 'getjob=',
                                                     'joboutput=', 'archive=',
                                                     'upload=', 'multipartupload=',
                                                     'listuploads', 'abortupload=',
                                                     'filename=', 'resume=', 'listparts=',
                                                     'checkhashes=', 'repairparts=',
                                                     'profile=', 'makeprofile='])
    if len(options) == 0:
        usage()
        sys.exit(0)
    
    def requireVault(opt):
        if len(vault) == 0:
            raise ValueError('Vault required for option: ' + opt)

    for opt, arg in options:
        if opt in ['--region']:
            config[profile]['region'] = arg
            config[profile]['host'] = 'glacier.' + region + '.amazonaws.com'
            saveConfig(config)
        elif opt in ['--vault']:
            vault = arg
        elif opt in ['--joboutput']:
            joboutput = arg
        elif opt in ['--filename']:
            filename = arg
        elif opt in ['--archive']:
            archive = arg
        elif opt in ['--supload']:
            requireVault(opt)
            uploadFile(config[profile], vault, arg, description)
        elif opt in ['--upload', '--multipartupload']:
            requireVault(opt)
            multipartUploadFile(config[profile], vault, arg, description, None)
        elif opt in ['--listparts']:
            requireVault(opt)
            listParts(config[profile], vault, arg)
        elif opt in ['--resume']:
            requireVault(opt)
            multipartUploadFile(config[profile], vault, filename, None, arg)
        elif opt in ['--checkhashes']:
            requireVault(opt)
            checkHashes(config[profile], vault, filename, arg)
        elif opt in ['--repairparts']:
            requireVault(opt)
            repairMultipartFile(config[profile], vault, filename, arg)
        elif opt in ['--delete']:
            requireVault(opt)
            deleteFile(config[profile], vault, arg)
        elif opt in ['--listuploads']:
            requireVault(opt)
            listUploads(config[profile], vault)
        elif opt in ['--abortupload']:
            requireVault(opt)
            abortUpload(config[profile], vault, arg)
        elif opt in ['--listjobs']:
            requireVault(opt)
            listJobs(config[profile], vault, joboutput)
        elif opt in ['--getjob']:
            requireVault(opt)
            getJobOutput(config[profile], vault, arg, joboutput)
        elif opt in ['--createjob']:
            requireVault(opt)
            if arg in ['archive-retrieval', 'inventory-retrieval']:
                params = {'Type': arg}
                if arg in ['inventory-retrieval']:
                    params['Format'] = 'JSON'
                if description != None:
                    params['Description'] = description
                if archive != None:
                    params['ArchiveId'] = archive

                createJob(config[profile], vault, params)
            else:
                raise ValueError("Job type not archive-retrieval or inventory-retrieval")
        elif opt in ['--description']:
            description = arg
        elif opt in ['--profile']:
            profile = arg
        elif opt in ['--makeprofile']:
            makeProfile(config, arg)
            saveConfig(config)
        elif opt in ['--id']:
            config[profile]['id'] = arg
            saveConfig(config)
        elif opt in ['--makevault']:
            makevault(config[profile], arg)
        elif opt in ['--deletevault']:
            deletevault(config[profile], arg)
        elif opt in ['--describevault']:
            describevault(config[profile], arg)
        elif opt in ['--listvaults']:
            listvaults(config[profile])
        elif opt in ['--key']:
            config[profile]['key'] = arg
            saveConfig(config)
        elif opt in ['-h', '--help']:
            usage()
            sys.exit(0)
        else:
            print('Invalid argument: ' + opt)
            usage()
            sys.exit(0)


if __name__ == '__main__':
    main()
