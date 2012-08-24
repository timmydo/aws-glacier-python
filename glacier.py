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

from urllib.parse import urlparse
#from email.utils import formatdate
import datetime

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
                       'debug': '0',
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
    h = hashlib.sha256()
    treehashlist = []
    with open(filename, 'rb') as infile:
        while True:
            data = infile.read(chunksize)
            if len(data) == 0:
                break
            th = hashlib.sha256()
            th.update(data)
            treehashlist += [th.digest()]
            h.update(data)

    return h.digest(), treehash(treehashlist)

def hashpair(x,y):
    h = hashlib.sha256()
    h.update(x)
    h.update(y)
    return h.digest()

def treehash(lines):
    if len(lines) == 0:
        return hashpair(b'',b'')
    while len(lines) > 1:
        pairs = zip(lines[::2], lines[1::2])
        lines = [hashpair(x,y) for x,y in pairs]
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

        linearhash, treehash = hashfile(filename)
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
        querystring = ''
        can_headers = {}
        ok_keys = ['content-sha256', 'content-type', 'date', 'host']

        for key in self.headers:
            lk = key.lower()
            if self.headers[key] is not None and (lk in ok_keys or lk.startswith('x-amz-')):
                can_headers[lk] = self.headers[key].strip()


        s = self.method + '\n'
        s += self.url + '\n'
        s += querystring + '\n'
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

    def send(self, config):
        con = http.client.HTTPConnection(config['host'], int(config['port']))
        con.set_debuglevel(self.debug)
        con.request(self.method, self.url, self.payload, self.headers)


        res = con.getresponse()
        if self.debug:
            print("\n\nStatus: " + str(res.status))
            print("Reason: " + str(res.reason))
            print("Headers: " + str(res.getheaders()))
            
        reply = res.read()

        print("Reply:\n" + str(reply))

        con.close()

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
    basename = os.path.basename(filename)
    req = Request(config, 'POST', '/-/vaults/' + vault + '/' + basename)
    if description != None:
        req.headers['x-amz-archive-description'] = description

    req.setPayloadFile(filename)
    req.addContentLength()
    req.sign()
    req.send(config)




def usage():
    print('\nusage: ' + sys.argv[0] + ' [options]\n');
    #print('  --filename            Set the filename for operations later on the command line');
    print('  --vault               Set the vault name for file operations later on the command line');
    print('  --description         Set the file description for file operations later');
    print('  --upload              Single part upload of a file');
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
    print('Examples: ');
    print('')
    print('  '+ sys.argv[0] + ' --makeprofile timmy')
    print('  '+ sys.argv[0] + ' --profile timmy --id myid --key mykey')
    print('  '+ sys.argv[0] + ' --profile timmy --makevault myvault')
    print('  '+ sys.argv[0] + ' --deletevault myvault  (uses DEFAULT profile)')
    print('  '+ sys.argv[0] + ' --describevault myvault  (uses DEFAULT profile)')
    print('  '+ sys.argv[0] + ' --listvaults  (uses DEFAULT profile)')
    print('')
    print('')

def main():
    config = readConfig()
    profile = DEFAULT_PROFILE
    vault = ''
    description = None

    options, rem = getopt.getopt(sys.argv[1:], 'h', ['help', 'description=',
                                                     'region=','id=','key=',
                                                     'makevault=', 'deletevault=',
                                                     'describevault=', 'listvaults',
                                                     'vault=', 'upload=',
                                                     'profile=', 'makeprofile='])
    if len(options) == 0:
        usage()
        sys.exit(0)


    for opt, arg in options:
        if opt in ['--region']:
            config[profile]['region'] = arg
            config[profile]['host'] = 'glacier.' + region + '.amazonaws.com'
            saveConfig(config)
        elif opt in ['--vault']:
            vault = arg
        elif opt in ['--upload']:
            if vault != '':
                uploadFile(config[profile], vault, arg, description)
            else:
                print("Vault not specified, skipping upload...")
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
