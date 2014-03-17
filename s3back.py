#!/usr/bin/env python
from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack
import os
import argparse
from ConfigParser import ConfigParser
import tempfile
import boto
import boto.s3
from boto.s3.key import Key

# for safety use OFB, and 56Bytes keys
CHUNK_SIZE=4096 # should be multiples of 8

def encrypt(key, infile, outfile):
    """Takes key and input file object and output file object"""
    iv = Random.new().read(Blowfish.block_size)
    if verbose:
        print "iv: ", bytes_to_hexstr(iv)
    outfile.write(iv) # Write iv to outfile

    # calc max size to see if last chunk need padding (and number of padding bytes)
    file_size = os.fstat(infile.fileno()).st_size
    pad_len = 8-(file_size%8)

    if pad_len == 8:
        if verbose:
            print "wow no padding needed"
        outfile.write(chr(0))
    else:
        if verbose:
            print "Padding: {}".format(pad_len)
        outfile.write(chr(pad_len))

    cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)

    while True:
        plain_data = infile.read(CHUNK_SIZE)

        if not plain_data:
            break # Nothing more to read

        if len(plain_data) != 4096 and pad_len != 8:
            # last package so pad it
            padding = Random.new().read(pad_len)
            outfile.write(cipher.encrypt(plain_data + padding))
        else:
            outfile.write(cipher.encrypt(plain_data))

def decrypt(key, infile, outfile):
    iv = infile.read(8)
    if verbose:
        print "iv: ", bytes_to_hexstr(iv)
    cipher = Blowfish.new(key, Blowfish.MODE_OFB, iv)

    padding = ord(infile.read(1))
    if verbose:
        print "Padding: {}".format(padding)

    while True:
        crypt_data = infile.read(CHUNK_SIZE)

        if not crypt_data:
            break # Nothing more to read

        plain_data = cipher.decrypt(crypt_data)

        # remove padding.
        if len(plain_data) != CHUNK_SIZE and padding > 0:
            plain_data = plain_data[:-padding]

        outfile.write(plain_data)

class Rotation:
    @classmethod
    def get_last(cls, files):
        if files:
            return sorted(files, key=lambda x: int(x[x.rfind('_')+1::]))[-1]
        else:
            return []

    @classmethod
    def get_edition(cls, files, edition):
        hit = filter(lambda x: x.endswith("_{}".format(edition)), files)
        if hit:
            if verbose:
                print "Found editon #{} called '{}'".format(edition, hit[0])
            #input_file = open(os.path.join(os.path.dirname(args.source), hit[0]))
            return hit[0]
        else:
            print "Error: Couldn't find edition #{}".format(edition)
            exit(1)

    @classmethod
    def get_new_name(cls, target, files):
        last = cls.get_last(files)

        if last:
            serial = int(last[last.rfind('_')+1:])
            return last[:last.rfind('_')] + "_{}".format(serial+1)
        else:
            return os.path.basename(target) + '_0'

    @classmethod
    def find_removable(cls, files, keep = 5):
        """Returns files to remove"""
        return sorted(files, key=lambda x: int(x[x.rfind('_')+1::]))[:-keep+1]

def bytes_to_hexstr(sbytes):
    out = "0x"
    for x in sbytes:
        out += hex(ord(x))[2:]
    return out

class S3:
    def __init__(self, bucket):
        self.bucket_name = bucket
        self.connect()

    def connect(self):
        self.s3c = boto.connect_s3(aws_access_key_id=s3_conf['id'], aws_secret_access_key=s3_conf['secret'])
        self.bucket = self.s3c.get_bucket(self.bucket_name)

    def store(self, infile, target_name, retries=3):
        # find next serial name
        self.files = filter(lambda x: x.startswith(target_name+'_'),
                            map(lambda x: x.key, self.bucket.get_all_keys()))

        name = Rotation.get_new_name(os.path.basename(target_name), self.files)
        if target_name.find('_'):
            name = os.path.dirname(target_name) + '/' + name

        if verbose:
            print "Uploading file {}".format(name)

        # upload
        while retries >= 0:
            try:
                k = Key(self.bucket)
                k.key = name
                k.set_contents_from_file(infile)
                return True
            except Exception, e:
                print "Exception, while trying to upload to S3"
                self.connect()
                retries -= 1
        return False

    def retrieve(self, source_name, temp_file, edition=-1):
        self.files = filter(lambda x: x.startswith(source_name+'_'),
                            map(lambda x: x.key, self.bucket.get_all_keys()))
        if edition == -1:
            name = Rotation.get_last(self.files)
        else:
            name = Rotation.get_edition(self.files, edition)

        if not name:
            return False

        if verbose:
            print "Trying to retrieve {}".format(name)

        k = self.bucket.get_key(name)
        k.get_contents_to_file(temp_file)
        return True

    def rotate(self, keep=5):
        pass


if '__main__' == __name__:
    parser = argparse.ArgumentParser(description="Handles encryption, remote-storage and rotation of backups")
    parser.add_argument('-d', help="Decrypt, default is encrypt", action="store_true", default=False, dest="decrypt")
    parser.add_argument('-v', help="be verbose, default false", action="store_true", default=False, dest="verbose")
    parser.add_argument('-c', help="configuration & secrets file to use. default: /etc/s3back.conf", default="/etc/s3back.conf",
                        dest="config")
    parser.add_argument('-e', help="Edition to restore (decrypt only, default latest)", default=-1, dest="edition")
    parser.add_argument('source', help="file to retrieve/send")
    parser.add_argument('target', help="target folder (use: s3://bucket/folder/file)")
    args = parser.parse_args()
    verbose = args.verbose

    # Parse config file..
    if not os.path.exists(args.config):
        print "Error: couldn't find config file {}".format(args.config)
        exit(1)
    config = ConfigParser()
    config.readfp(open(args.config))

    key = config.get('crypto', 'secret')
    if verbose:
        print "Using {}bits strong key".format(len(key)*8)
    s3_conf = {
        'id': config.get('s3', 'id'),
        'secret': config.get('s3', 'secret')
    }
    rotation_keep = config.getint('rotation', 'keep')

    ll_fp, temp_name = tempfile.mkstemp()
    os.close(ll_fp)
    temp_file = open(temp_name, 'wb+')

    if args.source[:5] == 's3://':
        bucket_name, source_name = args.source[5:].split('/', 1)
        s3 = S3(bucket_name)

        ll_fp, input_name = tempfile.mkstemp()
        os.close(ll_fp)
        input_file = open(input_name, 'wb+')

        if args.decrypt:
            if not s3.retrieve(source_name, input_file, args.edition):
                print "Unable to fetch {}".format(args.source)
                exit(2)
        else:
            raise NotImplementedError, "s3 source for encryption isn't implemented yet"
        # re-open temp input for reading
        input_file.close()
        input_file = open(input_name, 'rb')

    else:
        if args.decrypt:
            files = filter(lambda x: x.startswith(os.path.basename(args.source)+'_'),
                           os.listdir(os.path.dirname(args.source)))
            if args.edition == -1:
                # find latest
                input_file = open(os.path.join(os.path.dirname(args.source), Rotation.get_last(files)), 'rb')
            else:
                hit = Rotation.get_edition(files, args.edition)
                input_file = open(os.path.join(os.path.dirname(args.source), hit))
        else:
            input_file = open(args.source, 'rb')

    if args.decrypt:
        if verbose:
            print "Decrypting {} to {}".format(args.source, args.target)
        decrypt(key, input_file, temp_file)
    else:
        if verbose:
            print "Encrypting {} to {}".format(args.source, args.target)
        encrypt(key, input_file, temp_file)

    input_file.close()
    temp_file.close()

    if args.target[:5] == 's3://':
        bucket_name, target_name = args.target[5:].split('/', 1)
        s3 = S3(bucket_name)

        # upload file, with date suffix
        temp_file = open(temp_name, 'rb')
        if not s3.store(temp_file, target_name):
            print "Unable to upload backup!"
            exit(2)
        temp_file.close()
        # remove oldest file if more files then X
        s3.rotate()
        # remove temp file
        os.unlink(temp_name)
    else:
        if args.decrypt:
            # move temp file to target without suffix
            os.rename(temp_name, args.target)
        else:
            # move temp file to target, with suffix
            files = filter(lambda x: x.startswith(os.path.basename(args.target)+'_'),
                           os.listdir(os.path.dirname(args.target)))
            targ_name = Rotation.get_new_name(os.path.basename(args.target), files)
            os.rename(temp_name, os.path.join(os.path.dirname(args.target), targ_name))
            if verbose:
                print "Stored as {}".format(targ_name)
            # remove oldest file if more files then X
            for old_file in Rotation.find_removable(files, rotation_keep):
                old_full = os.path.join(os.path.dirname(args.target), old_file)
                if verbose:
                    print "Removing old file {}".format(old_full)
                os.unlink(old_full)
