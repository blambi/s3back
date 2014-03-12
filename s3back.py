#!/usr/bin/env python
from Crypto.Cipher import Blowfish
from Crypto import Random
from struct import pack
import os
import argparse
from ConfigParser import ConfigParser
import tempfile

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
            return sorted(files)[-1]
        else:
            return []

    @classmethod
    def get_new_name(cls, target, files):
        last = cls.get_last(files)

        if last:
            serial = int(last[last.rfind('_')+1:])
            return last[:last.rfind('_')] + "_{}".format(serial+1)
        else:
            return os.path.basename(target) + '_0'

    @classmethod
    def pruge(cls, files, keep = 5):
        """Returns files to remove"""
        return []

def bytes_to_hexstr(sbytes):
    out = "0x"
    for x in sbytes:
        out += hex(ord(x))[2:]
    return out


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
        'key': config.get('s3', 'secret'),
        'secret': config.get('s3', 'secret')
    }
    rotation_keep = config.get('rotation', 'keep')

    ll_fp, temp_name = tempfile.mkstemp()
    os.close(ll_fp)
    temp_file = open(temp_name, 'wb+')

    if args.source[:5] == 's3://':
        raise ValueError, "Not implemented yet"
    else:
        if args.decrypt:
            files = filter(lambda x: x.startswith(os.path.basename(args.source)+'_'),
                           os.listdir(os.path.dirname(args.source)))
            if args.edition == -1:
                # find latest
                input_file = open(os.path.join(os.path.dirname(args.source), Rotation.get_last(files)), 'rb')
            else:
                hit = filter(lambda x: x.endswith("_{}".format(args.edition)), files)
                if hit:
                    if verbose:
                        print "Found editon #{} called '{}'".format(args.edition, hit[0])
                    input_file = open(os.path.join(os.path.dirname(args.source), hit[0]))
                else:
                    print "Could'nt find edition #{}".format(args.edition)
                    exit(1)
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
        raise ValueError, "Not implemented yet"
        # upload file, with date suffix
        # remove oldest file if more files then X
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
            # remove oldest file if more files then X
