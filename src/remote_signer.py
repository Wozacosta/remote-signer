#########################################################
# Written by Carl Youngblood, carl@blockscale.net
# Copyright (c) 2018 Blockscale LLC
# released under the MIT license
#########################################################

from struct import unpack
from string import hexdigits
from src.tezos_rpc_client import TezosRPCClient
from binascii import unhexlify
from hashlib import blake2b, sha256
from base58check import b58encode
from base64 import b64encode
from logging import info, error
from six import indexbytes

class RemoteSigner:
    BLOCK_PREAMBLE = 1
    ENDORSEMENT_PREAMBLE = 2
    GENERIC_PREAMBLE = 3
    LEVEL_THRESHOLD: int = 120
    TEST_SIGNATURE = 'p2sigfqcE4b3NZwfmcoePgdFCvDgvUNa6DBp9h7SZ7wUE92cG3hQC76gfvistHBkFidj1Ymsi1ZcrNHrpEjPXQoQybAv6rRxke'
    P256_SIGNATURE = bytes.fromhex('36f02c34') #unpack('>L', b'\x36\xF0\x2C\x34')[0]  # results in p2sig prefix when encoded with base58

    def __init__(self, kvclient, kv_keyname, config, clientip, payload='', rpc_stub=None):
        self.payload = payload
        info('Verifying payload')
        self.data = self.decode_block(self.payload)
        info('Payload {} is valid'.format(self.data))
        self.rpc_stub = rpc_stub
        self.kvclient = kvclient
        self.kv_keyname = kv_keyname
        self.config = config
        self.remoteip = clientip

    @staticmethod
    def valid_block_format(blockdata):
        return all(c in hexdigits for c in blockdata)

    @staticmethod
    def decode_block(data):
        return RemoteSigner.valid_block_format(data) and bytes.fromhex(data)

    def is_block(self):
        return self.data and list(self.data)[0] == self.BLOCK_PREAMBLE

    def is_endorsement(self):
        return list(self.data)[0] == self.ENDORSEMENT_PREAMBLE

    def is_generic(self):
        return list(self.data)[0] == self.GENERIC_PREAMBLE

    def get_block_level(self):
        level = -1
        if self.is_block():
            hex_level = self.payload[10:18]
        else:
            hex_level = self.payload[-8:]
        level = unpack('>L', unhexlify(hex_level))[0]
        return level

    def is_within_level_threshold(self):
        rpc = self.rpc_stub or TezosRPCClient(node_url=self.config['node_addr'])
        current_level = rpc.get_current_level()
        payload_level = self.get_block_level()
        if self.is_block():
            within_threshold = current_level < payload_level <= current_level + self.LEVEL_THRESHOLD
        else:
            within_threshold = current_level - self.LEVEL_THRESHOLD <= payload_level <= current_level + self.LEVEL_THRESHOLD
        if within_threshold:
            info('Level {} is within threshold of current level {}'.format(payload_level, current_level))
        else:
            error('Level {} is not within threshold of current level {}'.format(payload_level, current_level))
        return within_threshold

    @staticmethod
    def b58encode_signature(sig):
        #return bin_to_b58check(sig, magicbyte=RemoteSigner.P256_SIGNATURE)
        shabytes = sha256(sha256(RemoteSigner.P256_SIGNATURE + sig).digest()).digest()[:4]
        return b58encode(RemoteSigner.P256_SIGNATURE + sig + shabytes).decode()

    @staticmethod
    def decode_asn1der_sig(sig):
        length_r = indexbytes(sig, 3)
        r_data = sig[4:4 + length_r]
        if length_r == 33: r_data = sig[5:5 + 32]
        s_data = sig[-32:]
        return r_data + s_data

    def sign(self, test_mode=False):
        encoded_sig = ''
        if self.is_endorsement() or self.is_block(): blocklevel = self.get_block_level()
        else: blocklevel = 'N/A'
        info('sign() function in remote_signer now has its data to sign')
        if self.valid_block_format(self.payload):
            info('Block format is valid')
            if not self.is_generic() or (self.remoteip == '127.0.0.1' and self.is_generic()):# or self.is_generic():  # to restrict transactions, just remove the or part
                info('Preamble is valid.  level is ' + str(blocklevel))
                if self.is_endorsement() or self.is_block():
                    if  self.is_within_level_threshold():
                        info('The request is witin level threshold.. getting signature')
                    else:
                        error('Invalid level')
                        raise Exception('Invalid level')
                op = blake2b(unhexlify(self.payload), digest_size=32).digest()
                keyid = 'projects/' + self.config['project_id'] + '/locations/' + self.config['location'] + '/keyRings/' + self.config['keyring'] + '/cryptoKeys/' + self.kv_keyname + '/cryptoKeyVersions/1'
                digest_json = {'sha256': op}
                asn1dersig = self.kvclient.asymmetric_sign(keyid, digest_json).signature
                encoded_sig = RemoteSigner.b58encode_signature(RemoteSigner.decode_asn1der_sig(asn1dersig))
                info('Base58-encoded signature: {}'.format(encoded_sig))
            else:
                error('Invalid preamble')
                raise Exception('Invalid preamble')
        else:
            error('Invalid payload')
            raise Exception('Invalid payload')

        return encoded_sig
