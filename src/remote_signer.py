#########################################################
# Written by Carl Youngblood, carl@blockscale.net
# Copyright (c) 2018 Blockscale LLC
# released under the MIT license
#########################################################

import struct
import string
#from src.tezos_rpc_client import TezosRPCClient
from src.dynamodb_client import DynamoDBClient
from pyhsm.hsmclient import HsmClient, HsmAttribute
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import hex_to_bytes, bytes_to_hex
from binascii import unhexlify
from os import environ
import bitcoin
from pyblake2 import blake2b
import logging


class RemoteSigner:
    BLOCK_PREAMBLE = 1
    ENDORSEMENT_PREAMBLE = 2
    TEST_SIGNATURE = 'p2sigfqcE4b3NZwfmcoePgdFCvDgvUNa6DBp9h7SZ7wUE92cG3hQC76gfvistHBkFidj1Ymsi1ZcrNHrpEjPXQoQybAv6rRxke'
    P256_SIGNATURE = struct.unpack('>L', b'\x36\xF0\x2C\x34')[0]  # results in p2sig prefix when encoded with base58

    def __init__(self, config, payload='', rpc_stub=None):
        self.keys = config['keys']
        self.payload = payload
        logging.info('Verifying payload')
        self.data = self.decode_block(self.payload)
        logging.info('Payload {} is valid'.format(self.data))
        self.rpc_stub = rpc_stub
        self.hsm_slot = config['hsm_slot']
        hsm_user = config['hsm_username']
        logging.info('HSM user is {}'.format(config['hsm_username']))
        logging.info('Attempting to read env var HSM_PASSWORD')
        hsm_password = environ['HSM_PASSWORD']
        self.hsm_pin = '{}:{}'.format(hsm_user, hsm_password)
        self.hsm_libfile = config['hsm_lib']
        logging.info('HSM lib is {}'.format(config['hsm_lib']))
        self.node_addr = config['node_addr']
        # Add support for DynamoDB on 9-22-18 by LY
        self.ddb_region = environ['REGION']
        self.ddb_table = environ['DDB_TABLE']

    @staticmethod
    def valid_block_format(blockdata):
        return all(c in string.hexdigits for c in blockdata)

    @staticmethod
    def decode_block(data):
        return RemoteSigner.valid_block_format(data) and bytes.fromhex(data)

    def is_block(self):
        return self.data and list(self.data)[0] == self.BLOCK_PREAMBLE

    def is_endorsement(self):
        return list(self.data)[0] == self.ENDORSEMENT_PREAMBLE

    def get_block_level(self):
        level = -1
        if self.is_block():
            hex_level = self.payload[10:18]
        else:
            hex_level = self.payload[-8:]
        level = struct.unpack('>L', unhexlify(hex_level))[0]
        logging.info('Block level is {}'.format(level))
        return level

    def not_already_signed(self):
        payload_level = self.get_block_level()
        if self.is_block():
            sig_type = 'Baking'
        else:
            sig_type = 'Endorsement'
        ddb = DynamoDBClient(self.ddb_region, self.ddb_table, sig_type, payload_level)
        not_signed = ddb.check_double_signature()
        if not_signed:
            logging.info('{} signature for level {} has not been generated before'.format(sig_type, payload_level))
        else:
            logging.error('{} signature for level {} has already been generated!'.format(sig_type, payload_level))
        return not_signed

    @staticmethod
    def b58encode_signature(sig):
        return bitcoin.bin_to_b58check(sig, magicbyte=RemoteSigner.P256_SIGNATURE)

    def sign(self, handle, test_mode=False):
        encoded_sig = ''
        data_to_sign = self.payload
        logging.info('About to sign {} with key handle {}'.format(data_to_sign, handle))
        if self.valid_block_format(data_to_sign):
            logging.info('Block format is valid')
            if self.is_block() or self.is_endorsement():
                logging.info('Preamble is valid')
                if self.not_already_signed():
                    if test_mode:
                        return self.TEST_SIGNATURE
                    else:
                        logging.info('About to sign with HSM client. Slot = {}, lib = {}, handle = {}'.format(self.hsm_slot, self.hsm_libfile, handle))
                        with HsmClient(slot=self.hsm_slot, pin=self.hsm_pin, pkcs11_lib=self.hsm_libfile) as c:
                            hashed_data = blake2b(hex_to_bytes(data_to_sign), digest_size=32).digest()
                            logging.info('Hashed data to sign: {}'.format(hashed_data))
                            sig = c.sign(handle=handle, data=hashed_data, mechanism=HsmMech.ECDSA)
                            logging.info('Raw signature: {}'.format(sig))
                            encoded_sig = RemoteSigner.b58encode_signature(sig)
                            logging.info('Base58-encoded signature: {}'.format(encoded_sig))
                else:
                    logging.error('Invalid level')
                    raise Exception('Invalid level')
            else:
                logging.error('Invalid preamble')
                raise Exception('Invalid preamble')
        else:
            logging.error('Invalid payload')
            raise Exception('Invalid payload')
        return encoded_sig
