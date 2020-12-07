from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import Crypto.Random
import binascii
import json


class Wallet:
    def __init__(self, node_id):
        self.private_key = None
        self.public_key = None
        self.node_id = node_id

    def create_keys(self):
        private_key, public_key = self.generate_keys()
        self.private_key = private_key
        self.public_key = public_key

    def save_keys(self):
        is_public_key = self.public_key is not None
        is_private_key = self.private_key is not None

        if is_public_key and is_private_key:
            try:
                with open(f'wallet-{self.node_id}.json', mode='w') as f:
                    keys = {'public-key': self.public_key,
                            'private-key': self.private_key}

                    json.dump(keys, f)
                return True
            except (IOError, IndexError):
                print('Saving wallet failed...')
                return False

    def load_keys(self):
        """Loads the keys from the wallet.txt file into memory."""
        try:
            with open(f'wallet-{self.node_id}.json', mode='r') as f:
                keys = json.load(f)
                self.public_key = keys['public-key']
                self.private_key = keys['private-key']
            return True
        except (IOError, IndexError):
            print('Loading wallet failed...')
            return False

    def generate_keys(self):
        """Generate a new pair of private and public key."""
        private_key = RSA.generate(1024, Crypto.Random.new().read)
        public_key = private_key.publickey()
        return (
            binascii
            .hexlify(private_key.exportKey(format='DER'))
            .decode('ascii'),
            binascii
            .hexlify(public_key.exportKey(format='DER'))
            .decode('ascii')
        )

    def sign_transaction(self, sender, recipient, amount):
        """Sign a transaction and return the signature.

        Arguments:
            :sender: The sender of the transaction.
            :recipient: The recipient of the transaction.
            :amount: The amount of the transaction.
        """
        signer = PKCS1_v1_5.new(RSA.importKey(
            binascii.unhexlify(self.private_key)))
        h = SHA256.new((str(sender) + str(recipient) +
                        str(amount)).encode('utf8'))
        signature = signer.sign(h)
        return binascii.hexlify(signature).decode('ascii')

    @staticmethod
    def verify_transaction(transaction):
        """Verify the signature of a transaction.

        Arguments:
            :transaction: The transaction that should be verified.
        """
        public_key = RSA.importKey(binascii.unhexlify(transaction.sender))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA256.new((str(transaction.sender) + str(transaction.recipient) +
                        str(transaction.amount)).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(transaction.signature))
