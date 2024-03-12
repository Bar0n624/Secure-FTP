from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import os

KEYS_DIR = "../../keys/"
CUR_DIR = os.path.abspath(os.path.dirname(__file__))

_rand = Random.new()


def generateNewKeypair(
    master_key: str, public_out: str = None, private_out: str = None, size: int = 2048
) -> None:
    """Generate a new RSA keypair.

    :param master_key:
        The master key of the user.

    :param public_out:
        The filename for the public key.

    :param public:
        The filename for the private key.

    :param size:
        The size of the RSA key. Must be either 1024, 2048 or 3072 bits
        as defined by the FIPS standard.
    """

    if not (size == 1024 or size == 2048 or size == 3072):
        raise ValueError("size: invalid key length (expected 1024, 2048 or 3072)")

    rel_path = os.path.join(CUR_DIR, KEYS_DIR)

    if public_out is None:
        public_out = rel_path + "public.pem"
    else:
        if not (public_out[-3:] == "pem"):
            raise ValueError("public_out: invalid RSA public keyfile.")
        public_out = rel_path + public_out

    if private_out is None:
        private_out = rel_path + "private.der"
    else:
        if not (private_out[-3:] == "der"):
            raise ValueError("private_out: invalid RSA private keyfile.")
        private_out = rel_path + private_out

    key = RSA.generate(size, _rand.read)

    # The public key in binary format
    pub = key.publickey().exportKey(format="PEM")

    with open(public_out, "wb") as f:
        f.write(pub)

    # The private key in binary format
    priv = key.exportKey(
        format="DER", passphrase=master_key, pkcs=8, randfunc=_rand.read
    )

    with open(private_out, "wb") as f:
        f.write(priv)


def encryptRsa(data: bytes, public_in: str = None) -> bytes:
    """
    Encrypts data using an RSA private key.

    :param data:
        The data to be encrypted.

    :param public_in:
        The filename of the RSA public key.

    :return:
        The encrypted data as bytes.
    """

    rel_path = os.path.join(CUR_DIR, KEYS_DIR)

    # if public_in is None:
    #   public_in = rel_path + "public.pem"
    # else:
    #   if not (public_in[-3:] == "pem"):
    #        raise ValueError("public_in: invalid RSA public keyfile.")
    #    public_in = rel_path + public_in

    # Load the private key
    with open(public_in, "rb") as f:
        public_key = RSA.import_key(f.read())

    # Use PKCS1_OAEP for optimal padding
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the data
    encrypted_data = cipher.encrypt(data)

    return encrypted_data


def decryptRsa(
    master_key: bytes, encrypted_data: bytes, private_in: str = None
) -> bytes:
    """
    Decrypts data using an RSA public key.

    :param encrypted_data:
        The data to be decrypted.

    :param public_in:
        The filename of the RSA public key.

    :return:
        The decrypted data as bytes.
    """

    rel_path = os.path.join(CUR_DIR, KEYS_DIR)

    if private_in is None:
        private_in = rel_path + "private.der"
    else:
        if not (private_in[-3:] == "der"):
            raise ValueError("private_in: invalid RSA private keyfile.")
        private_in = rel_path + private_in

    # Load the public key
    with open(private_in, "rb") as f:
        private_key = RSA.import_key(f.read(), passphrase=master)

    # Use PKCS1_OAEP for optimal padding
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data


master = "Thisisthemasterkey123"


if __name__ == "__main__":
    generateNewKeypair(master)

    # generateNewKeypair(master)

    data = "testdata"

    encrypted = encryptRsa(data.encode())

    print("Encrypted =", encrypted)

    print("Decrypted =", decryptRsa(master, encrypted))
