import os, struct, re
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import hashlib


AES_KEY_SIZE = 32
AES_IV_SIZE = 16
AES_BLOCK_SIZE = 16
AES_SALT_SIZE = 32
AES_SAFE_KEYLEN = 10
PBKDF2_ITER_COUNT = 32000
FILE_CHUNK_SIZE = 4096

_KEYS_DIR = "../../keys/"
_CUR_DIR = os.path.abspath(os.path.dirname(__file__))

_rand = Random.new()
_mk = None
_sk = None


def setMasterKey(master: str) -> int:
    """Set the user master key.

    :param master:
        The master key string.

    :returns:
        1 if the key is valid, 0 otherwise.
    """

    if not len(master) > 0:
        return 0

    if not re.search("[a-z]", master):
        return 0

    if not re.search("[A-Z]", master):
        return 0

    if not re.search("[0-9]", master):
        return 0

    if len(master) < AES_SAFE_KEYLEN:
        return 0

    global _mk
    _mk = master

    return 1


def generateSessionKey(size: int = 32) -> bytes:
    """Generate a session key using the master key and a random salt.

    :param size:
        Size of the session key (must be 16, 24 or 32 bytes).

    :returns:
        The AES session key in bytes.

    :raises ValueError:
        If size is not in the set (16, 24, 32).
    :raises AssertionError:
        If the master key is not set.
    """

    assert _mk != None

    if not (size == 16 or size == 24 or size == 32):
        raise ValueError("size: invalid AES key size")

    salt = _rand.read(AES_SALT_SIZE)

    dk = hashlib.pbkdf2_hmac(
        "sha256", _mk[:32].encode("utf-8"), salt, PBKDF2_ITER_COUNT, size
    )

    return dk


def getSessionKey(forcenew=False) -> bytes:
    """Get the session key. If the key hasn't been generated, create a new one.

    :param forcenew:
        If True, a new session key is created even if one already exists.

    :returns:
        The AES session key in bytes.
    """

    global _sk

    if not _sk or forcenew:
        _sk = generateSessionKey(AES_KEY_SIZE)

    return _sk


def calculateFileDigest(filename: str) -> bytes:
    """Compute the SHA-256 digest of a file.

    :param filename:
        The input filename.

    :returns:
        The digest of the file in bytes.
    """

    h = hashlib.sha256()

    with open(filename, "rb") as f:
        while True:
            chunk = f.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.digest()


def calculateMessageDigest(message: str) -> bytes:
    """Compute the SHA-256 digest of a string.

    :param message:
        The message string.

    :returns:
        The digest of the message in bytes.

    """

    assert message != ""

    return hashlib.sha256(message.encode()).digest()


def encryptFile(
    key: bytes,
    in_filename: str,
    out_filename: str | None = None,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> int:
    """Encrypts a file using AES (in CBC mode) with the given key.

    :param key:
        The encryption key - a bytes object that must be
        either 16, 24, or 32 bytes long. Longer keys
        are more secure.

    :param in_filename:
        Name of the input file.

    :param out_filename:
        If None, '<in_filename>.enc' will be used.

    :param chunk_size:
        Sets the size of the chunk which the function
        uses to read and encrypt the file. Larger chunk
        sizes can be faster for some files and machines.
        chunksize must be divisible by 16.

    :returns: chunk_size
    """

    if not out_filename:
        out_filename = os.path.basename(in_filename).rsplit(".", 1)[0] + ".enc"

    iv = _rand.read(AES_IV_SIZE)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, "rb") as infile:
        with open(out_filename, "wb") as outfile:
            outfile.write(struct.pack("<Q", filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % AES_BLOCK_SIZE != 0:
                    chunk += b" " * (AES_BLOCK_SIZE - len(chunk) % AES_BLOCK_SIZE)

                outfile.write(encryptor.encrypt(chunk))

    return chunk_size


def encryptSingleChunk(
    key: bytes, in_filename: str, chunk_size: int = FILE_CHUNK_SIZE
) -> any:
    """Generator which encrypts a single chunk of a file with AES (in CBC mode)
    with the given key.

        :param key:
            The encryption key - a bytes object that must be
            either 16, 24, or 32 bytes long. Longer keys
            are more secure.

        :param in_filename:
            Name of the input file

        :param out_filename:
            If None, '<in_filename>.enc' will be used.

        :param chunk_size:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.

        :returns:
            An iterable containing encrypted chunks of size chunk_size.
    """

    iv = _rand.read(AES_IV_SIZE)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, "rb") as infile:
        yield struct.pack("<Q", filesize)
        yield iv

        while True:
            chunk = infile.read(chunk_size)
            if len(chunk) == 0:
                break
            elif len(chunk) % AES_BLOCK_SIZE != 0:
                chunk += b" " * (AES_BLOCK_SIZE - len(chunk) % AES_BLOCK_SIZE)

            yield encryptor.encrypt(chunk)

    return None


def decryptFile(
    key: bytes,
    in_filename: str,
    out_filename: str | None = None,
    chunk_size: int = FILE_CHUNK_SIZE,
    ui=None,
) -> None:
    """Decrypts an AES-256-CBC encrypted file with the given key.

    :param key:
        The decryption key - a bytes object that must be
        either 16, 24, or 32 bytes long. Longer keys
        are more secure.

    :param in_filename:
        Name of the encrypted file.

    :param out_filename:
        The output filename. If None, '<in_filename>.bin' will be used.

    :param chunk_size:
        Sets the size of the chunk which the function
        uses to read and decrypt the file. Larger chunk
        sizes can be faster for some files and machines.
        chunksize must be divisible by 16.
    """

    if not out_filename:
        out_filename = os.path.basename(in_filename).rsplit(".", 1)[0] + ".bin"
    processed = 0
    with open(in_filename, "rb") as infile:
        original_size = struct.unpack("<Q", infile.read(struct.calcsize("Q")))[0]
        iv = infile.read(AES_IV_SIZE)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, "wb") as outfile:
            while True:
                chunk = infile.read(chunk_size)
                processed += len(chunk)
                if len(chunk) == 0:
                    break
                if ui:
                    ui[3].update_progress(int((processed / original_size) * 100))
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(original_size)
    if ui:
        ui[3].label_2.setText("Received Successfully!")
        ui[3].pushButton.setEnabled(True)


def generateNewKeypair(
    public_out: str | None = None, private_out: str | None = None, size: int = 2048
) -> None:
    """Generate a new RSA keypair.

    :param public_out:
        The public key filename.

    :param private_out:
        The private key filename.

    :param size:
        The size of the RSA key
        (the FIPS standard only defines 1024, 2048 or 3072 bits).

    :raises ValueError:
        If the key size is not in the set (1024, 2048, 3072).
    :raises ValueError:
        If public_out is not a PEM file.
    :raises ValueError:
        If private_out is not a DER file.
    :raises AssertionError:
        If the master key is not set.
    """

    assert _mk != None

    if not (size == 1024 or size == 2048 or size == 3072):
        raise ValueError("size: invalid key length (expected 1024, 2048 or 3072)")

    rel_path = os.path.join(_CUR_DIR, _KEYS_DIR)

    if public_out is None:
        public_out = rel_path + "public.pem"
    else:
        if not (public_out[-3:] == "pem"):
            raise ValueError("public_out: invalid RSA public keyfile")
        public_out = rel_path + public_out

    if private_out is None:
        private_out = rel_path + "private.der"
    else:
        if not (private_out[-3:] == "der"):
            raise ValueError("private_out: invalid RSA private keyfile")
        private_out = rel_path + private_out

    key = RSA.generate(size, _rand.read)

    # Export the public key
    pub = key.publickey().exportKey(format="PEM")

    with open(public_out, "wb") as f:
        f.write(pub)

    # Export the private key
    priv = key.exportKey(format="DER", passphrase=_mk, pkcs=8, randfunc=_rand.read)

    with open(private_out, "wb") as f:
        f.write(priv)


def encryptRsa(data: bytes, public_in: str | None = None) -> bytes:
    """
    Encrypts data using an RSA private key.

    :param data:
        The data to be encrypted.

    :param public_in:
        The filename of the RSA public key.

    :returns:
        The encrypted data in bytes.

    :raises ValueError:
        If public_in is not a PEM file.
    """

    rel_path = os.path.join(_CUR_DIR, _KEYS_DIR)

    if public_in is None:
        public_in = rel_path + "public.pem"
    else:
        if not (public_in[-3:] == "pem"):
            raise ValueError("public_in: invalid RSA public keyfile")
        public_in = rel_path + public_in

    # Load the private key
    with open(public_in, "rb") as f:
        public_key = RSA.import_key(f.read())

    # Use PKCS1_OAEP padding
    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the data
    encrypted_data = cipher.encrypt(data)

    return encrypted_data


def decryptRsa(encrypted_data: bytes, private_in: str | None = None) -> bytes:
    """
    Decrypts data using an RSA public key.

    :param encrypted_data:
        The data to be decrypted.

    :param private_in:
        The filename of the RSA private key.

    :returns:
        The decrypted data in bytes.

    :raises ValueError:
        If private_in is not DER file.
    :raises AssertionError:
        If the master key is not set.
    """

    assert _mk != None

    rel_path = os.path.join(_CUR_DIR, _KEYS_DIR)

    if private_in is None:
        private_in = rel_path + "private.der"
    else:
        if not (private_in[-3:] == "der"):
            raise ValueError("private_in: invalid RSA private keyfile")
        private_in = rel_path + private_in

    # Load the public key
    with open(private_in, "rb") as f:
        private_key = RSA.import_key(f.read(), passphrase=_mk)

    # Use PKCS1_OAEP padding
    cipher = PKCS1_OAEP.new(private_key)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    return decrypted_data
