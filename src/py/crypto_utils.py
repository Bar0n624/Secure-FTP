from Crypto import Random
from Crypto.Cipher import AES
from warnings import warn
import hashlib
import os, struct, re

_rand = Random.new()

AES_KEY_SIZE = 32
AES_IV_SIZE = 16
AES_BLOCK_SIZE = 16
AES_SALT_SIZE = 32
AES_SAFE_KEYLEN = 10
PBKDF2_ITER_COUNT = 32000
FILE_CHUNK_SIZE = 4096

# XXX hardcoded for now
session_key = None
master_key = "thisistheMaster123"


def generateSessionKey(master: str, size: int) -> bytes:
    """Generate a session key using the master key and a random salt.

    :param master:
        The client master key.

    :param size:
        Size of the session key.

    :Return: a bytes object, of the AES session key.
    """

    if not len(master) > 0:
        print("Master key was empty!")
        return b""

    if not re.search("[a-z]", master):
        print("Cannot use a weak master key!")
        return b""

    if not re.search("[A-Z]", master):
        print("Cannot use a weak master key!")
        return b""

    if not re.search("[0-9]", master):
        print("Cannot use a weak master key!")
        return b""

    # TODO add doc for e.g., use --help for password requirements
    if len(master) < AES_SAFE_KEYLEN:
        warn(
            "Key too short!\n"
            "A length of SAFE_PASSPHRASE_LEN or greater is required for the master key.\n",
            UserWarning,
            2,
        )

    salt = _rand.read(AES_SALT_SIZE)

    dk = hashlib.pbkdf2_hmac(
        "sha256", master[:32].encode("utf-8"), salt, PBKDF2_ITER_COUNT, size
    )

    return dk


# TODO temp
def getSessionKey(forcenew=False) -> bytes:
    """Get the session key. If the key hasn't been generated, create a new one."""
    session_key = generateSessionKey(master_key, AES_KEY_SIZE)

    return session_key


def calculateFileDigest(filename: str) -> bytes:
    """Compute the SHA-256 digest of a file.

    :param filename:
        The input filename.

    :Return: a bytes object, of the digest.
    """

    h = hashlib.sha256()

    with open(filename, "rb") as f:
        while True:
            chunk = f.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)

    return h.digest()


def encryptFile(
    key: bytes,
    in_filename: str,
    out_filename: str = None,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> int:
    """Encrypts a file using AES (in CBC mode) with the given key.

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

    :Return: the chunk_size.
    """

    if not out_filename:
        out_filename = in_filename + ".enc"

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

        :Return: a bytes object, of the encrypted chunk. None if EOF is reached.
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
    out_filename: str = None,
    chunk_size: int = FILE_CHUNK_SIZE,
) -> None:
    """Decrypts an AES-256-CBC encrypted file with the given key.

    :param key:
        The decryption key - a bytes object that must be
        either 16, 24, or 32 bytes long. Longer keys
        are more secure.

    :param in_filename:
        Name of the input encrypted file.

    :param out_filename:
        If None, '<in_filename>.dec' will be used.

    :param chunk_size:
        Sets the size of the chunk which the function
        uses to read and decrypt the file. Larger chunk
        sizes can be faster for some files and machines.
        chunksize must be divisible by 16.
    """

    if not out_filename:
        out_filename = in_filename[:-4]  # Remove '.enc' extension for decrypted file

    with open(in_filename, "rb") as infile:
        original_size = struct.unpack("<Q", infile.read(struct.calcsize("Q")))[0]
        iv = infile.read(AES_IV_SIZE)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, "wb") as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            # Truncate the file to its original size
            outfile.truncate(original_size)


mk = "Thisisthemasterkey123"

if __name__ == "__main__":
    dk = generateSessionKey(mk, 32)

    print(len(dk))
    print(dk)

    file_hash = calculateFileDigest(
        "D:\\Python\\Projects\\CN-SEM-4\\eftp\\files\\lotus.jpg"
    )

    # print(file_hash)

    # chunksize = encryptFile(dk, 'lotus.jpg')

    with open("D:\\Python\\Projects\\CN-SEM-4\\eftp\\files\\lotus.enc", "wb") as f:
        for block in encryptSingleChunk(
            dk, "D:\\Python\\Projects\\CN-SEM-4\\eftp\\files\\lotus.jpg"
        ):
            f.write(block)

    decryptFile(
        dk,
        "D:\\Python\\Projects\\CN-SEM-4\\eftp\\files\\lotus.enc",
        "D:\\Python\\Projects\\CN-SEM-4\\eftp\\files\\lotus.enc",
        chunk_size=FILE_CHUNK_SIZE,
    )
