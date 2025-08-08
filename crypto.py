from json import JSONDecodeError
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128, SHA256, HMAC
from Crypto.Protocol.DH import key_agreement
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import json

""" Checks if the exception is an integrity error. """
def is_integrity_error(e: Exception) -> bool:
    return isinstance(e, IntegrityError) or isinstance(e, JSONDecodeError)


def is_general_error(e: Exception) -> bool:
    return isinstance(e, InvalidNonceError) or isinstance(e, DroppedMessageError)


class IntegrityError(Exception):
    """
        Raised when a message fails integrity checks.
        Covers HMAC mismatches or invalid JSON payloads.
        """
    def __init__(self, msg="Message does not pass integrity checks"):
        self.message = msg
        super().__init__(self.message)


class InvalidHashError(IntegrityError):
    """
       Raised when HMAC verification fails.
       Inherits from IntegrityError.
       """
    def __init__(self, hmac: str):
        message = f"Invalid HMAC provided: {hmac}"
        super().__init__(message)


class InvalidNonceError(Exception):
    """
       Raised when the received nonce does not match the expected value.
       Helps prevent replay attacks.
       """
    def __init__(self, nonce: int, expected_nonce):
        message = f"Invalid nonce provided: {nonce}. Expected: {expected_nonce}"
        self.nonce = nonce
        super().__init__(message)


class DroppedMessageError(Exception):
    """
       Raised when an empty acknowledgment is received,
       indicating that a message was dropped.
       """
    def __init__(self):
        message = "Empty acks are drops messages"
        super().__init__(message)


def kdf(x):
    """
    Key derivation function used for DH secret generation

    Consider: for more security, this could take in some context of the operation (maybe a nonce?)
    More info: https://www.pycryptodome.org/src/protocol/dh
    """
    return SHAKE128.new(x).read(32)


def generate_keypair() -> ECC.EccKey:
    """
    Randomly generates a 256-bit ECC keypair
    https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
    """
    return ECC.generate(curve="p256")


def generate_shared_secret(private_key: ECC.EccKey, public_key: ECC.EccKey) -> bytes:
    """
    Uses DH to generate a byte array representing a shared secret given an ECC keypair
    """
    return key_agreement(static_priv=private_key, static_pub=public_key, kdf=kdf)


def derive_aes256_key(secret: bytes, salt: bytes) -> bytes:
    """Generates a 256-bit key intended for AES-CBC encryption, derived from a secret and a salt"""
    return SHA256.new(secret + salt).digest()


def derive_auth_key(secret: bytes) -> bytes:
    """Generates an authentication key derived from a secret, according to our protocol"""
    return derive_aes256_key(secret, "auth".encode("utf-8"))


def derive_enc_key(secret: bytes) -> bytes:
    """Generates an encryption key derived from a secret, according to our protocol"""
    return derive_aes256_key(secret, "enc".encode("utf-8"))


def serialize_key(key: ECC.EccKey) -> tuple[str, str]:
    """Generates a base64-encoded DER encoding of an ECC key in a tuple (private_key, public_key)"""
    priv_der_bytes, pub_der_bytes = (
        key.export_key(format="DER"),
        key.public_key().export_key(format="DER"),)

    return b64encode(priv_der_bytes).decode("utf-8"), b64encode(pub_der_bytes).decode("utf-8")


def parse_key(der_b64: str) -> ECC.EccKey:
    """Loads an ECC key (private or public) into a pycrpto EccKey object from its base64-encoded DER format"""
    try:
        key = ECC.import_key(b64decode(der_b64))
    except ValueError:  # key got modified, it's Invalid
        raise IntegrityError()
    return key


def dict_to_jsonb(d: dict) -> bytes:
    def recursive_sets_to_lists(x):
        if isinstance(x, dict):
            return {key: recursive_sets_to_lists(value) for key, value in x.items()}
        elif isinstance(x, set):
            return list(x)
        elif isinstance(x, list):
            return [recursive_sets_to_lists(elem) for elem in x]
        else:
            return x

    return json.dumps(recursive_sets_to_lists(d)).encode("utf-8")


def encrypt(plaintext: str, enc_key: bytes) -> tuple:
    cipher = AES.new(enc_key, AES.MODE_CBC)
    iv = cipher.iv.hex()
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size)).hex()
    return iv, ciphertext


def deserialize_payload(ciphertext: str) -> dict:
    return json.loads(ciphertext)


def validate_payload_hmac(payload: dict, auth_key: bytes) -> bool:
    """Validates that the body and MAC match"""
    hmac = HMAC.new(auth_key, dict_to_jsonb(payload["body"]), digestmod=SHA256)

    try:
        hmac.hexverify(payload["hmac"])
        return True
    except ValueError:
        # Could not verify HMAC
        raise InvalidHashError(payload["hmac"])
    except Exception:
        # unhandled exception
        raise


def parse_payload(payload: dict) -> tuple[bytes, bytes, int, ECC.EccKey]:
    """Returns a tuple with (ciphertext, iv, nonce, new_pub_key)"""

    body = payload["body"]

    ciphertext = bytes.fromhex(body["text"])
    iv = bytes.fromhex(body["iv"])
    nonce = body["nonce"]
    new_pub_key = parse_key(body["new_pub_key"])

    return ciphertext, iv, nonce, new_pub_key


def decrypt(ciphertext: bytes, iv: bytes, enc_key: bytes) -> str:
    cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode("utf-8")


def compute_hmac(auth_key: bytes, msg_body: bytes):
    return HMAC.new(auth_key, msg_body, digestmod=SHA256)
