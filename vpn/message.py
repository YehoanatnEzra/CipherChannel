from Crypto.PublicKey import ECC
from vpn.crypto import *

# =========================================================================================== #
GENERAL_WARNING = 1
INTEGRITY_WARNING = 2


# =========================================================================================== #


class Message:
    def __init__(self,
                 nonce: int,
                 text: str,
                 secret: bytes,
                 new_pub_key: ECC.EccKey,
                 warnings: list[int] = [],
                 encrypted: bool = False,
                 iv=""):
        """
        Method instantiates a new message.

        Args:
            nonce (int): the nonce used to id the message
            text (str): the text to be sent in the message
            auth_key (bytes): the auth key used to authenticate the message
            enc_key (bytes): the encryption key used to encrypt the message
            new_pub_key (ECC.EccKey): the new key to be sent in the message
            warnings (int, optional): Contains warning types to issue.
            encrypted (bool): indicator of whether the text is encrypted

        Returns:
            New Message object
        """
        self.warnings = warnings
        self.text = text
        self.iv = iv
        self.encrypted = encrypted
        self.nonce = nonce
        self.auth_key = derive_auth_key(secret)
        self.enc_key = derive_enc_key(secret)
        self.new_p_key = new_pub_key

    def prepare_for_sending(self) -> str:
        """returns a formatted and encrypted message as a string, ready to send"""
        if not self.encrypted:
            self.iv, self.text = encrypt(self.text, self.enc_key)
            self.encrypted = True
        _, pubk = serialize_key(self.new_p_key)

        body = {
            "warnings": self.warnings,
            "text": self.text,
            "iv": self.iv,
            "nonce": self.nonce,
            "new_pub_key": pubk}

        hmac = HMAC.new(self.auth_key, dict_to_jsonb(body), digestmod=SHA256).hexdigest()
        payload = {"body": body, "hmac": hmac}
        return json.dumps(payload)

    def msg_decrypt(self, enc_key: bytes) -> str:
        """
        Decrypts the text in a message using the given encryption key.
        """
        if not self.encrypted:
            return self.text
        self.text = decrypt(bytes.fromhex(self.text), bytes.fromhex(self.iv), enc_key)
        self.encrypted = False
        return self.text

    @staticmethod
    def get_new_pub_key(data: dict) -> str:
        """
        Returns the new public key from a dictionary representation of the message object.
        """
        body = data.get("body")
        return body.get("new_pub_key")

    @staticmethod
    def deserialize_payload(payload: str) -> dict:
        """
        Reconstitutes a serialized object into a dictionary, the dictionary object can be passed to verify_and_parse
        to be reconstituted into a message object.
        """
        if not payload:  # Empty payload is a Mallory drop
            raise DroppedMessageError()

        dict_to_ret = json.loads(payload)

        if not verify_dict_structure(dict_to_ret):
            raise JSONDecodeError("todo", "todo", 42)
        return dict_to_ret

    @staticmethod
    def extract_text(data: dict) -> str:
        body = data.get("body")
        return body.get("text")

    @staticmethod
    def verify_and_parse(data: dict, secret, expected_nonce: int) -> "Message":
        """
        This method assumes the data is encrypted.
        Takes in a dictionary representation of a message and returns a message object.
        """
        auth_key = derive_auth_key(secret)
        enc_key = derive_enc_key(secret)
        msg_body = data.get("body")
        if msg_body is None:
            raise IntegrityError("Invalid body supplied to verify_and_parse")

        hmac = compute_hmac(auth_key, dict_to_jsonb(msg_body))

        try:
            hmac.hexverify(data["hmac"])
        except ValueError:
            raise InvalidHashError(data["hmac"])

        if expected_nonce > msg_body.get("nonce"):
            raise InvalidNonceError(msg_body.get("nonce"), expected_nonce)

        return Message(msg_body.get("nonce"),
                       msg_body.get("text"), secret, msg_body.get("new_pub_key"),
                       msg_body.get("warnings"), True, msg_body.get("iv"))

    def set_general_warning(self) -> None:
        if GENERAL_WARNING not in self.warnings:
            self.warnings.append(GENERAL_WARNING)

    def set_integrity_warning(self) -> None:
        if INTEGRITY_WARNING not in self.warnings:
            self.warnings.append(INTEGRITY_WARNING)

    def is_general_warning(self) -> bool:
        return GENERAL_WARNING in self.warnings

    def is_integrity_warning(self) -> bool:
        return INTEGRITY_WARNING in self.warnings


def verify_dict_structure(d: dict) -> bool:
    try:
        assert "body" in d
        assert "hmac" in d
        assert "warnings" in d["body"]
        assert "text" in d["body"]
        assert "iv" in d["body"]
        assert "nonce" in d["body"]
        assert "new_pub_key" in d["body"]
        return True
    except AssertionError:
        return False
