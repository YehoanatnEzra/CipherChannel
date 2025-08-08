from config.keys import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
from vpn.crypto import *
from vpn.message import Message

ACK_FOR_FORGED = "what goes around comes around: invalid message, invalid response :)"
ACK_FOR_REPLAY_OR_DROP = "go away, mallory"


class VpnServer:
    def __init__(self, output_file):
        # pycrypto EccKey objects containing the current keys to use for the ratchet
        self.c_pub = None  # Client public key, set only when the connection is established
        self.message_cache = set()  # To detect replays
        self.s_priv = parse_key(SERVER_PRIVATE_KEY)  # Server private/public keypair
        self.nonce = 0
        self.output_file = output_file
        self.output_file.truncate(0)  # Clear file content (new session)
        self.logged_integrity_warning = False
        self.logged_general_warning = False
        self.prev_s_priv = None  # In case the client resends, and we need to verify with old keys

    def receive(self, ciphertext: str) -> str:
        """processes the ciphertext and returns an ack string ready to be sent to the client"""
        if self.c_pub is None:  # assume the first message is the initial pub key from the client
            self.c_pub = parse_key(ciphertext)
            return SERVER_PUBLIC_KEY

        plaintext = " "
        try:
            self._process_ciphertext(ciphertext)
        except Exception as e1:  # Detected security issue
            if is_integrity_error(e1):  # Suspected as integrity, but let's make sure
                try:
                    self._process_ciphertext_with_old_keys(ciphertext)  # Maybe a resend from the client?
                except Exception as e2:
                    return self.replay_or_forge(ciphertext, e2)
            elif is_general_error(e1):
                self._log_general_warning()
                return ACK_FOR_REPLAY_OR_DROP
            else:
                raise e1
        return self._prepare_ack("ack for " + plaintext[:-1])

    def _prepare_ack(self, message_text: str = "ack") -> str:
        """
        Creates a new encrypted message to be sent to the client according to communication protocol.
        It generates a new key pair, derives encryption and authentication keys using a shared secret, and constructs
        a serialized message object.

        Parameters:
            message_text (str): The content of the message to be sent to the client. Defaults to "ack".
        Returns:
            str: A serialized string (JSON format) representing the constructed message, ready to be sent to the client.
        """
        new_key = generate_keypair()
        secret = generate_shared_secret(new_key, self.c_pub)

        msg = Message(self.nonce, message_text, secret, new_key)
        message_to_send = msg.prepare_for_sending()

        self.prev_s_priv = self.s_priv
        self.s_priv = new_key
        self._cache(message_to_send)  # so that acks are also never replayed

        return message_to_send

    def _process_ciphertext(self, ciphertext):
        """ Process an incoming encrypted message from the client. """
        # Parse the JSON payload and check its structure
        client_mes_dict = Message.deserialize_payload(ciphertext)
        # Extract the client's new public key (base64), parse it, and derive a
        new_s_pub = Message.get_new_pub_key(client_mes_dict)
        secret = generate_shared_secret(self.s_priv, parse_key(new_s_pub))

        # Verify HMAC and nonce, and build a Message object
        msg = Message.verify_and_parse(client_mes_dict, secret, self.nonce)
        # Decrypt the ciphertext to ensure correct encryption
        plaintext = msg.msg_decrypt(derive_enc_key(secret))

        # Log the decrypted plaintext and any detected warnings
        if plaintext:  # Some messages will be empty with just warnings, ignore them when logging content
            self._output(plaintext)
        self._log_warnings(msg)  # Log warnings detected by client

        # Update ratchet state for next message
        self.c_pub = parse_key(new_s_pub)        # use the new client public key next time
        self._cache(ciphertext)                   # record this ciphertext to prevent replay
        self.nonce = msg.nonce + 1               # increment nonce for the next incoming message

        # return the original ciphertext so receive() can generate an ACK
        return ciphertext

    def _process_ciphertext_with_old_keys(self, ciphertext):
        client_mes_dict = Message.deserialize_payload(ciphertext)
        new_s_pub = Message.get_new_pub_key(client_mes_dict)
        secret = generate_shared_secret(self.prev_s_priv, parse_key(new_s_pub))
        msg = Message.verify_and_parse(client_mes_dict, secret, self.nonce)
        self._log_warnings(msg)  # Log warnings detected by client
        self._cache(ciphertext)
        self.nonce = msg.nonce + 1
        self.s_priv = self.prev_s_priv  # set private key to the previous one

    def replay_or_forge(self, ciphertext, e):
        """Identifies if the ciphertext is a replay or a forge, and returns correct ack"""
        if is_integrity_error(e):  # Not a resend from the client, maybe a Mallory replay?
            if self._is_replay(ciphertext):
                self._log_general_warning()
                return ACK_FOR_REPLAY_OR_DROP
            # truly a forged message
            self._log_integrity_warning()
            return ACK_FOR_FORGED
        if is_general_error(e):
            self._log_general_warning()
            return ACK_FOR_REPLAY_OR_DROP
        raise e

    def _cache(self, ciphertext):
        msg_hash = SHA256.new(ciphertext.encode("utf-8")).digest()
        self.message_cache.add(msg_hash)

    def _is_replay(self, ciphertext):
        msg_hash = SHA256.new(ciphertext.encode("utf-8")).digest()
        return msg_hash in self.message_cache

    def _output(self, message: str) -> None:
        """You should not need to modify this function.
        Output whatever the client typed into the textbox as an argument to this function
        """
        self.output_file.write(message)
        self.output_file.flush()

    def _log_general_warning(self):
        if not self.logged_general_warning:
            self._output("Mallory detected: General warning!\n")
            self.logged_general_warning = True

    def _log_integrity_warning(self):
        if not self.logged_integrity_warning:
            self._output("Mallory detected: Integrity warning!\n")
            self.logged_integrity_warning = True

    def _log_warnings(self, msg: Message) -> None:
        if msg.is_general_warning():
            self._log_general_warning()
        if msg.is_integrity_warning():
            self._log_integrity_warning()
