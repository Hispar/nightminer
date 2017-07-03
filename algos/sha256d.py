import hashlib


def sha256d(message):
    """Double SHA256 Hashing function."""

    return hashlib.sha256(hashlib.sha256(message).digest()).digest()
