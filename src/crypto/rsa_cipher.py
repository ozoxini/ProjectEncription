import secrets
import hashlib
from typing import Any, Tuple
from .base_algorithm import BaseCryptoAlgorithm


class RsaCipher(BaseCryptoAlgorithm):

    def __init__(self):
        super().__init__("RSA", "Szyfr asymetryczny RSA")
        self.hash_func = hashlib.sha256
        self.hash_len = self.hash_func().digest_size


    def validate_key(self, key: Any) -> bool:
        return isinstance(key, tuple) and len(key) == 2

    def generate_keys(self, bit_length: int = 2048):
        """Generuje bezpieczne klucze RSA."""
        p = self._generate_prime(bit_length // 2)
        q = self._generate_prime(bit_length // 2)
        while p == q:
            q = self._generate_prime(bit_length // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        d = pow(e, -1, phi)

        return (e, n), (d, n)


    # OAEP – ENCODE / DECODE

    def _mgf1(self, seed: bytes, length: int) -> bytes:
        """MGF1 zgodne z PKCS#1."""
        counter = 0
        output = b""
        while len(output) < length:
            c = counter.to_bytes(4, "big")
            output += self.hash_func(seed + c).digest()
            counter += 1
        return output[:length]

    def _oaep_encode(self, msg: bytes, k: int) -> int:
        """RSAES-OAEP-ENCODE (RFC 8017)."""
        h_len = self.hash_len
        l_hash = self.hash_func(b"").digest()

        m_len = len(msg)

        # k = rozmiar modułu w bajtach
        if m_len > k - 2 * h_len - 2:
            raise ValueError("Wiadomość zbyt długa dla OAEP.")

        padding_len = k - m_len - 2 * h_len - 2
        ps = b"\x00" * padding_len

        db = l_hash + ps + b"\x01" + msg
        seed = secrets.token_bytes(h_len)

        db_mask = self._mgf1(seed, k - h_len - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        seed_mask = self._mgf1(masked_db, h_len)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

        em = b"\x00" + masked_seed + masked_db
        return int.from_bytes(em, "big")

    def _oaep_decode(self, em_int: int, k: int) -> bytes:
        """RSAES-OAEP-DECODE."""
        h_len = self.hash_len
        em = em_int.to_bytes(k, "big")

        l_hash = self.hash_func(b"").digest()

        y = em[0]
        masked_seed = em[1:1 + h_len]
        masked_db = em[1 + h_len:]

        seed_mask = self._mgf1(masked_db, h_len)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

        db_mask = self._mgf1(seed, k - h_len - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        if db[:h_len] != l_hash:
            raise ValueError("OAEP: Błędny hash label.")

        # Znajdź separator \x01
        i = h_len
        while i < len(db) and db[i] == 0:
            i += 1
        
        if i >= len(db) or db[i] != 1:
            raise ValueError("OAEP decode error.")

        return db[i + 1:]


    # SZYFROWANIE RSA-OAEP


    def encrypt(self, data: Any, public_key: Tuple[int, int]) -> bytes:
        if isinstance(data, str):
            data = data.encode()

        e, n = public_key
        k = (n.bit_length() + 7) // 8

        m = self._oaep_encode(data, k)
        c = pow(m, e, n)

        return c.to_bytes(k, "big")

    def decrypt(self, encrypted_data: bytes, private_key: Tuple[int, int]) -> bytes:
        d, n = private_key
        k = (n.bit_length() + 7) // 8

        c = int.from_bytes(encrypted_data, "big")
        m = pow(c, d, n)

        return self._oaep_decode(m, k)

    # PSS – SIGN / VERIFY


    def sign(self, data: bytes, private_key: Tuple[int, int]) -> bytes:
        if isinstance(data, str):
            data = data.encode()

        d, n = private_key
        k = (n.bit_length() + 7) // 8
        h = self.hash_func(data).digest()

        # RSASSA-PSS
        salt = secrets.token_bytes(self.hash_len)
        m_prime = b"\x00" * 8 + h + salt
        h_prime = self.hash_func(m_prime).digest()

        ps = b"\x00" * (k - self.hash_len * 2 - 2)
        db = ps + b"\x01" + salt
        db_mask = self._mgf1(h_prime, k - self.hash_len - 1)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        em = masked_db + h_prime + b"\xbc"
        em_int = int.from_bytes(em, "big")

        s = pow(em_int, d, n)
        return s.to_bytes(k, "big")

    def verify(self, data: bytes, signature: bytes, public_key: Tuple[int, int]) -> bool:
        if isinstance(data, str):
            data = data.encode()

        e, n = public_key
        k = (n.bit_length() + 7) // 8

        try:
            h = self.hash_func(data).digest()

            s = int.from_bytes(signature, "big")
            em_int = pow(s, e, n)
            em = em_int.to_bytes(k, "big")

            if em[-1] != 0xbc:
                return False

            h_prime = em[-1 - self.hash_len : -1]
            masked_db = em[: -1 - self.hash_len]

            db_mask = self._mgf1(h_prime, len(masked_db))
            db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

            # znajdź delimiter 0x01
            i = 0
            while i < len(db) and db[i] == 0:
                i += 1
            if i >= len(db) or db[i] != 1:
                return False

            salt = db[i+1:]
            m_prime = b"\x00"*8 + h + salt

            h_check = self.hash_func(m_prime).digest()
            return h_check == h_prime

        except Exception:
            return False


    # PRZYDATNE FUNKCJE POMOCNICZE


    def _generate_prime(self, bits: int) -> int:
        """Generowanie bezpiecznej liczby pierwszej."""
        while True:
            p = secrets.randbits(bits)
            p |= (1 << (bits - 1)) | 1
            if self._is_prime(p):
                return p

    def _is_prime(self, n: int, k: int = 20) -> bool:
        """Miller-Rabin (bez random)."""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, s, n)
            if x in (1, n - 1):
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True