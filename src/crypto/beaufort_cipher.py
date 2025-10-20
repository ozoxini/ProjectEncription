from typing import Any
from .base_algorithm import BaseCryptoAlgorithm


class BeaufortCipher(BaseCryptoAlgorithm):

    def __init__(self):
        super().__init__(
            name="Szyfr Beauforta",
            description=(
                "Szyfr polialfabetyczny będący odmianą szyfru Vigenère'a. "
                "Dla liter A-Z stosuje formułę C = (K - P) mod 26; szyfrowanie i "
                "deszyfrowanie są tą samą operacją."
            ),
        )
        self.ALPHABET_SIZE = 26
        self.A_ORD = ord('A')

    def _prepare_data(self, data: str) -> str:
        """Konwertuje tekst na duże litery i usuwa znaki niealfabetyczne."""
        return ''.join(filter(str.isalpha, data.upper()))

    def _get_key_stream(self, key: str, length: int):
        """Generuje powtarzający się strumień przesunięć klucza (0..25)."""
        key = self._prepare_data(key)
        if not key:
            return (0 for _ in range(length))
        key_shifts = [(ord(char) - self.A_ORD) for char in key]
        for i in range(length):
            yield key_shifts[i % len(key_shifts)]

    def encrypt(self, data: str, key: Any) -> str:
        if not self.validate_key(key):
            raise ValueError("Niepoprawny klucz dla szyfru Beauforta. Musi być niepustym ciągiem liter.")

        processed = self._prepare_data(data)
        key_stream = self._get_key_stream(str(key), len(processed))
        out_chars = []

        for char, k in zip(processed, key_stream):
            p = ord(char) - self.A_ORD
            c = (k - p) % self.ALPHABET_SIZE
            out_chars.append(chr(c + self.A_ORD))

        return ''.join(out_chars)

    def decrypt(self, data: str, key: Any) -> str:
        # Beaufort jest samoinwolucyjny (szyfrowanie == deszyfrowanie)
        return self.encrypt(data, key)

    def validate_key(self, key: Any) -> bool:
        if not isinstance(key, str):
            return False
        key = key.strip().upper()
        if not key:
            return False
        return all(char.isalpha() for char in key)

