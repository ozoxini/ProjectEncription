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
        # Running-key / autokey support (wyłączone domyślnie)
        self.running_key_enabled = False
        self._running_key_pos = 0

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
        # If running-key not enabled: old behaviour
        if not self.running_key_enabled:
            key_stream = self._get_key_stream(str(key), len(processed))
            out_chars = []
            for char, k in zip(processed, key_stream):
                p = ord(char) - self.A_ORD
                c = (k - p) % self.ALPHABET_SIZE
                out_chars.append(chr(c + self.A_ORD))
            return ''.join(out_chars)

        # --- Running-key (autokey) mode ---
        key_clean = self._prepare_data(str(key))
        if not key_clean:
            raise ValueError("Running key wymaga niepustego klucza tekstowego.")

        # Build key stream: initial key then plaintext letters
        key_shifts = [(ord(c) - self.A_ORD) for c in key_clean]
        key_stream_shifts = key_shifts + [(ord(c) - self.A_ORD) for c in processed]

        out_chars = []
        for i, char in enumerate(processed):
            k = key_stream_shifts[i]
            p = ord(char) - self.A_ORD
            c = (k - p) % self.ALPHABET_SIZE
            out_chars.append(chr(c + self.A_ORD))

        return ''.join(out_chars)

    def decrypt(self, data: str, key: Any) -> str:
        # Beaufort jest samoinwolucyjny (szyfrowanie == deszyfrowanie)
        # Jeśli running-key wyłączony — użyj szyfrowania (samoinwolucyjny)
        if not self.running_key_enabled:
            return self.encrypt(data, key)

        # W trybie running-key musimy stopniowo odbudowywać oryginalny tekst
        processed = self._prepare_data(data)
        key_clean = self._prepare_data(str(key))
        if not key_clean:
            raise ValueError("Running key wymaga niepustego klucza tekstowego.")

        key_shifts = [(ord(c) - self.A_ORD) for c in key_clean]
        plaintext_chars = []

        for i, c in enumerate(processed):
            c_ord = ord(c) - self.A_ORD
            if i < len(key_shifts):
                k = key_shifts[i]
            else:
                # po wykorzystaniu początkowego klucza, używamy uprzednio odszyfrowanych liter jako klucza
                k = ord(plaintext_chars[i - len(key_shifts)]) - self.A_ORD

            # dla Beauforta: c = (k - p) mod 26 => p = (k - c) mod 26
            p_ord = (k - c_ord) % self.ALPHABET_SIZE
            plaintext_chars.append(chr(p_ord + self.A_ORD))

        return ''.join(plaintext_chars)

    def validate_key(self, key: Any) -> bool:
        if not isinstance(key, str):
            return False
        key = key.strip().upper()
        if not key:
            return False
        return all(char.isalpha() for char in key)

    # Running-key helpers
    def enable_running_key(self) -> None:
        self.running_key_enabled = True

    def disable_running_key(self) -> None:
        self.running_key_enabled = False

    def reset_running_key(self) -> None:
        self._running_key_pos = 0

