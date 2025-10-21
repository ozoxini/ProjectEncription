from typing import Any
from .base_algorithm import BaseCryptoAlgorithm


class VigenereCipher(BaseCryptoAlgorithm):

    def __init__(self):
        # Wywołanie konstruktora klasy bazowej (rodzica)
        super().__init__(
            name="Szyfr Vigenere'a",
            description="Szyfr Vigenere'a, oparty na powtarzającym się kluczu. Działa tylko na literach alfabetu łacińskiego (A-Z) i ignoruje spacje/znaki interpunkcyjne."
        )
        self.ALPHABET_SIZE = 26
        self.A_ORD = ord('A') # Wartość ASCII dla 'A'
        # Running-key / autokey support (wyłączone domyślnie)
        self.running_key_enabled = False
        self._running_key_pos = 0

    # --- Metody Pomocnicze do Logiki Szyfru ---

    def _prepare_data(self, data: str) -> str:
        """Konwertuje tekst na duże litery, usuwa znaki niealfabetyczne."""
        return ''.join(filter(str.isalpha, data.upper()))

    def _get_key_stream(self, key: str, length: int):
        """Generuje strumień klucza (powtarzanie) o odpowiedniej długości."""
        key = self._prepare_data(key)
        key_len = len(key)
        # Generowanie klucza jako sekwencji przesunięć (0=A, 1=B, ..., 25=Z)
        key_shifts = [(ord(char) - self.A_ORD) for char in key]
        
        # Generator, który powtarza przesunięcia klucza
        for i in range(length):
            yield key_shifts[i % key_len]

    # --- Wymagane Metody Abstrakcyjne ---

    def encrypt(self, data: str, key: Any) -> str:
        # 1. Sprawdzanie, czy klucz jest poprawny
        if not self.validate_key(key):
            raise ValueError("Niepoprawny klucz Vigenère'a. Musi być niepustym ciągiem literowym.")
        processed_data = self._prepare_data(data)

        # Jeśli running-key wyłączony: zachowaj istniejącą logikę
        if not self.running_key_enabled:
            key_stream = self._get_key_stream(str(key), len(processed_data))
            encrypted_chars = []
            for char, shift in zip(processed_data, key_stream):
                char_ord = ord(char) - self.A_ORD
                new_char_ord = (char_ord + shift) % self.ALPHABET_SIZE
                encrypted_chars.append(chr(new_char_ord + self.A_ORD))
            return "".join(encrypted_chars)

        # --- Autokey (running-key) mode ---
        key_clean = self._prepare_data(str(key))
        if not key_clean:
            raise ValueError("Running key wymaga niepustego klucza tekstowego.")

        key_shifts = [(ord(c) - self.A_ORD) for c in key_clean]
        # Autokey: po początkowym kluczu używamy kolejnych liter jawnych
        key_stream_shifts = key_shifts + [(ord(c) - self.A_ORD) for c in processed_data]
        encrypted_chars = []
        for i, char in enumerate(processed_data):
            shift = key_stream_shifts[i]
            char_ord = ord(char) - self.A_ORD
            new_char_ord = (char_ord + shift) % self.ALPHABET_SIZE
            encrypted_chars.append(chr(new_char_ord + self.A_ORD))

        return "".join(encrypted_chars)

    def decrypt(self, data: str, key: Any) -> str:
        # 1. Sprawdzanie, czy klucz jest poprawny
        if not self.validate_key(key):
            raise ValueError("Niepoprawny klucz Vigenère'a. Musi być niepustym ciągiem literowym.")
        processed_data = self._prepare_data(data)

        # Jeśli running-key wyłączony: dotychczasowa logika
        if not self.running_key_enabled:
            key_stream = self._get_key_stream(str(key), len(processed_data))
            decrypted_chars = []
            for char, shift in zip(processed_data, key_stream):
                char_ord = ord(char) - self.A_ORD
                new_char_ord = (char_ord - shift + self.ALPHABET_SIZE) % self.ALPHABET_SIZE
                decrypted_chars.append(chr(new_char_ord + self.A_ORD))
            return "".join(decrypted_chars)

        # --- Autokey (running-key) mode: rebuild plaintext progressively ---
        key_clean = self._prepare_data(str(key))
        if not key_clean:
            raise ValueError("Running key wymaga niepustego klucza tekstowego.")

        key_shifts = [(ord(c) - self.A_ORD) for c in key_clean]
        plaintext_chars = []

        for i, c in enumerate(processed_data):
            if i < len(key_shifts):
                shift = key_shifts[i]
            else:
                # po wykorzystaniu początkowego klucza, używamy uprzednio odszyfrowanych liter
                shift = ord(plaintext_chars[i - len(key_shifts)]) - self.A_ORD

            c_ord = ord(c) - self.A_ORD
            p_ord = (c_ord - shift + self.ALPHABET_SIZE) % self.ALPHABET_SIZE
            plaintext_chars.append(chr(p_ord + self.A_ORD))

        return "".join(plaintext_chars)

    def validate_key(self, key: Any) -> bool:
        """Sprawdza, czy klucz jest niepustym stringiem zawierającym tylko litery."""
        if not isinstance(key, str):
            return False
        
        # Czy po usunięciu białych znaków i konwersji na duże litery pozostało coś?
        key = key.strip().upper()
        if not key:
            return False
            
        # Sprawdzenie, czy wszystkie pozostałe znaki są literami
        return all(char.isalpha() for char in key)

    # --- Running-key control helpers ---
    def enable_running_key(self) -> None:
        """Włącza autokey (running-key)."""
        self.running_key_enabled = True

    def disable_running_key(self) -> None:
        """Wyłącza autokey (running-key)."""
        self.running_key_enabled = False

    def reset_running_key(self) -> None:
        """Resetuje pozycję running-key (przydatne przy utrzymywaniu stanu)."""
        self._running_key_pos = 0