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
        key_stream = self._get_key_stream(str(key), len(processed_data))
        encrypted_chars = []

        for char, shift in zip(processed_data, key_stream):
            # Obliczenie przesunięcia dla danej litery
            char_ord = ord(char) - self.A_ORD
            new_char_ord = (char_ord + shift) % self.ALPHABET_SIZE
            encrypted_chars.append(chr(new_char_ord + self.A_ORD))

        return "".join(encrypted_chars)

    def decrypt(self, data: str, key: Any) -> str:
        # 1. Sprawdzanie, czy klucz jest poprawny
        if not self.validate_key(key):
            raise ValueError("Niepoprawny klucz Vigenère'a. Musi być niepustym ciągiem literowym.")
            
        processed_data = self._prepare_data(data)
        key_stream = self._get_key_stream(str(key), len(processed_data))
        decrypted_chars = []

        for char, shift in zip(processed_data, key_stream):
            # Deszyfrowanie to ODWROTNE przesunięcie
            char_ord = ord(char) - self.A_ORD
            # (char - shift) % 26. Dodajemy 26, żeby uniknąć ujemnego wyniku w modulo
            new_char_ord = (char_ord - shift + self.ALPHABET_SIZE) % self.ALPHABET_SIZE
            decrypted_chars.append(chr(new_char_ord + self.A_ORD))

        return "".join(decrypted_chars)

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