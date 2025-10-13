from typing import Any
from .base_algorithm import BaseCryptoAlgorithm


class CaesarCipher(BaseCryptoAlgorithm):
    
    def __init__(self):
        super().__init__(
            name="Szyfr Cezara",
            description="Klasyczny szyfr przesunięcia, gdzie każda litera jest przesunięta o stałą liczbę pozycji w alfabecie"
        )
    
    def encrypt(self, data: str, key: int) -> str:
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz")
        
        result = []
        for char in data:
            if char.isalpha():
                # Obsługa polskich znaków
                if char in 'ąćęłńóśźż':
                    # Małe polskie litery
                    polish_lower = 'ąćęłńóśźż'
                    if char in polish_lower:
                        index = polish_lower.index(char)
                        shifted_index = (index + key) % len(polish_lower)
                        result.append(polish_lower[shifted_index])
                    else:
                        result.append(char)
                elif char in 'ĄĆĘŁŃÓŚŹŻ':
                    # Duże polskie litery
                    polish_upper = 'ĄĆĘŁŃÓŚŹŻ'
                    if char in polish_upper:
                        index = polish_upper.index(char)
                        shifted_index = (index + key) % len(polish_upper)
                        result.append(polish_upper[shifted_index])
                    else:
                        result.append(char)
                else:
                    # Standardowe litery łacińskie
                    start = ord('A') if char.isupper() else ord('a')
                    shifted = (ord(char) - start + key) % 26
                    result.append(chr(start + shifted))
            else:
                # Znaki niealfabetyczne pozostają bez zmian
                result.append(char)
        
        return ''.join(result)
    
    def decrypt(self, data: str, key: int) -> str:
        # Deszyfrowanie to szyfrowanie z przeciwnym kluczem
        return self.encrypt(data, -key)
    
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, int) and -25 <= key <= 25