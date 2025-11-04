import base64
from typing import Any, Union
from ..base_algorithm import BaseCryptoAlgorithm
from ..aes_core import AESCore 
class EcbMethod(BaseCryptoAlgorithm):

    def __init__(self):
        super().__init__(
            name="AES-128 (ECB)",
            description="Standardowy AES w niebezpiecznym trybie ECB."
        )
        # Tworzymy instancję naszego silnika
        self.core = AESCore()
        self.block_size = self.core.block_size

    def validate_key(self, key: Any) -> bool:
        """Klucz musi być tekstem (str) i nie może być pusty."""
        return isinstance(key, str) and len(key) > 0

    def _prepare_key(self, key_str: str) -> bytes:
        """Konwertuje klucz (str) na bajty i przycina/dopełnia do 16 bajtów."""
        key_bytes = key_str.encode('utf-8')
        return key_bytes.ljust(self.core.key_size, b'\x00')[:self.core.key_size]

    # --- Padding (PKCS#7) ---
    def _pad(self, dane: bytes) -> bytes:
        """Dopełnia dane do wielokrotności rozmiaru bloku."""
        ilosc_brakujaca = self.block_size - (len(dane) % self.block_size)
        bajt_dopelnienia = bytes([ilosc_brakujaca])
        return dane + bajt_dopelnienia * ilosc_brakujaca

    def _unpad(self, dane: bytes) -> bytes:
        """Usuwa dopełnienie PKCS#7 z danych."""
        if not dane:
            raise ValueError("Puste dane do od-dopełnienia")
        
        ilosc_dopelnienia = dane[-1]
        if ilosc_dopelnienia == 0 or ilosc_dopelnienia > self.block_size:
            raise ValueError("Błędna wartość dopełnienia")
        if dane[-ilosc_dopelnienia:] != bytes([ilosc_dopelnienia]) * ilosc_dopelnienia:
            raise ValueError("Błędne bajty dopełnienia")
        return dane[:-ilosc_dopelnienia]

    def encrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        return_text = False
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
            return_text = True
        elif isinstance(data, (bytes, bytearray)):
            data_bytes = bytes(data)
        else:
            raise TypeError("Dane muszą być typu str lub bytes")

        try:
            key_bytes = self._prepare_key(key)
            expanded_key = self.core.expand_key(key_bytes) # <-- Użyj silnika
            
            padded_data = self._pad(data_bytes)
            encrypted_bytes = b''

            # Logika ECB: szyfruj blok po bloku, niezależnie
            for i in range(0, len(padded_data), self.block_size):
                blok = padded_data[i : i + self.block_size]
                encrypted_bytes += self.core.encrypt_block(blok, expanded_key) 
        except Exception as e:
            raise RuntimeError(f"Błąd szyfrowania ECB: {e}")

        if return_text:
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_bytes

    def decrypt(self, data: Union[str, bytes], key: Any) -> Union[str, bytes]:
        if not self.validate_key(key):
            raise ValueError("Nieprawidłowy klucz.")

        return_text = False
        if isinstance(data, str):
            try:
                enc_bytes = base64.b64decode(data)
                return_text = True
            except Exception:
                raise ValueError("Nieprawidłowy format base64")
        elif isinstance(data, (bytes, bytearray)):
            enc_bytes = bytes(data)
        else:
            raise TypeError("Dane muszą być typu str lub bytes")
        
        if len(enc_bytes) % self.block_size != 0:
            raise ValueError("Dane szyfrogramu mają nieprawidłową długość.")

        try:
            key_bytes = self._prepare_key(key)
            expanded_key = self.core.expand_key(key_bytes) # <-- Użyj silnika
            
            decrypted_padded_bytes = b''

            # Logika ECB: deszyfruj blok po bloku, niezależnie
            for i in range(0, len(enc_bytes), self.block_size):
                blok = enc_bytes[i : i + self.block_size]
                decrypted_padded_bytes += self.core.decrypt_block(blok, expanded_key)

            decrypted_bytes = self._unpad(decrypted_padded_bytes)
        except ValueError as e:
            raise ValueError(f"Błąd deszyfrowania ECB: {e}. Prawdopodobnie zły klucz.")
        except Exception as e:
             raise RuntimeError(f"Błąd deszyfrowania ECB: {e}")

        if return_text:
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Błąd deszyfrowania: Zły klucz lub dane nie są tekstem UTF-8.")
        return decrypted_bytes