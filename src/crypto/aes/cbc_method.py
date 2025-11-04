import base64
import os  # Do generowania losowego IV
from typing import Any, Union
from ..base_algorithm import BaseCryptoAlgorithm
from ..aes_core import AESCore  # <-- Import silnika

# Funkcja pomocnicza do XORowania bloków
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Wykonuje operację XOR na dwóch ciągach bajtów."""
    return bytes(x ^ y for x, y in zip(a, b))

class CbcMethod(BaseCryptoAlgorithm):
    """
    Implementacja AES w trybie CBC ("Cipher Block Chaining").
    """
    def __init__(self):
        super().__init__(
            name="AES-128 (CBC)",
            description="Standardowy AES w bezpiecznym trybie CBC."
        )
        self.core = AESCore()
        self.block_size = self.core.block_size

    # --- Te funkcje są identyczne jak w ECB ---
    def validate_key(self, key: Any) -> bool:
        return isinstance(key, str) and len(key) > 0

    def _prepare_key(self, key_str: str) -> bytes:
        key_bytes = key_str.encode('utf-8')
        return key_bytes.ljust(self.core.key_size, b'\x00')[:self.core.key_size]

    def _pad(self, dane: bytes) -> bytes:
        ilosc_brakujaca = self.block_size - (len(dane) % self.block_size)
        bajt_dopelnienia = bytes([ilosc_brakujaca])
        return dane + bajt_dopelnienia * ilosc_brakujaca

    def _unpad(self, dane: bytes) -> bytes:
        if not dane:
            raise ValueError("Puste dane do od-dopełnienia")
        ilosc_dopelnienia = dane[-1]
        if ilosc_dopelnienia == 0 or ilosc_dopelnienia > self.block_size:
            raise ValueError("Błędna wartość dopełnienia")
        if dane[-ilosc_dopelnienia:] != bytes([ilosc_dopelnienia]) * ilosc_dopelnienia:
            raise ValueError("Błędne bajty dopełnienia")
        return dane[:-ilosc_dopelnienia]
    # --- Koniec identycznych funkcji ---

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
            expanded_key = self.core.expand_key(key_bytes)
            padded_data = self._pad(data_bytes)
            
            # --- Logika CBC ---
            # 1. Wygeneruj losowy Wektor Inicjujący (IV)
            iv = os.urandom(self.block_size)
            
            encrypted_bytes = b''
            poprzedni_blok_szyfrogramu = iv # Zaczynamy od IV

            for i in range(0, len(padded_data), self.block_size):
                blok_jawny = padded_data[i : i + self.block_size]
                
                # Operacja CBC: Ci = Ek(Pi ⊕ Ci-1)
                blok_do_szyfrowania = xor_bytes(blok_jawny, poprzedni_blok_szyfrogramu)
                nowy_blok_szyfrogramu = self.core.encrypt_block(blok_do_szyfrowania, expanded_key)
                
                encrypted_bytes += nowy_blok_szyfrogramu
                poprzedni_blok_szyfrogramu = nowy_blok_szyfrogramu

            # 2. Dołącz IV na początku szyfrogramu
            final_output_bytes = iv + encrypted_bytes
        except Exception as e:
            raise RuntimeError(f"Błąd szyfrowania CBC: {e}")

        if return_text:
            return base64.b64encode(final_output_bytes).decode('utf-8')
        return final_output_bytes

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
            expanded_key = self.core.expand_key(key_bytes)
            
            # --- Logika CBC ---
            # 1. Wyodrębnij IV (pierwsze 16 bajtów)
            iv = enc_bytes[:self.block_size]
            szyfrogram_wlasciwy = enc_bytes[self.block_size:]

            decrypted_padded_bytes = b''
            poprzedni_blok_szyfrogramu = iv

            for i in range(0, len(szyfrogram_wlasciwy), self.block_size):
                blok_szyfrogramu = szyfrogram_wlasciwy[i : i + self.block_size]
                
                # Operacja CBC: Pi = Dk(Ci) ⊕ Ci-1
                blok_odszyfrowany = self.core.decrypt_block(blok_szyfrogramu, expanded_key)
                blok_jawny = xor_bytes(blok_odszyfrowany, poprzedni_blok_szyfrogramu)
                
                decrypted_padded_bytes += blok_jawny
                poprzedni_blok_szyfrogramu = blok_szyfrogramu

            decrypted_bytes = self._unpad(decrypted_padded_bytes)
        except ValueError as e:
            raise ValueError(f"Błąd deszyfrowania CBC: {e}. Prawdopodobnie zły klucz.")
        except Exception as e:
            raise RuntimeError(f"Błąd deszyfrowania CBC: {e}")

        if return_text:
            try:
                return decrypted_bytes.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Błąd deszyfrowania: Zły klucz lub dane nie są tekstem UTF-8.")
        return decrypted_bytes