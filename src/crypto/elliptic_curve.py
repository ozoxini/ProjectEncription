"""
Implementacja krzywej eliptycznej P-256 (secp256r1)
Bez zewnętrznych bibliotek - tylko matematyka modulo
"""

import hashlib
from typing import Optional, Tuple


class Point:
    """Punkt na krzywej eliptycznej P-256: y² = x³ - 3x + b (mod p)"""
    
    def __init__(self, x: int, y: int):
        """Punkt (x, y) na krzywej P-256"""
        self.x = x
        self.y = y
    
    def __eq__(self, other: 'Point') -> bool:
        """Porównanie dwóch punktów"""
        if other is None:
            return False
        return self.x == other.x and self.y == other.y
    
    def __mul__(self, scalar: int) -> 'Point':
        """Mnożenie punktu przez skalar: scalar × P (używaj: result = scalar * point)"""
        return self.scalar_multiply(scalar)
    
    def __rmul__(self, scalar: int) -> 'Point':
        """Mnożenie skalarem (odwrotnie): scalar × P (używaj: result = scalar * point)"""
        return self.scalar_multiply(scalar)
    
    def is_at_infinity(self) -> bool:
        """Sprawdź czy punkt jest w nieskończoności (punkt neutralny)"""
        return self.x is None and self.y is None
    
    @staticmethod
    def infinity() -> 'Point':
        """Zwróć punkt w nieskończoności (element neutralny)"""
        p = Point(None, None)
        return p
    
    def double(self) -> 'Point':
        """Dodaj punkt do siebie: P + P"""
        if self.x is None:
            return Point.infinity()
        
        # Wzór na punkt podwójny:
        # λ = (3x² + a) / (2y) mod p
        # x' = λ² - 2x mod p
        # y' = λ(x - x') - y mod p
        
        p = P256_P
        a = P256_A
        
        # Oblicz λ
        numerator = (3 * self.x * self.x + a) % p
        denominator = (2 * self.y) % p
        denominator_inv = mod_inverse(denominator, p)
        lam = (numerator * denominator_inv) % p
        
        # Oblicz x'
        x_new = (lam * lam - 2 * self.x) % p
        
        # Oblicz y'
        y_new = (lam * (self.x - x_new) - self.y) % p
        
        return Point(x_new, y_new)
    
    def add(self, other: 'Point') -> 'Point':
        """Dodaj dwa różne punkty: P + Q"""
        if self.x is None:
            return other
        if other.x is None:
            return self
        
        if self.x == other.x:
            if self.y == other.y:
                return self.double()
            else:
                # Punkty są odwrotne: P + (-P) = O (nieskończoność)
                return Point.infinity()
        
        # Wzór na dodawanie dwóch różnych punktów:
        # λ = (Q.y - P.y) / (Q.x - P.x) mod p
        # x' = λ² - P.x - Q.x mod p
        # y' = λ(P.x - x') - P.y mod p
        
        p = P256_P
        
        # Oblicz λ
        numerator = (other.y - self.y) % p
        denominator = (other.x - self.x) % p
        denominator_inv = mod_inverse(denominator, p)
        lam = (numerator * denominator_inv) % p
        
        # Oblicz x'
        x_new = (lam * lam - self.x - other.x) % p
        
        # Oblicz y'
        y_new = (lam * (self.x - x_new) - self.y) % p
        
        return Point(x_new, y_new)
    
    def scalar_multiply(self, k: int) -> 'Point':
        """Mnóż punkt przez skalar: k × P (binary double-and-add method)"""
        if k == 0:
            return Point.infinity()
        
        if k < 0:
            # Dla ujemnych skalarów, zwróć punkt odwrotny
            k = -k
            result = self.scalar_multiply(k)
            return Point(result.x, (-result.y) % P256_P)
        
        # Binary method (double-and-add)
        result = Point.infinity()
        addend = self
        
        while k:
            if k & 1:  # Jeśli ostatni bit to 1
                result = result.add(addend)
            addend = addend.double()
            k >>= 1  # Przesuń bity w prawo
        
        return result
    
    def to_bytes(self) -> bytes:
        """Konwertuj punkt do bajtów: 0x04 || x(32B) || y(32B) (uncompressed format)"""
        if self.is_at_infinity():
            return b'\x00'
        return b'\x04' + self.x.to_bytes(32, 'big') + self.y.to_bytes(32, 'big')
    
    @staticmethod
    def from_bytes(data: bytes) -> 'Point':
        """Dekoduj punkt z bajtów"""
        if data == b'\x00':
            return Point.infinity()
        
        if data[0] != 0x04:
            raise ValueError("Nieznany format punktu (oczekiwany 0x04 uncompressed)")
        
        if len(data) != 65:  # 1 bajt flagi + 32 bajty x + 32 bajty y
            raise ValueError(f"Nieprawidłowa długość punktu: {len(data)} (oczekiwane 65)")
        
        x = int.from_bytes(data[1:33], 'big')
        y = int.from_bytes(data[33:65], 'big')
        
        return Point(x, y)


def mod_inverse(a: int, m: int) -> int:
    """
    Oblicza odwrotność modularną a mod m
    Używa rozszerzonego algorytmu Euklidesa
    """
    if a < 0:
        a = (a % m + m) % m
    
    g, x, _ = extended_gcd(a, m)
    
    if g != 1:
        raise ValueError(f"Odwrotność modularna nie istnieje dla {a} mod {m}")
    
    return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Rozszerzony algorytm Euklidesa
    Zwraca: (gcd, x, y) takie że a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


# ============================================
# Parametry Krzywej P-256 (secp256r1 / prime256v1)
# ============================================

# Liczba pierwsza definiująca pole
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

# Współczynnik a w równaniu: y² = x³ + ax + b
P256_A = -3

# Współczynnik b w równaniu: y² = x³ + ax + b
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

# Punkt bazowy G (generator)
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

# Rząd grupy (liczba punktów w grupie)
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


class EllipticCurveP256:
    """Krzywa eliptyczna P-256 - stałe i operacje"""
    
    # Stałe krzywej
    p = P256_P
    a = P256_A
    b = P256_B
    n = P256_N  # Rząd
    
    # Punkt bazowy
    G = Point(P256_GX, P256_GY)
    
    @staticmethod
    def verify_point(point: Point) -> bool:
        """Sprawdź czy punkt leży na krzywej: y² = x³ - 3x + b (mod p)"""
        if point.is_at_infinity():
            return True
        
        p = P256_P
        a = P256_A
        b = P256_B
        
        lhs = (point.y * point.y) % p
        rhs = (point.x * point.x * point.x + a * point.x + b) % p
        
        return lhs == rhs
