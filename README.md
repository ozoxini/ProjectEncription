# Instrukcja Instalacji

## Wymagania Systemowe

- **Python:** 3.7 lub nowszy
- **System operacyjny:** Windows, macOS, Linux

## Instalacja

### Metoda 1: Instalacja z GitHub

```bash
# Sklonuj repozytorium
git clone https://github.com/ozoxini/ProjectEncription
cd ProjectEncription

# Zainstaluj zależności
pip install -r requirements.txt

# Uruchom aplikację
python main.py
```

### Metoda 2: Instalacja lokalna

```bash
# Pobierz pliki projektu
# Rozpakuj archiwum do wybranego folderu
cd ProjectEncription

# Zainstaluj zależności
pip install -r requirements.txt

# Uruchom aplikację
python main.py
```

##  Rozwiązywanie Problemów

### Błąd: "ModuleNotFoundError: No module named 'PyQt5'"
```bash
# Rozwiązanie:
pip install PyQt5==5.15.9
```

### Błąd: "Python not found"
```bash
# Zainstaluj Python z https://python.org
# Upewnij się, że Python jest w PATH
python --version
```

##  Struktura Projektu

```
ProjectEncription/
├── main.py                    # Główny plik aplikacji
├── requirements.txt           # Zależności Python
├── README.md                 # Dokumentacja
├── CHANGELOG.md              # Historia zmian
├── LICENSE                   # Licencja MIT
├── INSTALL.md                # Ta instrukcja
├── test_app.py              # Testy aplikacji
└── src/
    ├── crypto/               # Moduł 
    └── ui/                   # Interfejs użytkownika
```

## 🎯 Pierwsze Uruchomienie

1. **Uruchom aplikację:**
   ```bash
   python main.py
   ```

2. **Sprawdź funkcjonalność:**
   - Wybierz zakładkę "Tekst"
   - Wprowadź tekst: "Hello World"
   - Ustaw klucz: 3
   - Kliknij "Szyfruj"
   - Sprawdź wynik: "Khoor Zruog"

3. **Test plików:**
   - Wybierz zakładkę "Plik"
   - Stwórz plik testowy
   - Wybierz plik i zaszyfruj
   - Sprawdź czy plik został zmieniony

## Architektura

Aplikacja została zaprojektowana z myślą o łatwym dodawaniu nowych algorytmów:

- `src/crypto/base_algorithm.py` - Bazowa klasa dla algorytmów
- `src/crypto/caesar_cipher.py` - Implementacja szyfru Cezara
- `src/crypto/algorithm_manager.py` - Menedżer algorytmów
- `src/ui/main_window.py` - Interfejs użytkownika

## Dodawanie Nowych Algorytmów

Aby dodać nowy algorytm, stwórz klasę dziedziczącą z `BaseCryptoAlgorithm` i zarejestruj ją w `AlgorithmManager`.