"""
Główne okno aplikacji kryptograficznej
"""

from tkinter import EW
from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QStackedWidget, QLabel, QPushButton, QTextEdit, 
                            QLineEdit, QComboBox, QSpinBox, QFileDialog, 
                            QMessageBox, QGroupBox, QFormLayout, QSplitter)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
import os
import ast

from ..crypto.algorithm_manager import AlgorithmManager


class MainWindow(QMainWindow):
    """Główne okno aplikacji"""
    
    def __init__(self):
        super().__init__()
        self.algorithm_manager = AlgorithmManager()
        self.current_algorithm = None

        # Kontrolki specyficzne dla RSA (przeniesione z init_ui)
        self.rsa_group_box = QGroupBox("Opcje RSA")
        rsa_outer_layout = QFormLayout(self.rsa_group_box)
        
        self.generate_keys_btn = QPushButton("Generuj nowe klucze")
        rsa_outer_layout.addRow(self.generate_keys_btn)

        self.rsa_mode_combo = QComboBox()
        self.rsa_mode_combo.addItems(["Szyfruj / Deszyfruj", "Podpisz / Weryfikuj"])
        rsa_outer_layout.addRow("Tryb operacji:", self.rsa_mode_combo)

        keys_layout = QHBoxLayout()
        
        public_key_layout = QVBoxLayout()
        public_key_label = QLabel("Klucz publiczny:")
        self.public_key_text = QTextEdit()
        self.public_key_text.setPlaceholderText("(e, n)")
        public_key_layout.addWidget(public_key_label)
        public_key_layout.addWidget(self.public_key_text)
        
        private_key_layout = QVBoxLayout()
        private_key_label = QLabel("Klucz prywatny:")
        self.private_key_text = QTextEdit()
        self.private_key_text.setPlaceholderText("(d, n)")
        private_key_layout.addWidget(private_key_label)
        private_key_layout.addWidget(self.private_key_text)
        
        keys_layout.addLayout(public_key_layout)
        keys_layout.addLayout(private_key_layout)
        rsa_outer_layout.addRow(keys_layout)

        self.init_ui()
        self.apply_studio_style()
    
    def init_ui(self):
        """Inicjalizuje interfejs użytkownika w stylu Studio"""
        self.setWindowTitle("Szyfronator")
        self.setGeometry(100, 100, 850, 750)
        
        # Główny widget i layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(35, 25, 35, 25)
        main_layout.setAlignment(Qt.AlignTop)
        
        # Duży tytuł aplikacji, wyrównany do lewej
        title_label = QLabel("Szyfronator")
        title_label.setObjectName("mainTitle")
        title_label.setAlignment(Qt.AlignLeft)
        main_layout.addWidget(title_label)
        
        # Segmented Control (przełącznik widoków), wyrównany do lewej
        segmented_control_layout = QHBoxLayout()
        segmented_control_layout.setSpacing(0)
        segmented_control_layout.setAlignment(Qt.AlignLeft)

        self.btn_tekst = QPushButton("Tekst")
        self.btn_tekst.setObjectName("segmentedButtonLeft")
        self.btn_tekst.setCheckable(True)
        
        self.btn_plik = QPushButton("Plik")
        self.btn_plik.setObjectName("segmentedButtonRight")
        self.btn_plik.setCheckable(True)
        
        segmented_control_layout.addWidget(self.btn_tekst)
        segmented_control_layout.addWidget(self.btn_plik)
        segmented_control_layout.addStretch(1)
        main_layout.addLayout(segmented_control_layout)
        
        # Kontener na przełączane widoki
        self.stacked_widget = QStackedWidget()
        self.stacked_widget.addWidget(self.create_text_view())
        self.stacked_widget.addWidget(self.create_file_view())
        main_layout.addWidget(self.stacked_widget)
        
        # Połączenia sygnałów
        self.btn_tekst.clicked.connect(lambda: self.switch_view(0))
        self.btn_plik.clicked.connect(lambda: self.switch_view(1))
        
        # Połączenia przycisków
        self.generate_keys_btn.clicked.connect(self.generate_rsa_keys)
        self.encrypt_btn.clicked.connect(self.encrypt_text)
        self.decrypt_btn.clicked.connect(self.decrypt_text)
        self.clear_btn.clicked.connect(self.clear_text)
        self.encrypt_file_btn.clicked.connect(self.encrypt_file)
        self.decrypt_file_btn.clicked.connect(self.decrypt_file)
        
        # Pasek statusu
        self.statusBar().showMessage("Gotowy")
        version_label = QLabel("v.1.3a")
        version_label.setObjectName("versionLabel")
        self.statusBar().addPermanentWidget(version_label)
        
        # Ustawienie stanu początkowego
        self.switch_view(0)
        if self.algorithm_combo.count() > 0:
            self.on_algorithm_changed(self.algorithm_combo.currentText())

    def switch_view(self, index):
        """Przełącza widok i styl przycisków"""
        self.stacked_widget.setCurrentIndex(index)
        self.btn_tekst.setChecked(index == 0)
        self.btn_plik.setChecked(index == 1)

    def create_text_view(self):
        """Tworzy widok ("kartę") do szyfrowania tekstu"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setSpacing(20)
        layout.setContentsMargins(0, 20, 0, 0)
        
        # Karta z ustawieniami
        control_card = QGroupBox()
        control_layout = QFormLayout(control_card)
        control_layout.setSpacing(15)
        
        self.algorithm_combo = QComboBox()
        self.populate_algorithms()
        self.algorithm_combo.currentTextChanged.connect(self.on_algorithm_changed)
        control_layout.addRow("Algorytm:", self.algorithm_combo)

        # Dodajemy ComboBox dla rozmiaru klucza AES, początkowo ukryty
        self.aes_key_size_combo = QComboBox()
        self.aes_key_size_combo.addItems(["AES-128 (16 bajtów)", "AES-192 (24 bajty)", "AES-256 (32 bajty)"])
        self.aes_key_size_label = QLabel("Rozmiar klucza AES:")
        control_layout.addRow(self.aes_key_size_label, self.aes_key_size_combo)
        self.aes_key_size_label.hide()
        self.aes_key_size_combo.hide()
        
        control_layout.addRow(self.rsa_group_box) # Dodajemy rsa_group_box do layoutu tekstowego
        # self.rsa_group_box.hide() # Ukrywanie jest obsługiwane przez on_algorithm_changed
        
        # ZAMIANA: zamiast pojedynczego QSpinBox udostępniamy stos (spin/text)
        self.key_spin = QSpinBox()
        self.key_spin.setRange(-25, 25)
        self.key_spin.setValue(3)
        spin_container = QWidget()
        spin_layout = QHBoxLayout(spin_container)
        spin_layout.setContentsMargins(0, 0, 0, 0)
        spin_layout.addWidget(self.key_spin)

        self.key_text = QLineEdit()
        self.key_text.setPlaceholderText("Wpisz klucz tekstowy...")
        text_container = QWidget()
        text_layout = QHBoxLayout(text_container)
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.addWidget(self.key_text)

        self.key_stack = QStackedWidget()
        self.key_stack.addWidget(spin_container)   # index 0 -> numeric
        self.key_stack.addWidget(text_container)   # index 1 -> text

        control_layout.addRow(self.key_stack)
        ##self.key_input = QTextEdit()
        ##control_layout.addRow("Klucz:", self.input_text)

        layout.addWidget(control_card)

        # Karta z polami tekstowymi
        text_card = QGroupBox()
        text_layout = QVBoxLayout(text_card)
        text_layout.setSpacing(15)
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Wpisz lub wklej tekst...")
        self.output_text = QTextEdit()
        self.output_text.setPlaceholderText("Tutaj pojawi się wynik...")
        self.output_text.setReadOnly(True)
        
        text_layout.addWidget(self.input_text)
        text_layout.addWidget(self.output_text)
        layout.addWidget(text_card)

        # Przyciski akcji
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        self.encrypt_btn = QPushButton("Szyfruj")
        self.decrypt_btn = QPushButton("Deszyfruj")
        self.clear_btn = QPushButton("Wyczyść")
        self.clear_btn.setObjectName("clearButton")

        button_layout.addStretch()
        button_layout.addWidget(self.encrypt_btn)
        button_layout.addWidget(self.decrypt_btn)
        button_layout.addWidget(self.clear_btn)
        layout.addLayout(button_layout)
        
        return view

    def create_file_view(self):
        """Tworzy widok ("kartę") do szyfrowania plików"""
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setSpacing(20)
        layout.setContentsMargins(0, 20, 0, 0)
        layout.setAlignment(Qt.AlignTop)

        # Karta z ustawieniami
        settings_card = QGroupBox()
        settings_layout = QFormLayout(settings_card)
        settings_layout.setSpacing(15)
        
        self.file_algorithm_combo = QComboBox()
        self.populate_file_algorithms()
        # podłączamy także zmianę wyboru w combo plików do tej samej metody
        self.file_algorithm_combo.currentTextChanged.connect(self.on_algorithm_changed)
        settings_layout.addRow("Algorytm:", self.file_algorithm_combo)

        # Dodajemy ComboBox dla rozmiaru klucza AES w widoku pliku
        self.file_aes_key_size_combo = QComboBox()
        self.file_aes_key_size_combo.addItems(["AES-128 (16 bajtów)", "AES-192 (24 bajty)", "AES-256 (32 bajty)"])
        self.file_aes_key_size_label = QLabel("Rozmiar klucza AES:")
        settings_layout.addRow(self.file_aes_key_size_label, self.file_aes_key_size_combo)
        self.file_aes_key_size_label.hide()
        self.file_aes_key_size_combo.hide()

        settings_layout.addRow(self.rsa_group_box) # Dodajemy rsa_group_box do layoutu plikowego
        # self.rsa_group_box.hide() # Ukrywanie jest obsługiwane przez on_algorithm_changed
        
        # ZAMIANA podobnie jak w widoku tekstowym: stack dla klucza plikowego
        self.file_key_spin = QSpinBox()
        self.file_key_spin.setRange(-25, 25)
        self.file_key_spin.setValue(3)
        fspin_container = QWidget()
        fspin_layout = QHBoxLayout(fspin_container)
        fspin_layout.setContentsMargins(0, 0, 0, 0)
        fspin_layout.addWidget(self.file_key_spin)

        self.file_key_text = QLineEdit()
        self.file_key_text.setPlaceholderText("Wpisz klucz tekstowy...")
        ftext_container = QWidget()
        ftext_layout = QHBoxLayout(ftext_container)
        ftext_layout.setContentsMargins(0, 0, 0, 0)
        ftext_layout.addWidget(self.file_key_text)


        self.file_key_stack = QStackedWidget()
        self.file_key_stack.addWidget(fspin_container)
        self.file_key_stack.addWidget(ftext_container)


        settings_layout.addRow(self.file_key_stack)
        layout.addWidget(settings_card)
        
        # Karta operacji na pliku
        file_card = QGroupBox()
        file_layout = QVBoxLayout(file_card)
        file_layout.setSpacing(15)
        
        file_selection_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("Wybierz plik do przetworzenia...")
        self.file_path_input.setReadOnly(True)
        self.browse_btn = QPushButton("...")
        self.browse_btn.setFixedWidth(50)
        self.browse_btn.clicked.connect(self.browse_file)
        
        file_selection_layout.addWidget(self.file_path_input)
        file_selection_layout.addWidget(self.browse_btn)
        file_layout.addLayout(file_selection_layout)
        
        button_layout = QHBoxLayout()
        self.encrypt_file_btn = QPushButton("Szyfruj Plik")
        self.decrypt_file_btn = QPushButton("Deszyfruj Plik")
        
        button_layout.addStretch()
        button_layout.addWidget(self.encrypt_file_btn)
        button_layout.addWidget(self.decrypt_file_btn)
        file_layout.addLayout(button_layout)
        
        layout.addWidget(file_card)
        
        layout.addStretch(1)

        return view

    def apply_studio_style(self):
        """Aplikuje profesjonalny, stonowany styl 'Studio UI'"""
        # --- Paleta Kolorów ---
        BG_COLOR = "#1a1a1f"           # Głęboki grafit
        CARD_COLOR = "#25252b"         # Ciemnoszara karta
        INPUT_COLOR = "#2d2d33"        # Pole wprowadzania
        BORDER_COLOR = "#3a3a40"       # Subtelna ramka
        TEXT_PRIMARY = "#ffffff"       # Czysty, jasny tekst
        TEXT_SECONDARY = "#a0a0a8"     # Drugorzędny szary
        ACCENT_BLUE = "#4a90e2"        # Niebieski
        ACCENT_GREEN = "#2ecc71"       # Zielony
        ACCENT_RED = "#e74c3c"         # Czerwony

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {BG_COLOR};
                color: {TEXT_PRIMARY};
                font-family: 'Segoe UI', 'Helvetica Neue', sans-serif;
                font-size: 11pt;
            }}
            QLabel {{
                background-color: transparent;
                padding-top: 8px;
            }}
            #mainTitle {{
                font-size: 30pt;
                font-weight: 600;
                padding-bottom: 15px;
            }}
            QGroupBox {{
                background-color: {CARD_COLOR};
                border: none;
                border-radius: 12px;
                padding: 20px;
            }}
            QGroupBox::title {{
                color: {TEXT_SECONDARY};
                font-size: 10pt;
                font-weight: bold;
                padding-left: 0px;
                padding-bottom: 5px;
            }}
            #segmentedButtonLeft, #segmentedButtonRight {{
                background-color: transparent;
                border: 1px solid {BORDER_COLOR};
                padding: 8px 30px;
                font-size: 11pt;
                font-weight: 500;
                color: {TEXT_SECONDARY};
            }}
            #segmentedButtonLeft {{
                border-top-left-radius: 8px;
                border-bottom-left-radius: 8px;
            }}
            #segmentedButtonRight {{
                border-top-right-radius: 8px;
                border-bottom-right-radius: 8px;
                margin-left: 3px;
            }}
            #segmentedButtonLeft:checked, #segmentedButtonRight:checked {{
                background-color: {INPUT_COLOR};
                color: {TEXT_PRIMARY};
                border-color: {INPUT_COLOR};
            }}
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {ACCENT_BLUE}, stop:1 #3a7bd5);
                color: {TEXT_PRIMARY};
                border: none;
                border-radius: 10px;
                padding: 14px 28px;
                font-size: 12pt;
                font-weight: 600;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #5ba0f2, stop:1 #4a8bd5);
            }}
            QPushButton:pressed {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #3a7bd5, stop:1 #2e6bc4);
            }}
            #clearButton {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {ACCENT_RED}, stop:1 #c0392b);
            }}
            #clearButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #e55a4a, stop:1 #d63031);
            }}
            #browse_btn {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 {INPUT_COLOR}, stop:1 #25252b);
                padding: 8px 16px;
                font-size: 11pt;
            }}
            QTextEdit, QLineEdit, QComboBox, QSpinBox {{
                background-color: {INPUT_COLOR};
                border: 1px solid {BORDER_COLOR};
                border-radius: 8px;
                padding: 12px;
                color: {TEXT_PRIMARY};
            }}
            QTextEdit:focus, QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
                border: 1px solid {ACCENT_BLUE};
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 25px;
                border-left-width: 1px;
                border-left-color: {BORDER_COLOR};
                border-left-style: solid;
                border-top-right-radius: 8px;
                border-bottom-right-radius: 8px;
            }}
            QStatusBar {{
                font-size: 10pt;
                color: {TEXT_SECONDARY};
            }}
            #versionLabel {{
                color: {TEXT_SECONDARY};
                font-size: 9pt;
                padding-top: 0px;
            }}
        """)

    # --- Metody uproszczone ---
    def populate_algorithms(self):
        for alg in self.algorithm_manager.get_all_algorithms():
            self.algorithm_combo.addItem(alg.name)
    
    def populate_file_algorithms(self):
        for alg in self.algorithm_manager.get_all_algorithms():
            self.file_algorithm_combo.addItem(alg.name)
    
    def on_algorithm_changed(self, name):
        self.current_algorithm = self.algorithm_manager.get_algorithm(name)
        if not self.current_algorithm:
            return

        # najpierw sprawdź, czy algorytm akceptuje klucz liczbowy (spin)
        prefers_numeric = False
        try:
            if self.current_algorithm.validate_key(self.key_spin.value()):
                prefers_numeric = True
        except Exception:
            prefers_numeric = False

        # jeśli nie, spróbuj sprawdzić klucz tekstowy (najpierw aktualne pole, potem przykładowy string)
        if not prefers_numeric:
            try:
                if self.current_algorithm.validate_key(self.key_text.text()):
                    prefers_numeric = False
                elif self.current_algorithm.validate_key("K"):  # próbka tekstowa
                    prefers_numeric = False
                else:
                    # nie rozpoznano jako tekstowy — domyślnie pozostaw numeric (bez zmiany)
                    prefers_numeric = False
            except Exception:
                # w razie błędu w validate_key nie zmieniamy preferencji wcześniej wykrytej
                pass

        # ustawiamy widoczność dla obu widoków (tekst i plik)
        if hasattr(self, 'key_stack'):
            self.key_stack.setCurrentIndex(0 if prefers_numeric else 1)
        if hasattr(self, 'file_key_stack'):
            self.file_key_stack.setCurrentIndex(0 if prefers_numeric else 1)

        # Pokaż/ukryj wybór rozmiaru klucza AES
        is_aes = "AES" in name
        if hasattr(self, 'aes_key_size_label'):
            self.aes_key_size_label.setVisible(is_aes)
            self.aes_key_size_combo.setVisible(is_aes)
        if hasattr(self, 'file_aes_key_size_label'):
            self.file_aes_key_size_label.setVisible(is_aes)
            self.file_aes_key_size_combo.setVisible(is_aes)

        is_rsa = "RSA" in name
        if hasattr(self, 'rsa_group_box'):
            self.rsa_group_box.setVisible(is_rsa)
        
        # Ukryj standardowe pole klucza dla RSA
        if hasattr(self, 'key_stack'):
            self.key_stack.setVisible(not is_rsa)
        if hasattr(self, 'file_key_stack'):
            self.file_key_stack.setVisible(not is_rsa)

        self.statusBar().showMessage(f"Aktywny: {name}")
    
    def generate_rsa_keys(self):
        """Generuje i wyświetla nową parę kluczy RSA."""
        try:
            rsa_alg = self.algorithm_manager.get_algorithm("RSA")
            public_key, private_key = rsa_alg.generate_keys()
            
            self.public_key_text.setPlainText(str(public_key))
            self.private_key_text.setPlainText(str(private_key))
            self.statusBar().showMessage("Wygenerowano nowe klucze RSA")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Generowanie kluczy RSA: {str(e)}")
    
    def encrypt_text(self):
        if not self._validate_text_input(): return
        try:
            if "RSA" in self.current_algorithm.name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    encrypted = self.current_algorithm.encrypt(self.input_text.toPlainText(), key)
                    self.output_text.setPlainText(encrypted.hex())
                    self.statusBar().showMessage("Zaszyfrowano!")
                elif mode == "Podpisz / Weryfikuj":
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    signed = self.current_algorithm.sign(self.input_text.toPlainText().encode('utf-8'), key)
                    self.output_text.setPlainText(signed.hex())
                    self.statusBar().showMessage("Podpisano!")
            else:
                key = self._get_text_key()
                options = {}
                if "AES" in self.current_algorithm.name:
                    key_size_str = self.aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    options['key_size'] = int(key_size_str) // 8
                encrypted = self.current_algorithm.encrypt(self.input_text.toPlainText(), key, **options)
                self.output_text.setPlainText(encrypted)
                self.statusBar().showMessage("Zaszyfrowano.")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Szyfrowanie: {str(e)}")
    
    def decrypt_text(self):
        if not self._validate_text_input(): return
        try:
            if "RSA" in self.current_algorithm.name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    encrypted_data = bytes.fromhex(self.input_text.toPlainText())
                    decrypted = self.current_algorithm.decrypt(encrypted_data, key)
                    self.input_text.clear()
                    self.output_text.setPlainText(decrypted.decode('utf-8', errors='replace'))
                    self.statusBar().showMessage("Deszyfrowano!")
                elif mode == "Podpisz / Weryfikuj":
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    signed_data = bytes.fromhex(self.input_text.toPlainText())
                    data = self.input_text.toPlainText()  # Oryginalne dane do weryfikacji
                    
                    # Dla weryfikacji w GUI potrzebujemy oddzielnie podpisu i danych
                    # Aktualnie mamy tylko podpis w hex. Powinniśmy mieć dane i podpis.
                    # Dla uproszczenia: weryfikujemy podpis samych danych z output
                    if self.output_text.toPlainText():
                        data_to_verify = self.output_text.toPlainText().encode('utf-8')
                    else:
                        QMessageBox.warning(self, "Błąd", "Brak danych do weryfikacji (powinny być w polu wyjściowym)")
                        return
                    
                    is_valid = self.current_algorithm.verify(data_to_verify, signed_data, key)
                    if is_valid:
                        QMessageBox.information(self, "Sukces", "✓ Podpis jest prawidłowy!")
                        self.statusBar().showMessage("Podpis zweryfikowany!")
                    else:
                        QMessageBox.warning(self, "Błąd", "✗ Podpis jest NIEPRAWIDŁOWY!")
                        self.statusBar().showMessage("Błąd: Podpis NIEPRAWIDŁOWY!")
            else:
                key = self._get_text_key()
                options = {}
                if "AES" in self.current_algorithm.name:
                    key_size_str = self.aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    options['key_size'] = int(key_size_str) // 8
                decrypted = self.current_algorithm.decrypt(self.input_text.toPlainText(), key, **options)
                self.input_text.clear()
                self.output_text.setPlainText(decrypted)
                self.statusBar().showMessage("Deszyfrowano!")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Deszyfrowanie: {str(e)}")
    
    def clear_text(self):
        self.input_text.clear()
        self.output_text.clear()
        self.statusBar().showMessage("Wyczyszczono")
    
    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Wybierz plik", "", "Wszystkie pliki (*)")
        if path:
            self.file_path_input.setText(path)
            self.statusBar().showMessage(f"Wybrano: {os.path.basename(path)}")
    
    def encrypt_file(self):
        if not self._validate_file_input(): return
        try:
            alg = self.algorithm_manager.get_algorithm(self.file_algorithm_combo.currentText())
            if "RSA" in alg.name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    with open(self.file_path_input.text(), 'rb') as f:
                        content = f.read()
                    encrypted = alg.encrypt(content, key)
                    with open(self.file_path_input.text() + ".enc", 'wb') as f:
                        f.write(encrypted)
                    QMessageBox.information(self, "Sukces", "Plik zaszyfrowany do .enc")
                    self.statusBar().showMessage("Plik zaszyfrowany!")
                elif mode == "Podpisz / Weryfikuj":
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    with open(self.file_path_input.text(), 'rb') as f:
                        content = f.read()
                    signed = alg.sign(content, key)
                    with open(self.file_path_input.text() + ".sig", 'wb') as f:
                        f.write(signed)
                    QMessageBox.information(self, "Sukces", "Plik podpisany do .sig")
                    self.statusBar().showMessage("Plik podpisany!")
            else:
                with open(self.file_path_input.text(), 'r', encoding='utf-8') as f:
                    content = f.read()
                key = self._get_file_key()
                options = {}
                if "AES" in alg.name:
                    key_size_str = self.file_aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    options['key_size'] = int(key_size_str) // 8
                encrypted = alg.encrypt(content, key, **options)
                with open(self.file_path_input.text(), 'w', encoding='utf-8') as f:
                    f.write(encrypted)
                QMessageBox.information(self, "Sukces", "Plik zaszyfrowany.")
                self.statusBar().showMessage("Plik zaszyfrowany!")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Szyfrowanie pliku: {str(e)}")
    
    def decrypt_file(self):
        if not self._validate_file_input(): return
        try:
            alg = self.algorithm_manager.get_algorithm(self.file_algorithm_combo.currentText())
            if "RSA" in alg.name:
                mode = self.rsa_mode_combo.currentText()
                if mode == "Szyfruj / Deszyfruj":
                    private_key_str = self.private_key_text.toPlainText()
                    if not private_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz prywatny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(private_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    with open(self.file_path_input.text(), 'rb') as f:
                        content = f.read()
                    decrypted = alg.decrypt(content, key)
                    output_path = self.file_path_input.text().replace(".enc", "")
                    with open(output_path, 'wb') as f:
                        f.write(decrypted)
                    QMessageBox.information(self, "Sukces", f"Plik deszyfrowany do {os.path.basename(output_path)}!")
                    self.statusBar().showMessage("Plik deszyfrowany!")
                elif mode == "Podpisz / Weryfikuj":
                    public_key_str = self.public_key_text.toPlainText()
                    if not public_key_str:
                        QMessageBox.warning(self, "Błąd", "Klucz publiczny nie może być pusty!")
                        return
                    try:
                        key = self._parse_rsa_key_safe(public_key_str)
                    except ValueError as e:
                        QMessageBox.warning(self, "Błąd", f"Błąd parsowania klucza: {str(e)}")
                        return
                    
                    # Czytaj plik podpisu
                    sig_path = self.file_path_input.text()
                    with open(sig_path, 'rb') as f:
                        signature = f.read()
                    
                    # Czytaj oryginalny plik danych (bez .sig)
                    data_path = sig_path.replace(".sig", "")
                    if data_path == sig_path:
                        QMessageBox.warning(self, "Błąd", "Plik powinien mieć rozszerzenie .sig!")
                        return
                    
                    with open(data_path, 'rb') as f:
                        data = f.read()
                    
                    # Weryfikuj podpis
                    is_valid = alg.verify(data, signature, key)
                    if is_valid:
                        QMessageBox.information(self, "Sukces", f"✓ Podpis pliku {os.path.basename(data_path)} jest PRAWIDŁOWY!")
                        self.statusBar().showMessage("Podpis zweryfikowany!")
                    else:
                        QMessageBox.critical(self, "Błąd", f"✗ Podpis pliku {os.path.basename(data_path)} jest NIEPRAWIDŁOWY!")
                        self.statusBar().showMessage("Błąd: Podpis NIEPRAWIDŁOWY!")
            else:
                with open(self.file_path_input.text(), 'r', encoding='utf-8') as f:
                    content = f.read()
                key = self._get_file_key()
                options = {}
                if "AES" in alg.name:
                    key_size_str = self.file_aes_key_size_combo.currentText().split(' ')[0].replace('AES-', '')
                    options['key_size'] = int(key_size_str) // 8
                decrypted = alg.decrypt(content, key, **options)
                with open(self.file_path_input.text(), 'w', encoding='utf-8') as f:
                    f.write(decrypted)
                QMessageBox.information(self, "Sukces", "Plik deszyfrowany!")
                self.statusBar().showMessage("Plik deszyfrowany!")
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Deszyfrowanie pliku: {str(e)}")
    
    def _validate_text_input(self):
        if not self.current_algorithm:
            QMessageBox.warning(self, "Błąd", "Wybierz algorytm!")
            return False
        if not self.input_text.toPlainText():
            QMessageBox.warning(self, "Błąd", "Wprowadź tekst!")
            return False
        
        if "RSA" in self.current_algorithm.name:
            mode = self.rsa_mode_combo.currentText()
            if mode == "Szyfruj / Deszyfruj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
            elif mode == "Podpisz / Weryfikuj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
        else:
            key = self._get_text_key()
            try:
                if not self.current_algorithm.validate_key(key):
                    QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                    return False
            except Exception:
                QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                return False
        return True
    
    def _validate_file_input(self):
        alg = self.algorithm_manager.get_algorithm(self.file_algorithm_combo.currentText())
        if not alg:
            QMessageBox.warning(self, "Błąd", "Wybierz algorytm!")
            return False
        if not self.file_path_input.text():
            QMessageBox.warning(self, "Błąd", "Wybierz plik!")
            return False
        
        if "RSA" in alg.name:
            mode = self.rsa_mode_combo.currentText()
            if mode == "Szyfruj / Deszyfruj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
            elif mode == "Podpisz / Weryfikuj":
                if not self.public_key_text.toPlainText() and not self.private_key_text.toPlainText():
                    QMessageBox.warning(self, "Błąd", "Wprowadź klucz publiczny lub prywatny dla RSA!")
                    return False
        else:
            key = self._get_file_key()
            try:
                if not alg.validate_key(key):
                    QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                    return False
            except Exception:
                QMessageBox.warning(self, "Błąd", "Nieprawidłowy klucz!")
                return False
        return True

    # pomocnicze metody do pobierania aktualnego klucza
    def _get_text_key(self):
        if hasattr(self, 'key_stack') and self.key_stack.currentIndex() == 0:
            return self.key_spin.value()
        return self.key_text.text()

    def _get_file_key(self):
        if hasattr(self, 'file_key_stack') and self.file_key_stack.currentIndex() == 0:
            return self.file_key_spin.value()
        return self.file_key_text.text()

    def _parse_rsa_key_safe(self, key_str: str) -> tuple:
        """
        Bezpiecznie parsuje string klucza RSA na krotkę (e, n) lub (d, n).
        
        Zwraca: tuple (e/d, n) lub raises ValueError/SyntaxError
        """
        if not key_str or not key_str.strip():
            raise ValueError("Klucz nie może być pusty")
        
        try:
            # Użyj ast.literal_eval zamiast eval() dla bezpieczeństwa
            parsed = ast.literal_eval(key_str.strip())
            
            if not isinstance(parsed, tuple) or len(parsed) != 2:
                raise ValueError("Klucz RSA musi być krotką (liczba, liczba)")
            
            if not (isinstance(parsed[0], int) and isinstance(parsed[1], int)):
                raise ValueError("Obie części klucza muszą być liczbami całkowitymi")
            
            return parsed
        except (ValueError, SyntaxError) as e:
            raise ValueError(f"Nieprawidłowy format klucza RSA: {str(e)}")
