import shutil

import emoji
import random
import string
import os
import csv
import tkinter as tk
from tkinter import messagebox

devir = 1

valid_values = {8, 10, 12, 16}  # Geçerli değerler kümesi (int)

f = None  # Varsayılan olarak boş
x = None
xx = None

def deger_ata():
    global f , x , xx
    try:
        f = int(entry.get().strip())  # Kullanıcının girdiği değeri int'e çevir
        x = int(entry1.get().strip())  # Kullanıcının girdiği değeri int'e çevir
        xx = int(entry2.get().strip())  # Kullanıcının girdiği değeri int'e çevir

        if f not in valid_values:
            messagebox.showerror("Hata", "Geçersiz değer. Lütfen 8, 10, 12 veya 16 girin.")
        else:
            print(f"Atanan f değeri: {f} (int)")
            root.quit()  # Pencereyi kapatmadan döngüyü sonlandır
    except ValueError:
        messagebox.showerror("Hata", "Lütfen geçerli bir tam sayı girin.")


# Tkinter pencere oluşturma
root = tk.Tk()
root.title("f Değeri Atama")

# Girdi kutusu ve buton ekleme
tk.Label(root, text="Emojilerin Sayı(8,10,12,16) olarak girin").pack(pady=5)
entry = tk.Entry(root)
entry.pack(pady=5)


# Girdi kutusu ve buton ekleme
tk.Label(root, text="Harf sayını girin(2 seçimi 2 büyük 2 küçük ekler)").pack(pady=5)
entry1 = tk.Entry(root)
entry1.pack(pady=5)

# Girdi kutusu ve buton ekleme
tk.Label(root, text="Rakam eklemek istediğiniz sayı").pack(pady=5)
entry2 = tk.Entry(root)
entry2.pack(pady=5)

tk.Button(root, text="Atama Yap", command=deger_ata).pack(pady=5)


# Klasör yolunu belirle
folder_path = 'site'

# Klasördeki tüm dosyaları al
files = [f for f in os.listdir(folder_path) if f.endswith('.txt')]

# Dosyaları sıralayarak son txt dosyasını al
if files:

    latest_file = sorted(files)[-1]  # Son dosyayı al
    latest_file_without_extension = os.path.splitext(latest_file)[0]  # .txt uzantısını kaldır
    print(latest_file_without_extension)
    if "facebook" in latest_file_without_extension or "linkedin" in latest_file_without_extension or "icloud" in latest_file_without_extension or "github" in latest_file_without_extension or "twitter" in latest_file_without_extension or "steam" in latest_file_without_extension or "reddit" in latest_file_without_extension or "netflix" in latest_file_without_extension or "amazon" in latest_file_without_extension or "facebook.com" in latest_file_without_extension or "linkedin.com" in latest_file_without_extension or "icloud.com" in latest_file_without_extension or "github.com" in latest_file_without_extension or "twitter.com" in latest_file_without_extension or "steam.com" in latest_file_without_extension or "reddit.com" in latest_file_without_extension or "netflix.com" in latest_file_without_extension or "amazon.com" in latest_file_without_extension or "spotify" in latest_file_without_extension or "spotify.com" in latest_file_without_extension or "zoom" in latest_file_without_extension or "zoom.us" in latest_file_without_extension or "zoom.com" in latest_file_without_extension or "turnitin" in latest_file_without_extension or "turnitin.com" in latest_file_without_extension or "ebay" in latest_file_without_extension or "ebay.com" in latest_file_without_extension:
        first1 = "Sifre Uretilecek site - "
        second1 = latest_file_without_extension
        tk.Label(root, text=first1+second1).pack(pady=5)
        entry.insert(0, "8")  # Varsayılan olarak 8 atanıyor
        entry1.insert(0, "2")  # Varsayılan olarak 8 atanıyor
        entry2.insert(0, "1")  # Varsayılan olarak 8 atanıyor
    elif "google" in latest_file_without_extension or "outlook" in latest_file_without_extension or "yahoo" in latest_file_without_extension or "twitch" in latest_file_without_extension or "google.com"  in latest_file_without_extension or "yahoo.com" in latest_file_without_extension  or "twitch.com" in latest_file_without_extension or "google.com" in latest_file_without_extension:
        first1 = "Sifre Uretilecek site - "
        second1 = latest_file_without_extension
        tk.Label(root, text=first1+second1).pack(pady=5)
        entry.insert(0, "8")  # Varsayılan olarak 8 atanıyor
        entry1.insert(0, "2")  # Varsayılan olarak 8 atanıyor
        entry2.insert(0, "1")  # Varsayılan olarak 8 atanıyor
    else:
        first1 = "Sifre Uretilecek site - "
        second1 = latest_file_without_extension
        tk.Label(root, text=first1+second1).pack(pady=5)
        entry.insert(0, "0")  # Varsayılan olarak 8 atanıyor
        entry1.insert(0, "0")  # Varsayılan olarak 8 atanıyor
        entry2.insert(0, "0")  # Varsayılan olarak 8 atanıyor

else:
    print("Klasörde .txt dosyası bulunamadı.")



root.mainloop()  # Tkinter döngüsü çalışır, pencere kapanınca devam eder

# Tkinter kapandıktan sonra burada devam eden kodlar çalışır
if f is not None:
    print(f"Son olarak atanan f değeri: {f}")
else:
    print("Hiçbir değer atanmadı!")


# Geçerli olup olmadığını kontrol et
while f not in valid_values:
    print("Geçersiz değer. Lütfen 8, 10, 12 veya 16 girin.")
    f = int(input("Değer gir (8, 10, 12, 16): "))

# Doğru bir değer girildiğinde devam et
print(f"Geçerli değer girildi: {f}")

import time

start_time = time.perf_counter()  # süre ölçüm başlangıcı

emoji_liste = []
while devir <= f:
    devir = devir + 1
    emoji = "ABC"
    emoji_list = list(emoji)

    a, b, c = None, None, None

    # Emojilerin Unicode son iki basamağını al
    for idx, char in enumerate(emoji_list):
        unicode_code_point = ord(char)
        hex_unicode = hex(unicode_code_point)
        last_two_hex_digits = hex_unicode[-2:]

        # A, B, C değişkenlerine sırayla kaydet
        if idx == 0:
            a = last_two_hex_digits
        elif idx == 1:
            b = last_two_hex_digits
        elif idx == 2:
            c = last_two_hex_digits

    # Unicode'un son iki basamağını 16'lık sisteme çevir
    a, b, c = int(a, 16), int(b, 16), int(c, 16)

    # Sonuçları saklamak için bir liste
    results = []

    # 25 farklı hesaplama yöntemi
    for i in range(25):
        if i == 0:
            results.append(a ^ b)  # S1: XOR işlemi
        elif i == 1:
            results.append((a + b) % 256)  # S2: Toplama ve mod
        elif i == 2:
            results.append((b - c) % 256)  # S3: Çıkarma ve mod
        elif i == 3:
            results.append(a ^ c)  # S4: XOR işlemi
        elif i == 4:
            results.append((a * b) % 256)  # S5: Çarpma ve mod
        elif i == 5:
            results.append((results[i - 1] ^ a) % 256)  # S6: Önceki değer XOR a
        elif i == 6:
            results.append((results[i - 1] + b) % 256)  # S7: Önceki değer + b
        elif i == 7:
            results.append((~results[i - 1]) & 0xFF)  # S8: Önceki değerin NOT'u
        elif i == 8:
            results.append((results[i - 1] << 1) & 0xFF)  # S9: 1 sola kaydır
        elif i == 9:
            results.append((results[i - 1] >> 1) & 0xFF)  # S10: 1 sağa kaydır
        elif i == 10:
            results.append((a ^ b ^ c) & 0xFF)  # S11: Üçlü XOR
        elif i == 11:
            results.append((a + c) % 256)  # S12: a ve c toplamı
        elif i == 12:
            results.append((b * c) % 256)  # S13: b ve c çarpımı
        elif i == 13:
            results.append((a | b) & 0xFF)  # S14: OR işlemi
        elif i == 14:
            results.append((b & c) & 0xFF)  # S15: AND işlemi
        elif i == 15:
            results.append((a ^ (b << 1)) & 0xFF)  # S16: b sola kaydırılmış XOR a
        elif i == 16:
            results.append((results[i - 1] - a) % 256)  # S17: Önceki değer - a
        elif i == 17:
            results.append((results[i - 1] * 2) % 256)  # S18: Önceki değer * 2
        elif i == 18:
            results.append((results[i - 1] ^ (c >> 1)) & 0xFF)  # S19: c sağa kaydırılmış XOR
        elif i == 19:
            results.append((a + b + c) % 256)  # S20: a, b ve c toplamı
        elif i == 20:
            results.append((a & ~b) & 0xFF)  # S21: a AND NOT b
        elif i == 21:
            results.append((c | ~a) & 0xFF)  # S22: c OR NOT a
        elif i == 22:
            results.append((b ^ c ^ (a >> 2)) & 0xFF)  # S23: XOR ve sağa kaydırma
        elif i == 23:
            results.append((results[i - 1] + results[i - 2]) % 256)  # S24: Son iki toplamı
        elif i == 24:
            results.append((~(results[i - 1] & c)) & 0xFF)  # S25: NOT (son değer AND c)

    # Her sonucu son karaktere çevir (hex)
    last_char_results = [hex(result & 0xFFFF)[-1].upper().zfill(2) for result in results]

    # Her sonucu 4 bitlik binary string'e çevir
    hex_to_binary_matrix = [bin(int(char, 16))[2:].zfill(4) for char in last_char_results]

    # Yeni 8 bitlik değerleri oluştur
    new_eight_bit_values = []
    hex_values = []

    for value in hex_to_binary_matrix:
        new_value = ""  # Yeni 8 bitlik değeri oluştur
        for bit in value:
            if bit == "1":
                new_value += "0"  # Eğer bit 1 ise sonuna 0 ekle
            else:
                new_value += "1"  # Eğer bit 0 ise sonuna 1 ekle
        new_eight_bit_values.append(value + new_value)  # 8 bitlik değer
        hex_values.append(hex(int(value + new_value, 2))[2:].upper().zfill(2))  # 16'lık sisteme çevir

    # 5x5 Matris Formatında Oluşturma
    hex_matrix = [last_char_results[i:i + 5] for i in range(0, len(last_char_results), 5)]
    binary_matrix = [hex_to_binary_matrix[i:i + 5] for i in range(0, len(hex_to_binary_matrix), 5)]
    new_binary_matrix = [new_eight_bit_values[i:i + 5] for i in range(0, len(new_eight_bit_values), 5)]
    new_hex_matrix = [hex_values[i:i + 5] for i in range(0, len(hex_values), 5)]

    # Matrisleri Yazdırma
    print("\nElde edilen sonuçlar (5x5 matris, 16'lık sistem): 2 ci karakterlerin asagida bit degeri alindi 0 lar kullanilmadi")
    print("Matrix-1")
    for row in hex_matrix:
        print("  ".join(row))

    print("\nElde edilen sonuçlar (5x5 matris, 4 bitlik binary):")
    print("Matrix-2")

    for row in binary_matrix:
        print("  ".join(row))

    print("\nYeni oluşturulan 8 bitlik binary matris:")
    print("Matrix-3")

    for row in new_binary_matrix:
        print("  ".join(row))

    print("\nBu değerlerin 16'lık sistemdeki karşılıkları:")
    print("Matrix-4")
    for row in new_hex_matrix:
        print("  ".join(row))


    # Emoji bilgilerini bulan fonksiyon
    def find_emoji_info(input_emoji):
        emoji_unicode = input_emoji.encode("unicode_escape").decode("ASCII")
        emoji_meaning = emoji.demojize(input_emoji)
        return emoji_unicode, emoji_meaning

    # Rastgele bir emoji üreten fonksiyon
    def generate_random_emoji():
        emoji_ranges = [

            (0x1F300, 0x1FAF8),  # Yüz ifadeleri
            (0x2100, 0x2426),  # Zodyak ve eski semboller
            (0x2460, 0x2B95),

        ]

        unsupported_emoji_ranges = [
            (0x1F7EC, 0x1F7FF), (0x1F54F, 0x1F54F), (0x1F6D6, 0x1F6DF),
            (0x1F6D3, 0x1F6D3), (0x1F6D4, 0x1F6D4), (0x1F6ED, 0x1F6EF),
            (0x1F6FB, 0x1F6FF), (0x1F774, 0x1F77F), (0x1F786, 0x1F786),
            (0x1F788, 0x1F788), (0x1F78A, 0x1F78B), (0x1F78E, 0x1F78F),
            (0x1F790, 0x1F790), (0x1F7C1, 0x1F7C1), (0x1F7C5, 0x1F7C5),
            (0x1F7CB, 0x1F7CB), (0x1F7CF, 0x1F7CF), (0x1F7D1, 0x1F7D1),
            (0x1F7D3, 0x1F7DF), (0x1F7EC, 0x1F7FF), (0x1F80C, 0x1F80F),
            (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F), (0x1F888, 0x1F88F),
            (0x1F8AE, 0x1F90C), (0x1F972, 0x1F972), (0x1F977, 0x1F979),
            (0x1F9A3, 0x1F9AD), (0x1F9CB, 0x1F9CC), (0x1FA74, 0x1FA77),
            (0x1FA7B, 0x1FA7F), (0x1FA83, 0x1FA8F), (0x1FA96, 0x1FAFF),
            (0x2B74, 0x2B75), (0x1FA14, 0x1FA14), (0x1FA28, 0x1FA28),
            (0x1FA42, 0x1FA42), (0x2342, 0x2342), (0x1FA00, 0x1FA6F),
            (0x1F946, 0x1F946), (0x218C, 0x218F)
        ]

        while True:
            chosen_range = random.choice(emoji_ranges)
            emoji_code = chr(random.randint(chosen_range[0], chosen_range[1]))

            emoji_code_unicode = ord(emoji_code)
            if not any(start <= emoji_code_unicode <= end for start, end in unsupported_emoji_ranges):
                return emoji_code



    # Rastgele emoji listesi
    random_emojis = [generate_random_emoji() for _ in range(25)]

    # Matris oluşturma fonksiyonu
    def create_emoji_matrix(emojis):
        return [emojis[i:i + 5] for i in range(0, len(emojis), 5)]

    # İlk emoji matrisi
    emoji_matrix = create_emoji_matrix(random_emojis)

    # Son iki hexadecimal değere göre matris oluşturma fonksiyonu
    def create_hex_matrix(emoji_matrix):
        hex_matrix = []
        for row in emoji_matrix:
            hex_row = []
            for emoji in row:
                unicode_value = emoji.encode("unicode_escape").decode("ASCII")
                hex_value = unicode_value.replace("\\u", "").upper()[-2:]
                hex_row.append(hex_value)
            hex_matrix.append(hex_row)
        return hex_matrix

    # İlk matrise göre ikinci hex matrisi
    hex_matrix = create_hex_matrix(emoji_matrix)

    # İlk emoji matrisini yazdır
    print("\n5x5 Emoji Matrisi (İlk Matris):")
    print("Matrix-5")

    for row in emoji_matrix:
        print(" ".join(row))

    # Hex matrisini yazdır
    print("\n5x5 Hex Matrisi (Son 2 Hex Karakteri):")
    print("Matrix-6")

    for row in hex_matrix:
        print(" ".join(row))


    # Hexadecimal değerlerden binary değerler üretme fonksiyonu
    def create_binary_matrix(hex_matrix):
        binary_matrix = []
        for row in hex_matrix:
            binary_row = []
            for hex_value in row:
                # Hexadecimal değeri 4 bitlik binary'ye çevir
                binary_value = bin(int(hex_value, 16))[2:].zfill(8)
                binary_row.append(binary_value)
            binary_matrix.append(binary_row)
        return binary_matrix

    # Binary matrisi oluştur
    binary_matrix = create_binary_matrix(hex_matrix)

    # Binary matrisi yazdır
    print("\n5x5 Binary Matrisi:")
    print("Matrix-7")
    for row in binary_matrix:
        print(" ".join(row))

    # XOR işlemi yaparak yeni matrisi oluşturma fonksiyonu
    def xor_matrices(matrix1, matrix2):
        xor_matrix = []
        for row1, row2 in zip(matrix1, matrix2):
            xor_row = []
            for bin1, bin2 in zip(row1, row2):
                # XOR işlemini yap ve sonucu 8 bitlik formata getir
                xor_result = bin(int(bin1, 2) ^ int(bin2, 2))[2:].zfill(8)
                xor_row.append(xor_result)
            xor_matrix.append(xor_row)
        return xor_matrix

    # Matrix-8'i oluştur
    matrix_8 = xor_matrices(new_binary_matrix, binary_matrix)

    # Matrix-8'i yazdır
    print("\n5x5 XOR Sonuç Matrisi:")
    print("Matrix-8")
    for row in matrix_8:
        print(" ".join(row))

    # Binary değerleri hex'e dönüştürme
    matrix_9 = []

    for row in matrix_8:
        hex_row = [hex(int(binary_value, 2))[2:].upper().zfill(2) for binary_value in row]
        matrix_9.append(hex_row)

    # Matrix-9'u yazdırma
    print("\n(Hexadecimal):")
    print("matrix_9")
    for row in matrix_9:
        print("  ".join(row))

    # Örnek bir AES S-Box tanımlaması (16x16 boyutunda tablo)
    print("\nilk deger\/, ikinci deger >")
    AES_S_BOX = [
        [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
        [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
        [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
        [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
        [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
        [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
        [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
        [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
        [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
        [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
        [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
        [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
        [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
        [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
        [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
        [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
    ]

    # Matrix-9'a S-Box uygulama fonksiyonu
    def apply_sbox(matrix, sbox):
        sbox_matrix = []
        for row in matrix:
            sbox_row = []
            for hex_value in row:
                value = int(hex_value, 16)  # Hexadecimal değerini integer'a çevir
                x = value >> 4  # İlk 4 bit (satır)
                y = value & 0x0F  # Son 4 bit (sütun)
                sbox_row.append(hex(sbox[x][y])[2:].upper().zfill(2))  # S-Box'tan al ve hex'e dönüştür
            sbox_matrix.append(sbox_row)
        return sbox_matrix


    # S-Box uygulanan yeni matris
    matrix_sbox = apply_sbox(matrix_9, AES_S_BOX)

    # S-Box sonucu yazdırma
    print("\nUygulanan Matris:")
    print("Matrix-10")
    for row in matrix_sbox:
        print("  ".join(map(str, row)))

    print("----------------------------")


    # Matrix üzerinde işlem yapma (Örnek)

    # Tüm değerleri tek bir listeye ekleyin
    values = [value for row in matrix_sbox for value in row]

    # Her değeri eşit frekansta seçmek
    frequencies = [1] * len(values)  # Her değerin seçilme frekansı eşit

    # random.choices() ile eşit frekansla seçim yapma
    selected_value = random.choices(values, frequencies)[0]

    # Eğer seçilen değer bir string ise, integer'a çevir (hexadecimal string ise)
    if isinstance(selected_value, str):
        selected_value = int(selected_value, 16)

    # Sonuç
    print(f"Seçilen Değer: {selected_value:02X}")


    print("---------------------")


    createlastbayt = f"{selected_value:02X}"
    # Uygun emoji aralıkları
    emoji_ranges = [
        (0x1F300, 0x1FAF8),  # Yüz ifadeleri
        (0x2100, 0x2426),  # Zodyak ve eski semboller
        (0x2460, 0x2B95),

    ]

    # Desteklenmeyen emoji aralıkları
    unsupported_emoji_ranges = [
        (0x1F7EC, 0x1F7FF), (0x1F54F, 0x1F54F), (0x1F6D6, 0x1F6DF),
        (0x1F6D3, 0x1F6D3), (0x1F6D4, 0x1F6D4), (0x1F6ED, 0x1F6EF),
        (0x1F6FB, 0x1F6FF), (0x1F774, 0x1F77F), (0x1F786, 0x1F786),
        (0x1F788, 0x1F788), (0x1F78A, 0x1F78B), (0x1F78E, 0x1F78F),
        (0x1F790, 0x1F790), (0x1F7C1, 0x1F7C1), (0x1F7C5, 0x1F7C5),
        (0x1F7CB, 0x1F7CB), (0x1F7CF, 0x1F7CF), (0x1F7D1, 0x1F7D1),
        (0x1F7D3, 0x1F7DF), (0x1F7EC, 0x1F7FF), (0x1F80C, 0x1F80F),
        (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F), (0x1F888, 0x1F88F),
        (0x1F8AE, 0x1F90C), (0x1F972, 0x1F972), (0x1F977, 0x1F979),
        (0x1F9A3, 0x1F9AD), (0x1F9CB, 0x1F9CC), (0x1FA74, 0x1FA77),
        (0x1FA7B, 0x1FA7F), (0x1FA83, 0x1FA8F), (0x1FA96, 0x1FAFF),
        (0x2B74, 0x2B75), (0x1FA14, 0x1FA14), (0x1FA28, 0x1FA28),
        (0x1FA42, 0x1FA42), (0x2342, 0x2342), (0x1FA00, 0x1FA6F),
        (0x1F946, 0x1F946), (0x218C, 0x218F)
    ]

    # Değerlerin emoji aralıklarında olup olmadığını kontrol eden fonksiyon
    def is_emoji_supported(value):
        # Desteklenmeyen emoji aralıkları kontrol edilmez
        for start, end in unsupported_emoji_ranges:
            if start <= value <= end:
                return False  # Desteklenmeyen aralıkta ise False döndür

        # Desteklenen emoji aralıkları kontrol edilir
        for start, end in emoji_ranges:
            if start <= value <= end:
                return True
        return False

    emoji_list = []

    # d değeri 1'den F'ye kadar olan hexadecimal değerleri dene
    for d in range(1, 16):
        d_hex = hex(d)[2:].upper()
        b = random.randint(0, 1)
        print(b,d_hex)
        # 'c' ve 'createlastbayt' ile birlikte yazdırma
        if b == 0:
            c = "0001F"
            combined_value = int(c + d_hex + createlastbayt, 16)
            if is_emoji_supported(combined_value):
                print(f"Uygun Emoji (b=0): {chr(combined_value)}")
                emoji_list.append(chr(combined_value))  # Uygun emojiyi listeye ekle



        if b == 1:
            c = "2"
            combined_value = int(c + d_hex + createlastbayt, 16)
            if is_emoji_supported(combined_value):
                print(f"Uygun Emoji (b=1): {chr(combined_value)}")
                emoji_list.append(chr(combined_value))  # Uygun emojiyi listeye ekle



    # Sonuçları yazdır
    print("Uygun Emojiler:")
    for emoji in emoji_list:
        print(emoji)

    selemo=random.choice(emoji_list)
    print(selemo)
    emoji_liste.append(selemo)
    emoji_lists = ("", *emoji_liste)
    print(emoji_lists)


def extract_file_names_to_refer():
    folder_name = "site"
    refer_list = []  # Refer içeriğini tutacak liste

    # "site" klasörünün varlığını kontrol et
    if not os.path.exists(folder_name):
        print(f"'{folder_name}' klasörü bulunamadı!")
        return

    # Klasördeki dosyaları listele
    txt_files = [file for file in os.listdir(folder_name) if file.endswith(".txt")]

    if txt_files:
        print(f"'{folder_name}' klasöründeki .txt dosyaları:")
        for file in txt_files:
            # Dosya adının nokta öncesindeki kısmını al
            file_name_without_extension = os.path.splitext(file)[0]
            refer_list.append(file_name_without_extension)  # Listeye ekle
            print(f"- {file} (Refer: {file_name_without_extension})")
    else:
        print(f"'{folder_name}' klasöründe hiçbir .txt dosyası bulunamadı.")

    # Refer listesini döndür veya işlem yap
    return refer_list

# Fonksiyonu çağır
refer = extract_file_names_to_refer()
print(f"Refer listesi: {refer}")
refer_list_site = 1

###davam burdan
if "facebook" in refer or "linkedin" in refer or "icloud" in refer or "github" in refer or "twitter" in refer or "steam" in refer or "reddit" in refer or "netflix" in refer or "amazon" in refer or "facebook.com" in refer or "linkedin.com" in refer or "icloud.com" in refer or "github.com" in refer or "twitter.com" in refer or "steam.com" in refer or "reddit.com" in refer or "netflix.com" in refer or "amazon.com" in refer or "spotify" in refer or "spotify.com" in refer or "zoom" in refer or "zoom.us" in refer or "zoom.com" in refer or "turnitin" in refer or "turnitin.com" in refer or "ebay" in refer or "ebay.com" in refer:
    refer_list_site = 0
    harf = "y"
    if harf == "y":
        i = 1
        while i <= x:
            i = i + 1
            kucuk_harf = random.choice(string.ascii_lowercase)  # Küçük harflerden biri
            buyuk_harf = random.choice(string.ascii_uppercase)  # Büyük harflerden biri

            # Rastgele bir konum seç ve ekle
            index_kucuk = random.randint(0, len(emoji_liste))  # Küçük harf için rastgele bir indeks
            emoji_liste.insert(index_kucuk, kucuk_harf)  # Küçük harfi listeye ekle

            index_buyuk = random.randint(0, len(emoji_liste))  # Büyük harf için rastgele bir indeks
            emoji_liste.insert(index_buyuk, buyuk_harf)  # Büyük harfi listeye ekle

            # Güncel listeyi yazdır
            print("Güncellenmiş liste: ", *emoji_liste, sep='')
            emoji_lists = ("", *emoji_liste)

        else:
            print("Liste değişmedi.")
            emoji_lists = ("", *emoji_liste)


    rakam_ekle = "y"

    if rakam_ekle.lower() == 'y':  # Kullanıcı 'y' derse
        i = 1
        while i <= xx:
            i = i + 1
            # Rastgele bir rakam oluştur
            rastgele_rakam = random.choice(string.digits)  # '0' ile '9' arasından rastgele bir rakam seç

            # Rastgele bir konum seç ve ekle
            index_rakam = random.randint(0, len(emoji_liste))  # Rakam için rastgele bir indeks
            emoji_liste.insert(index_rakam, rastgele_rakam)  # Rakamı listeye ekle

            # Güncel listeyi yazdır
            print("Güncellenmiş liste: ", *emoji_liste, sep='')
            emoji_lists = ("", *emoji_liste)

        else:
            print("Liste değişmedi.")
            emoji_lists = ("", *emoji_liste)

    # noinspection PyUnboundLocalVariable
    ascii = "n"
    if ascii == "y":

        # rashad.csv dosyasını oku ve emojilere karşılık gelen işaretleri bir sözlükte sakla
        emoji_to_sign = {}
        with open('supported_emojis_with_symbols.csv', 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                emoji, sign = row
                emoji_to_sign[emoji] = sign

        # Her emoji için eşleşen işareti ya da "is gecerek" ifadesini yazdır
        output = []
        for emoji in emoji_lists:
            if emoji in emoji_to_sign:
                output.append(f"{emoji_to_sign[emoji]}")
            else:
                output.append(f"{emoji}")

        # Sonuçları yan yana yazdır
        print("Sonuç2:", ''.join(output))
        emoji_lists = random.shuffle(output)
        emoji_lists = ''.join(output)
        print(emoji_lists)


    else:
        pass

if "google" in refer or "outlook" in refer or "yahoo" in refer or "twitch" in refer or "google.com"  in refer or "yahoo.com" in refer  or "twitch.com" in refer or "google.com" in refer:
    refer_list_site = 0
    harf1 = "y"
    if harf1 == "y":
        i = 1
        while i <= x:
            i = i + 1
            kucuk_harf = random.choice(string.ascii_lowercase)  # Küçük harflerden biri
            buyuk_harf = random.choice(string.ascii_uppercase)  # Büyük harflerden biri

            # Rastgele bir konum seç ve ekle
            index_kucuk = random.randint(0, len(emoji_liste))  # Küçük harf için rastgele bir indeks
            emoji_liste.insert(index_kucuk, kucuk_harf)  # Küçük harfi listeye ekle

            index_buyuk = random.randint(0, len(emoji_liste))  # Büyük harf için rastgele bir indeks
            emoji_liste.insert(index_buyuk, buyuk_harf)  # Büyük harfi listeye ekle

            # Güncel listeyi yazdır
            print("Güncellenmiş liste: ", *emoji_liste, sep='')
            emoji_lists = ("", *emoji_liste)

        else:
            print("Liste değişmedi.")
            emoji_lists = ("", *emoji_liste)


    rakam_ekle1 = "y"
    if rakam_ekle1 == 'y':  # Kullanıcı 'y' derse
        i = 1
        while i <= xx:
            i = i + 1
            # Rastgele bir rakam oluştur
            rastgele_rakam = random.choice(string.digits)  # '0' ile '9' arasından rastgele bir rakam seç

            # Rastgele bir konum seç ve ekle
            index_rakam = random.randint(0, len(emoji_liste))  # Rakam için rastgele bir indeks
            emoji_liste.insert(index_rakam, rastgele_rakam)  # Rakamı listeye ekle

            # Güncel listeyi yazdır
            print("Güncellenmiş liste: ", *emoji_liste, sep='')
            emoji_lists = ("", *emoji_liste)

        else:
            print("Liste değişmedi.")
            emoji_lists = ("", *emoji_liste)


        # Emoji listesi

        # print("Normal liste: ", *emoji_liste, sep='')

    ascii1 = "y"
    if ascii1 == "y":

        # supported_emojis_with_symbols.csv dosyasını oku ve emojilere karşılık gelen işaretleri bir sözlükte sakla
        emoji_to_sign = {}
        with open('supported_emojis_with_symbols.csv', 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                emoji, sign = row
                emoji_to_sign[emoji] = sign

        # Her emoji için eşleşen işareti ya da "is gecerek" ifadesini yazdır
        output = []
        for emoji in emoji_lists:
            if emoji in emoji_to_sign:
                output.append(f"{emoji_to_sign[emoji]}")
            else:
                output.append(f"{emoji}")

        # Sonuçları yan yana yazdır
        print("Sonuç:", ''.join(output))
        emoji_lists = random.shuffle(output)
        emoji_lists = ''.join(output)
        print(emoji_lists)
    else:
        pass

if refer_list_site == 1:
    print(refer)
    if x != 0:
        i = 1
        while i <= x:
            i = i + 1
            kucuk_harf = random.choice(string.ascii_lowercase)  # Küçük harflerden biri
            buyuk_harf = random.choice(string.ascii_uppercase)  # Büyük harflerden biri

            # Rastgele bir konum seç ve ekle
            index_kucuk = random.randint(0, len(emoji_liste))  # Küçük harf için rastgele bir indeks
            emoji_liste.insert(index_kucuk, kucuk_harf)  # Küçük harfi listeye ekle

            index_buyuk = random.randint(0, len(emoji_liste))  # Büyük harf için rastgele bir indeks
            emoji_liste.insert(index_buyuk, buyuk_harf)  # Büyük harfi listeye ekle

            # Güncel listeyi yazdır
            print("Güncellenmiş liste: ", *emoji_liste, sep='')
            emoji_lists = ("", *emoji_liste)

        else:
            print("Liste değişmedi.")
            emoji_lists = ("", *emoji_liste)


    if xx != 0:  # Kullanıcı 'y' derse
        i = 1
        while i <= xx:
            i = i + 1
            # Rastgele bir rakam oluştur
            rastgele_rakam = random.choice(string.digits)  # '0' ile '9' arasından rastgele bir rakam seç

            # Rastgele bir konum seç ve ekle
            index_rakam = random.randint(0, len(emoji_liste))  # Rakam için rastgele bir indeks
            emoji_liste.insert(index_rakam, rastgele_rakam)  # Rakamı listeye ekle

            # Güncel listeyi yazdır
            print("Güncellenmiş liste: ", *emoji_liste, sep='')
            emoji_lists = ("", *emoji_liste)

        else:
            print("Liste değişmedi.")
            emoji_lists = ("", *emoji_liste)


        # Emoji listesi

        # print("Normal liste: ", *emoji_liste, sep='')

    ascii3 = "y"
    if ascii3 == "y":

        # rashad.csv dosyasını oku ve emojilere karşılık gelen işaretleri bir sözlükte sakla
        emoji_to_sign = {}
        with open('supported_emojis_with_symbols.csv', 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                emoji, sign = row
                emoji_to_sign[emoji] = sign

        # Her emoji için eşleşen işareti ya da "is gecerek" ifadesini yazdır
        output = []
        for emoji in emoji_lists:
            if emoji in emoji_to_sign:
                output.append(f"{emoji_to_sign[emoji]}")
            else:
                output.append(f"{emoji}")

        # Sonuçları yan yana yazdır
        print("Sonuç1:", ''.join(output))
        emoji_lists = random.shuffle(output)
        emoji_lists = ''.join(output)
        print(emoji_lists)
    else:
        pass


# Silmek istediğimiz klasörün yolu
site_klasoru = "site"

end_time = time.perf_counter()  # süre ölçüm bitişi
elapsed_time = end_time - start_time

print(f"Şifre üretimi {elapsed_time:.4f} saniye sürdü.")

#Klasörün var olup olmadığını kontrol et
if os.path.exists(site_klasoru):
    shutil.rmtree(site_klasoru)  # Klasör ve içindekiler silinir
    print(f"{site_klasoru} ve içindekiler silindi.")
    root.destroy()
else:
    print(f"{site_klasoru} bulunamadı.")

