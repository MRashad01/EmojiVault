import shutil
import emoji
import random
import string
import os
import csv
import tkinter as tk
from tkinter import messagebox

transfer = 1

valid_values = {8, 10, 12, 16}  

f = None
x = None
xx = None

def assign_value():
    global f , x , xx
    try:
        f = int(entry.get().strip())    
        x = int(entry1.get().strip())    
        xx = int(entry2.get().strip())    

        if f not in valid_values:
            messagebox.showerror("Error", "Invalid value. Please enter 8, 10, 12, or 16.")
        else:
            print(f"Assigned f value: {f} (int)")
            root.quit()
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid integer.")



root = tk.Tk()
root.title("Assigning Value f")


tk.Label(root, text="Enter emojis as Number(8,10,12,16)").pack(pady=5)
entry = tk.Entry(root)
entry.pack(pady=5)



tk.Label(root, text="Enter the number of letters (choosing 2 adds 2 uppercase and 2 lowercase letters)").pack(pady=5)
entry1 = tk.Entry(root)
entry1.pack(pady=5)


tk.Label(root, text="The number you want to add digits to").pack(pady=5)
entry2 = tk.Entry(root)
entry2.pack(pady=5)

tk.Button(root, text="Make an Appointment", command=assign_value).pack(pady=5)



folder_path = 'site'


files = [f for f in os.listdir(folder_path) if f.endswith('.txt')]


if files:

    latest_file = sorted(files)[-1]
    latest_file_without_extension = os.path.splitext(latest_file)[0]
    print(latest_file_without_extension)
    if "facebook" in latest_file_without_extension or "linkedin" in latest_file_without_extension or "icloud" in latest_file_without_extension or "github" in latest_file_without_extension or "twitter" in latest_file_without_extension or "steam" in latest_file_without_extension or "reddit" in latest_file_without_extension or "netflix" in latest_file_without_extension or "amazon" in latest_file_without_extension or "facebook.com" in latest_file_without_extension or "linkedin.com" in latest_file_without_extension or "icloud.com" in latest_file_without_extension or "github.com" in latest_file_without_extension or "twitter.com" in latest_file_without_extension or "steam.com" in latest_file_without_extension or "reddit.com" in latest_file_without_extension or "netflix.com" in latest_file_without_extension or "amazon.com" in latest_file_without_extension or "spotify" in latest_file_without_extension or "spotify.com" in latest_file_without_extension or "zoom" in latest_file_without_extension or "zoom.us" in latest_file_without_extension or "zoom.com" in latest_file_without_extension or "turnitin" in latest_file_without_extension or "turnitin.com" in latest_file_without_extension or "ebay" in latest_file_without_extension or "ebay.com" in latest_file_without_extension:
        first1 = "Site to Generate Password- "
        second1 = latest_file_without_extension
        tk.Label(root, text=first1+second1).pack(pady=5)
        entry.insert(0, "8")   
        entry1.insert(0, "2")   
        entry2.insert(0, "1")   
    elif "google" in latest_file_without_extension or "outlook" in latest_file_without_extension or "yahoo" in latest_file_without_extension or "twitch" in latest_file_without_extension or "google.com"  in latest_file_without_extension or "yahoo.com" in latest_file_without_extension  or "twitch.com" in latest_file_without_extension or "google.com" in latest_file_without_extension:
        first1 = "Site to Generate Password- "
        second1 = latest_file_without_extension
        tk.Label(root, text=first1+second1).pack(pady=5)
        entry.insert(0, "8")   
        entry1.insert(0, "2")   
        entry2.insert(0, "1")   
    else:
        first1 = "Site to Generate Password"
        second1 = latest_file_without_extension
        tk.Label(root, text=first1+second1).pack(pady=5)
        entry.insert(0, "0")   
        entry1.insert(0, "0")   
        entry2.insert(0, "0")   

else:
    print("No .txt file found in folder.")



root.mainloop()  


if f is not None:
    print(f"The final assigned f value is: {f}")
else:
    print("No value assigned!")



while f not in valid_values:
    print("Invalid value. Please enter 8, 10, 12, or 16.")
    f = int(input("Enter value (8, 10, 12, 16): "))


print(f"Valid value entered: {f}")

import time

start_time = time.perf_counter() 

emoji_list11 = []
while transfer <= f:
    transfer = transfer + 1
    emoji = "ABC"
    emoji_list = list(emoji)

    a, b, c = None, None, None


    for idx, char in enumerate(emoji_list):
        unicode_code_point = ord(char)
        hex_unicode = hex(unicode_code_point)
        last_two_hex_digits = hex_unicode[-2:]


        if idx == 0:
            a = last_two_hex_digits
        elif idx == 1:
            b = last_two_hex_digits
        elif idx == 2:
            c = last_two_hex_digits


    a, b, c = int(a, 16), int(b, 16), int(c, 16)


    results = []


    for i in range(25):
        if i == 0:
            results.append(a ^ b)
        elif i == 1:
            results.append((a + b) % 256)
        elif i == 2:
            results.append((b - c) % 256)
        elif i == 3:
            results.append(a ^ c)
        elif i == 4:
            results.append((a * b) % 256)
        elif i == 5:
            results.append((results[i - 1] ^ a) % 256)
        elif i == 6:
            results.append((results[i - 1] + b) % 256)
        elif i == 7:
            results.append((~results[i - 1]) & 0xFF)
        elif i == 8:
            results.append((results[i - 1] << 1) & 0xFF)
        elif i == 9:
            results.append((results[i - 1] >> 1) & 0xFF)
        elif i == 10:
            results.append((a ^ b ^ c) & 0xFF)
        elif i == 11:
            results.append((a + c) % 256)
        elif i == 12:
            results.append((b * c) % 256)
        elif i == 13:
            results.append((a | b) & 0xFF)
        elif i == 14:
            results.append((b & c) & 0xFF)
        elif i == 15:
            results.append((a ^ (b << 1)) & 0xFF)
        elif i == 16:
            results.append((results[i - 1] - a) % 256)
        elif i == 17:
            results.append((results[i - 1] * 2) % 256)
        elif i == 18:
            results.append((results[i - 1] ^ (c >> 1)) & 0xFF)
        elif i == 19:
            results.append((a + b + c) % 256)
        elif i == 20:
            results.append((a & ~b) & 0xFF)
        elif i == 21:
            results.append((c | ~a) & 0xFF)
        elif i == 22:
            results.append((b ^ c ^ (a >> 2)) & 0xFF)
        elif i == 23:
            results.append((results[i - 1] + results[i - 2]) % 256)
        elif i == 24:
            results.append((~(results[i - 1] & c)) & 0xFF)


    last_char_results = [hex(result & 0xFFFF)[-1].upper().zfill(2) for result in results]


    hex_to_binary_matrix = [bin(int(char, 16))[2:].zfill(4) for char in last_char_results]


    new_eight_bit_values = []
    hex_values = []

    for value in hex_to_binary_matrix:
        new_value = ""
        for bit in value:
            if bit == "1":
                new_value += "0"
            else:
                new_value += "1"
        new_eight_bit_values.append(value + new_value)
        hex_values.append(hex(int(value + new_value, 2))[2:].upper().zfill(2))


    hex_matrix = [last_char_results[i:i + 5] for i in range(0, len(last_char_results), 5)]
    binary_matrix = [hex_to_binary_matrix[i:i + 5] for i in range(0, len(hex_to_binary_matrix), 5)]
    new_binary_matrix = [new_eight_bit_values[i:i + 5] for i in range(0, len(new_eight_bit_values), 5)]
    new_hex_matrix = [hex_values[i:i + 5] for i in range(0, len(hex_values), 5)]


    print("\nObtained results (5x5 matrix, hexadecimal system): The bit values of the second characters were taken below, 0s were not used.")
    print("Matrix-1")
    for row in hex_matrix:
        print("  ".join(row))

    print("\nObtained results (5x5 matrix, 4-bit binary):")
    print("Matrix-2")

    for row in binary_matrix:
        print("  ".join(row))

    print("\nNewly created 8-bit binary matrix:")
    print("Matrix-3")

    for row in new_binary_matrix:
        print("  ".join(row))

    print("\nThe equivalents of these values in the hexadecimal system are:")
    print("Matrix-4")
    for row in new_hex_matrix:
        print("  ".join(row))



    def find_emoji_info(input_emoji):
        emoji_unicode = input_emoji.encode("unicode_escape").decode("ASCII")
        emoji_meaning = emoji.demojize(input_emoji)
        return emoji_unicode, emoji_meaning


    def generate_random_emoji():
        emoji_ranges = [

            (0x1F300, 0x1FAF8),
            (0x2100, 0x2426),
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




    random_emojis = [generate_random_emoji() for _ in range(25)]


    def create_emoji_matrix(emojis):
        return [emojis[i:i + 5] for i in range(0, len(emojis), 5)]


    emoji_matrix = create_emoji_matrix(random_emojis)


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


    hex_matrix = create_hex_matrix(emoji_matrix)


    print("\n5x5 Emoji Matrix (Initial Matrix):")
    print("Matrix-5")

    for row in emoji_matrix:
        print(" ".join(row))


    print("\n5x5 Hex Matrix (Last 2 Hex Characters):")
    print("Matrix-6")

    for row in hex_matrix:
        print(" ".join(row))



    def create_binary_matrix(hex_matrix):
        binary_matrix = []
        for row in hex_matrix:
            binary_row = []
            for hex_value in row:

                binary_value = bin(int(hex_value, 16))[2:].zfill(8)
                binary_row.append(binary_value)
            binary_matrix.append(binary_row)
        return binary_matrix


    binary_matrix = create_binary_matrix(hex_matrix)


    print("\n5x5 Binary Matrix:")
    print("Matrix-7")
    for row in binary_matrix:
        print(" ".join(row))


    def xor_matrices(matrix1, matrix2):
        xor_matrix = []
        for row1, row2 in zip(matrix1, matrix2):
            xor_row = []
            for bin1, bin2 in zip(row1, row2):

                xor_result = bin(int(bin1, 2) ^ int(bin2, 2))[2:].zfill(8)
                xor_row.append(xor_result)
            xor_matrix.append(xor_row)
        return xor_matrix


    matrix_8 = xor_matrices(new_binary_matrix, binary_matrix)


    print("\n5x5 XOR Result Matrix:")
    print("Matrix-8")
    for row in matrix_8:
        print(" ".join(row))


    matrix_9 = []

    for row in matrix_8:
        hex_row = [hex(int(binary_value, 2))[2:].upper().zfill(2) for binary_value in row]
        matrix_9.append(hex_row)


    print("\n(Hexadecimal):")
    print("matrix_9")
    for row in matrix_9:
        print("  ".join(row))


    print("\nFirst value\/, Second value >")
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


    def apply_sbox(matrix, sbox):
        sbox_matrix = []
        for row in matrix:
            sbox_row = []
            for hex_value in row:
                value = int(hex_value, 16)
                x = value >> 4
                y = value & 0x0F
                sbox_row.append(hex(sbox[x][y])[2:].upper().zfill(2))
            sbox_matrix.append(sbox_row)
        return sbox_matrix



    matrix_sbox = apply_sbox(matrix_9, AES_S_BOX)


    print("\nApplication Matrix:")
    print("Matrix-10")
    for row in matrix_sbox:
        print("  ".join(map(str, row)))

    print("----------------------------")





    values = [value for row in matrix_sbox for value in row]


    frequencies = [1] * len(values)


    selected_value = random.choices(values, frequencies)[0]


    if isinstance(selected_value, str):
        selected_value = int(selected_value, 16)


    print(f"Selected Value: {selected_value:02X}")


    print("---------------------")


    createlastbayt = f"{selected_value:02X}"

    emoji_ranges = [
        (0x1F300, 0x1FAF8),
        (0x2100, 0x2426),
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


    def is_emoji_supported(value):

        for start, end in unsupported_emoji_ranges:
            if start <= value <= end:
                return False


        for start, end in emoji_ranges:
            if start <= value <= end:
                return True
        return False

    emoji_list = []


    for d in range(1, 16):
        d_hex = hex(d)[2:].upper()
        b = random.randint(0, 1)
        print(b,d_hex)

        if b == 0:
            c = "0001F"
            combined_value = int(c + d_hex + createlastbayt, 16)
            if is_emoji_supported(combined_value):
                print(f"Suitable Emoji (b=0): {chr(combined_value)}")
                emoji_list.append(chr(combined_value))



        if b == 1:
            c = "2"
            combined_value = int(c + d_hex + createlastbayt, 16)
            if is_emoji_supported(combined_value):
                print(f"Suitable Emoji(b=1): {chr(combined_value)}")
                emoji_list.append(chr(combined_value))




    print("Suitable Emoji:")
    for emoji in emoji_list:
        print(emoji)

    selemo=random.choice(emoji_list)
    print(selemo)
    emoji_list11.append(selemo)
    emoji_lists = ("", *emoji_list11)
    print(emoji_lists)


def extract_file_names_to_refer():
    folder_name = "site"
    refer_list = []


    if not os.path.exists(folder_name):
        print(f"'{folder_name}' folder not found!")
        return


    txt_files = [file for file in os.listdir(folder_name) if file.endswith(".txt")]

    if txt_files:
        print(f"'{folder_name}' .txt files in the folder:")
        for file in txt_files:

            file_name_without_extension = os.path.splitext(file)[0]
            refer_list.append(file_name_without_extension)
            print(f"- {file} (Refer: {file_name_without_extension})")
    else:
        print(f"'{folder_name}' No .txt files were found in the folder.")


    return refer_list


refer = extract_file_names_to_refer()
print(f"Refer List: {refer}")
refer_list_site = 1


if "facebook" in refer or "linkedin" in refer or "icloud" in refer or "github" in refer or "twitter" in refer or "steam" in refer or "reddit" in refer or "netflix" in refer or "amazon" in refer or "facebook.com" in refer or "linkedin.com" in refer or "icloud.com" in refer or "github.com" in refer or "twitter.com" in refer or "steam.com" in refer or "reddit.com" in refer or "netflix.com" in refer or "amazon.com" in refer or "spotify" in refer or "spotify.com" in refer or "zoom" in refer or "zoom.us" in refer or "zoom.com" in refer or "turnitin" in refer or "turnitin.com" in refer or "ebay" in refer or "ebay.com" in refer:
    refer_list_site = 0
    letter = "y"
    if letter == "y":
        i = 1
        while i <= x:
            i = i + 1
            lowercase_letter = random.choice(string.ascii_lowercase)
            uppercase_letter = random.choice(string.ascii_uppercase)


            index_small = random.randint(0, len(emoji_list11))
            emoji_list11.insert(index_small, lowercase_letter)

            index_big = random.randint(0, len(emoji_list11))
            emoji_list11.insert(index_big, uppercase_letter)


            print("Updated list: ", *emoji_list11, sep='')
            emoji_lists = ("", *emoji_list11)

        else:
            print("The list has not changed.")
            emoji_lists = ("", *emoji_list11)


    add_number = "y"

    if add_number.lower() == 'y':
        i = 1
        while i <= xx:
            i = i + 1

            random_number = random.choice(string.digits)


            index_number = random.randint(0, len(emoji_list11))
            emoji_list11.insert(index_number, random_number)



            print("Updated list: ", *emoji_list11, sep='')
            emoji_lists = ("", *emoji_list11)

        else:
            print("The list has not changed.")
            emoji_lists = ("", *emoji_list11)


    ascii = "n"
    if ascii == "y":


        emoji_to_sign = {}
        with open('supported_emojis_with_symbols.csv', 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                emoji, sign = row
                emoji_to_sign[emoji] = sign


        output = []
        for emoji in emoji_lists:
            if emoji in emoji_to_sign:
                output.append(f"{emoji_to_sign[emoji]}")
            else:
                output.append(f"{emoji}")


        print("Result2:", ''.join(output))
        emoji_lists = random.shuffle(output)
        emoji_lists = ''.join(output)
        print(emoji_lists)


    else:
        pass

if "google" in refer or "outlook" in refer or "yahoo" in refer or "twitch" in refer or "google.com"  in refer or "yahoo.com" in refer  or "twitch.com" in refer or "google.com" in refer:
    refer_list_site = 0
    letter1 = "y"
    if letter1 == "y":
        i = 1
        while i <= x:
            i = i + 1
            lowercase_letter = random.choice(string.ascii_lowercase)   
            uppercase_letter = random.choice(string.ascii_uppercase)   


            index_small = random.randint(0, len(emoji_list11))   
            emoji_list11.insert(index_small, lowercase_letter)   

            index_big = random.randint(0, len(emoji_list11))   
            emoji_list11.insert(index_big, uppercase_letter)   


            print("Updated list: ", *emoji_list11, sep='')
            emoji_lists = ("", *emoji_list11)

        else:
            print("The list has not changed.")
            emoji_lists = ("", *emoji_list11)


    add_number1 = "y"
    if add_number1 == 'y':
        i = 1
        while i <= xx:
            i = i + 1

            random_number = random.choice(string.digits)


            index_number = random.randint(0, len(emoji_list11))
            emoji_list11.insert(index_number, random_number)


            print("Updated list: ", *emoji_list11, sep='')
            emoji_lists = ("", *emoji_list11)

        else:
            print("The list has not changed.")
            emoji_lists = ("", *emoji_list11)


        # print("Normal liste: ", *emoji_list11, sep='')

    ascii1 = "y"
    if ascii1 == "y":


        emoji_to_sign = {}
        with open('supported_emojis_with_symbols.csv', 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                emoji, sign = row
                emoji_to_sign[emoji] = sign


        output = []
        for emoji in emoji_lists:
            if emoji in emoji_to_sign:
                output.append(f"{emoji_to_sign[emoji]}")
            else:
                output.append(f"{emoji}")


        print("Result:", ''.join(output))
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
            lowercase_letter = random.choice(string.ascii_lowercase)   
            uppercase_letter = random.choice(string.ascii_uppercase)   


            index_small = random.randint(0, len(emoji_list11))
            emoji_list11.insert(index_small, lowercase_letter)   

            index_big = random.randint(0, len(emoji_list11))   
            emoji_list11.insert(index_big, uppercase_letter)   


            print("Updated list: ", *emoji_list11, sep='')
            emoji_lists = ("", *emoji_list11)

        else:
            print("The list has not changed.")
            emoji_lists = ("", *emoji_list11)


    if xx != 0:
        i = 1
        while i <= xx:
            i = i + 1

            random_number = random.choice(string.digits)


            index_number = random.randint(0, len(emoji_list11))
            emoji_list11.insert(index_number, random_number)


            print("Updated list: ", *emoji_list11, sep='')
            emoji_lists = ("", *emoji_list11)

        else:
            print("The list has not changed.")
            emoji_lists = ("", *emoji_list11)



        # print("Normal liste: ", *emoji_list11, sep='')

    ascii3 = "y"
    if ascii3 == "y":


        emoji_to_sign = {}
        with open('supported_emojis_with_symbols.csv', 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            for row in reader:
                emoji, sign = row
                emoji_to_sign[emoji] = sign


        output = []
        for emoji in emoji_lists:
            if emoji in emoji_to_sign:
                output.append(f"{emoji_to_sign[emoji]}")
            else:
                output.append(f"{emoji}")


        print("Result1:", ''.join(output))
        emoji_lists = random.shuffle(output)
        emoji_lists = ''.join(output)
        print(emoji_lists)
    else:
        pass



site_folder = "site"

end_time = time.perf_counter()
elapsed_time = end_time - start_time

print(f"Password generation {elapsed_time:.4f} It took seconds.")


if os.path.exists(site_folder):
    shutil.rmtree(site_folder)
    print(f"{site_folder} and its contents were deleted.")
    root.destroy()
else:
    print(f"{site_folder} not found.")

