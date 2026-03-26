import importlib.util
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import platform
import uuid
import psutil
import qrcode
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
import sqlite3
import cv2
import base64
import os




conn = sqlite3.connect("users2.db")
cursor = conn.cursor()


cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    site_name TEXT NOT NULL,
    site_username TEXT NOT NULL,
    password TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
""")
conn.commit()


global logged_in_user_id
logged_in_user_id = None


def block_physical_keyboard(event):
    return "break"


def xor_hex(a, b):
    result = hex(int(a, 16) ^ int(b, 16))[2:].zfill(2)
    return result[0] + result[-1]

def get_largest_digit(value):
    return max(int(digit) for digit in str(value))


def get_system_info():
    mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])
    mac_parts = mac_address.split(':')
    first_part = mac_parts[0]
    last_part = mac_parts[-1]
    print(mac_address)



    system = platform.system()[:2].encode('ascii').hex()
    version = platform.version()[:2].encode('ascii').hex()
    machine = platform.machine()[:2].encode('ascii').hex()
    node = platform.node()[:2].encode('ascii').hex()
    processor = platform.processor()[:2].encode('ascii').hex()
    system1 = platform.system()
    version1 = platform.version()
    machine1 = platform.machine()
    node1 = platform.node()
    processor1 = platform.processor()
    system2 = platform.system()[:2]
    version2 = platform.version()[:2]
    machine2 = platform.machine()[:2]
    node2 = platform.node()[:2]
    processor2 = platform.processor()[:2]

    print(system1, version1, machine1, node1, processor1)
    print(system2, version2, machine2, node2, processor2)
    print(system, version, machine, node, processor)

    print(mac_address)

    xor_results = {
        "System XOR MAC1": xor_hex(system, first_part),
        "Version XOR MAC2": xor_hex(version, mac_parts[1]),
        "Machine XOR MAC3": xor_hex(machine, mac_parts[2]),
        "Node XOR MAC4": xor_hex(node, mac_parts[3]),
        "Processor XOR MAC5": xor_hex(processor, mac_parts[4])
    }
    print(system, first_part)

    total_ram = int(psutil.virtual_memory().total / (1024 ** 3))
    total_disk = 0
    for disk in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(disk.mountpoint)
            total_disk += usage.total
        except PermissionError:
            pass
        except FileNotFoundError:
            pass

    total_disk = int(total_disk / (1024 ** 3))
    largest_ram_digit = get_largest_digit(total_ram)
    largest_disk_digit = get_largest_digit(total_disk)
    print(largest_disk_digit)

    aes_key = (
        f"{first_part}"  
        f"{xor_results['System XOR MAC1']}"  
        f"{largest_ram_digit}"  
        f"{xor_results['Version XOR MAC2']}"  
        f"{xor_results['Machine XOR MAC3']}"  
        f"{last_part}"  
        f"{xor_results['Node XOR MAC4']}"  
        f"{largest_disk_digit}"  
        f"{xor_results['Processor XOR MAC5']}"
    )


    return aes_key


aes_key = get_system_info()
print("AES Key:", aes_key)
aes_key_bytes = aes_key.encode('utf-8')
print("AES Key (Bytes):", aes_key_bytes)


AES_KEY = aes_key_bytes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_data(plain_text):
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode(), None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_data(encrypted_text):
    data = base64.b64decode(encrypted_text)
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(AES_KEY)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode()


def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def add_emoji_to_password(entry, emoji):
    entry.insert(tk.END, emoji)

def clear_password(entry):
    entry.delete(0, tk.END)

virtual_keyboard_open = False

def open_virtual_keyboard(entry):
    global virtual_keyboard_open


    if virtual_keyboard_open:
        return

    keyboard_window = tk.Toplevel()
    keyboard_window.title("Virtual Keyboard")
    keyboard_window.geometry("350x450+700+250")
    keyboard_window.configure(bg="#f0f4f7")

    def on_close():
        global virtual_keyboard_open
        virtual_keyboard_open = False
        keyboard_window.destroy()


    keyboard_window.protocol("WM_DELETE_WINDOW", on_close)
    virtual_keyboard_open = True

    tk.Label(keyboard_window, text="Enter your password!", font=("Helvetica", 14, "bold"), bg="#f0f4f7").pack(pady=10)

    emoji_list = [
        "😀", "😁", "😂", "🤣",
        "😅", "😆", "😉", "😊",
        "😍", "😘", "😗", "😙",
        "🤗", "😇", "😋", "😝",
    ]

    keyboard_frame = tk.Frame(keyboard_window, bg="#f0f4f7")
    keyboard_frame.pack()

    for i in range(4):
        for j in range(4):
            emoji = emoji_list[i * 4 + j]
            btn_emoji = tk.Button(
                keyboard_frame, text=emoji,
                command=lambda e=emoji: add_emoji_to_password(entry, e),
                width=4, height=2, font=("Arial", 12),
                bg="#ffffff", fg="#000000", relief="groove", bd=1
            )
            btn_emoji.grid(row=i, column=j, padx=3, pady=3)

    tk.Button(
        keyboard_window, text="Clear", font=("Helvetica", 12, "bold"),
        command=lambda: clear_password(entry), bg="#ff6961", fg="white"
    ).pack(side="left", padx=20, pady=7)
    tk.Button(
        keyboard_window, text="OK!", font=("Helvetica", 12, "bold"),
        command=lambda: on_close(), bg="#ff6961", fg="white"
    ).pack(side="right", padx=20, pady=7)

def get_logged_in_user_id():
    global logged_in_user_id
    return logged_in_user_id

def load_user_passwords():
    user_id = get_logged_in_user_id()
    if not user_id:
        return

    cursor.execute("SELECT site_name, site_username, password FROM passwords WHERE user_id = ?", (user_id,))
    passwords = cursor.fetchall()

    list_passwords.delete(0, tk.END)
    for encrypted_site_name, encrypted_site_username, encrypted_password in passwords:
        site_name = decrypt_data(encrypted_site_name)
        site_username = decrypt_data(encrypted_site_username)
        password = decrypt_data(encrypted_password)

        list_passwords.insert(tk.END, f"Site: {site_name}")
        list_passwords.insert(tk.END, f"Username: {site_username}")
        list_passwords.insert(tk.END, f"Password: {password}")
        list_passwords.insert(tk.END, f"-----------------------------------")


def add_password():
    import time
    start_time = time.time()

    site_name = entry_site_name.get().lower()
    site_username = entry_site_username.get()

    folder_name = "site"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    try:
        file_path = os.path.join(folder_name, f"{site_name}.txt")
        with open(file_path, "w") as file:
            file.write("Information will be added below...\n")
        messagebox.showinfo("Successful", f"'{file_path}' Create File!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while creating the file: {e}")

    site_username = entry_site_username.get()

    if not site_name or not site_username:
        messagebox.showerror("Error", "Fill in all fields!")
        return

    user_id = get_logged_in_user_id()
    if not user_id:
        messagebox.showerror("Error", "User session not found!")
        return

    spec = importlib.util.spec_from_file_location("Algorithm", "Algorithm.py")
    onemli_kod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(onemli_kod)

    encrypted_site_name = encrypt_data(site_name)
    encrypted_site_username = encrypt_data(site_username)
    generated_password = ''.join(onemli_kod.emoji_lists)
    encrypted_password = encrypt_data(generated_password)


    cursor.execute("INSERT INTO passwords (user_id, site_name, site_username, password) VALUES (?, ?, ?, ?)",
                   (user_id, encrypted_site_name, encrypted_site_username, encrypted_password))
    conn.commit()


    load_user_passwords()
    end_time = time.time()
    total_time = end_time - start_time
    print(f"Password generation, encryption and registration process in total {total_time:.4f} It took seconds.")


def login():
    username = entry_login_username.get()
    password = entry_login_password.get()

    if not username or not password:
        messagebox.showerror("Error", "Fill in all fields!")
        return

    hashed_username = hash_text(username)
    hashed_password = hash_text(password)
    cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (hashed_username, hashed_password))
    user = cursor.fetchone()

    if user:
        global logged_in_user_id
        logged_in_user_id = user[0]
        messagebox.showinfo("Successful", f"Welcome!")
        login_frame.pack_forget()
        main_frame.pack()
        load_user_passwords()
    else:
        messagebox.showerror("Error", "Username or password is incorrect!")

def register():
    username = entry_reg_username.get()
    password = entry_reg_password.get()

    if not username or not password:
        messagebox.showerror("Error", "Fill in all fields!")
        return

    try:
        hashed_username = hash_text(username)
        hashed_password = hash_text(password)

        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (hashed_username, hashed_password))
        conn.commit()

        messagebox.showinfo("Successful", "Registration successful! You can log in.")
        show_login_screen()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "This username is already taken!")


def show_login_screen():
    register_frame.pack_forget()
    main_frame.pack_forget()
    login_frame.pack()


def show_register_screen():
    login_frame.pack_forget()
    register_frame.pack()

    #####################
    #####################



    def get_motherboard_serial():
        try:
            result = subprocess.run(["powershell", "-Command",
                                     "Get-WmiObject Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber"],
                                    capture_output=True, text=True)
            serial_number = result.stdout.strip()
            return serial_number
        except Exception as e:
            return f"Error: {e}"

    serinumber = get_motherboard_serial()
    print("Motherboard Serial Number:", serinumber)

    plain_text = aes_key
    key = serinumber
    cipher_text = []

    key_length = len(key)
    key_index = 0

    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index].upper()) - ord('A')
            if char.isupper():
                cipher_text.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                cipher_text.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            key_index = (key_index + 1) % key_length
        elif char.isdigit():
            shift = ord(key[key_index].upper()) - ord('A')
            cipher_text.append(str((int(char) + shift) % 10))
            key_index = (key_index + 1) % key_length
        else:
            cipher_text.append(char)


    print(f"Ciphertext: {''.join(cipher_text)}")
    chipher__text = ''.join(cipher_text)
    print(chipher__text)


    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )

    qr.add_data(chipher__text)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    img.save("qrcode.png")
    print("QR code successfully saved as 'qrcode.png'.")




def approve():

    def approve_confirm():
        messagebox.showinfo("Continue", "The process continues...")
        root.destroy()

    def cancel():

        messagebox.showwarning("Stopped", "The transaction was terminated.")
        root.destroy()
        root.quit()


    root = tk.Tk()
    root.title("Confirmation Screen")
    root.geometry("600x250+200+730")


    label = tk.Label(root, text="""  If the hardware has been changed,
select "Yes" and then scan the QR CODE!
This process will save the generated passwords
to a text file
and will completely clear the database.
However, if the hardware has not changed, please select "No".""", font=("Arial", 12))
    label.pack(pady=10)


    button_yes = tk.Button(root, text="YES", command=lambda: (approve_confirm() , app()), width=10, bg="lightgreen")
    button_yes.pack(side=tk.LEFT, padx=20, pady=20)

    button_no = tk.Button(root, text="NO", command=cancel, width=10, bg="lightcoral")
    button_no.pack(side=tk.RIGHT, padx=20, pady=20)


    root.mainloop()


def app():

    conn = sqlite3.connect("users2.db")
    cursor = conn.cursor()

    def unpad(data):
        pad_len = data[-1]
        return data[:-pad_len]

    def decrypt_data(encrypted_text, decryption_key):

        try:
            encrypted_data = base64.b64decode(encrypted_text)
            cipher = Cipher(algorithms.AES(decryption_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

            return unpadded_data.decode()
        except Exception as e:
            print(f"Decryption error: {e}")
            return "[Unsolved]"


    def decode_qr(file_path):
        img = cv2.imread(file_path)
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        return data if data else None

    def decrypt_and_save():
        file_path = filedialog.askopenfilename(title="Select QR Code",
                                               filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")])
        if not file_path:
            return

        qr_content = decode_qr(file_path)
        print(qr_content)
        result = subprocess.run(["powershell", "-Command",
                                 "Get-WmiObject Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber"],
                                capture_output=True, text=True)
        serial_number = result.stdout.strip()

        cipher_text = qr_content
        key = serial_number
        print(serial_number)

        plain_text = []


        key_length = len(key)
        key_index = 0


        for char in cipher_text:
            if char.isalpha():
                shift = ord(key[key_index].upper()) - ord('A')
                if char.isupper():
                    plain_text.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
                else:
                    plain_text.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
                key_index = (key_index + 1) % key_length
            elif char.isdigit():
                shift = ord(key[key_index].upper()) - ord('A')
                plain_text.append(str((int(char) - shift) % 10))
                key_index = (key_index + 1) % key_length
            else:
                plain_text.append(char)

        qr_content = ''.join(plain_text)
        qr_content = qr_content.encode('utf-8')
        print(qr_content)


        if not qr_content:
            messagebox.showerror("Error", "QR code could not be read!")
            return

        decryption_key = qr_content
        if len(decryption_key) not in [16, 24, 32]:
            messagebox.showerror("Error", "The key received from the QR code is of invalid length!")
            return

        load_user_passwords(decryption_key)

    def load_user_passwords(decryption_key):
        cursor.execute("SELECT site_name, site_username, password FROM passwords")
        passwords = cursor.fetchall()


        decrypted_data = []
        for enc_site, enc_user, enc_pass in passwords:
            site_name = decrypt_data(enc_site, decryption_key)
            site_username = decrypt_data(enc_user, decryption_key)
            password = decrypt_data(enc_pass, decryption_key)
            decrypted_data.append(f"Site: {site_name}\nUsername: {site_username}\nPassword: {password}\n---\n")

        save_path = "solved_passwords.txt"
        with open(save_path, "w", encoding='utf-8') as file:
            file.writelines(decrypted_data)

        messagebox.showinfo("Successful", f"Passwords '{save_path}' Saved to file!")

    def close_db():
        conn.close()

    def delete_db():
        try:

            cursor.execute("DELETE FROM passwords")
            conn.commit()
            messagebox.showinfo("Successful", "Database data was deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Database data could not be deleted: {e}")

    window2 = tk.Tk()
    window2.title("Decryption with QR Code")
    window2.geometry("350x120+700+100")
    window2.protocol("WM_DELETE_WINDOW",
                    lambda: [window2.destroy()])

    btn_decrypt = tk.Button(window2, text="Decrypt Passwords with QR Code", command=lambda : (decrypt_and_save() , delete_db(), close_db(), window2.destroy()), font=("Helvetica", 12),
                            bg="#4CAF50", fg="white")
    btn_decrypt.pack(pady=20)

    window2.mainloop()





def copy_to_clipboard(event):
    try:
        selected_item_index = list_passwords.curselection()
        if not selected_item_index:
            return

        selected_item = list_passwords.get(selected_item_index[0])


        if selected_item.startswith("Site:"):
            item_to_copy = selected_item.replace("Site:", "").strip()
        elif selected_item.startswith("Username:"):
            item_to_copy = selected_item.replace("Username:", "").strip()
        elif selected_item.startswith("Password:"):
            item_to_copy = selected_item.replace("Password:", "").strip()
        else:
            return

        window.clipboard_clear()
        window.clipboard_append(item_to_copy)
        window.update()

        messagebox.showinfo("Copied", f"{item_to_copy} copied to clipboard!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during copying: {e}")

    list_passwords.bind("<Double-Button-1>", copy_to_clipboard)


window = tk.Tk()
window.title("Password Manager")
window.geometry("500x600+200+100")
window.configure(bg="#f5f5f5")


login_frame = tk.Frame(window, bg="#f5f5f5")
login_frame.pack()

tk.Label(login_frame, text="Username:", bg="#f5f5f5", font=("Helvetica", 12)).pack(pady=5)
entry_login_username = tk.Entry(login_frame, font=("Helvetica", 12))
entry_login_username.pack(pady=5)

tk.Label(login_frame, text="Password:", bg="#f5f5f5", font=("Helvetica", 12)).pack(pady=5)
entry_login_password = tk.Entry(login_frame, show="*", font=("Helvetica", 12))
entry_login_password.pack(pady=5)

entry_login_password.bind("<Key>", block_physical_keyboard)
entry_login_password.bind("<Button-1>", lambda e: open_virtual_keyboard(entry_login_password))

btn_login = tk.Button(login_frame, text="Login", command = login , bg="#4CAF50", fg="white", font=("Helvetica", 12), width=20)
btn_login.pack(pady=10)

btn_to_register = tk.Button(login_frame, text="Register", command=show_register_screen, bg="#2196F3", fg="white", font=("Helvetica", 12), width=20)
btn_to_register.pack()

btn_to_click = tk.Button(login_frame, text="HARDWARE CHANGE", command= approve , bg="#2196F3", fg="white", font=("Helvetica", 12), width=20)
btn_to_click.pack(pady=120)

label_text = tk.Label(login_frame, text="""If you make a hardware change on your computer,
you will receive an error for security reasons.
In this case, please select the "HARDWARE CHANGE" button.
 After selecting and confirming this option, the database
  will be completely deleted and exported to a .txt file.""", font=("Helvetica", 12), fg="black")
label_text.pack(pady=10)



register_frame = tk.Frame(window, bg="#f5f5f5")

tk.Label(register_frame, text="Username:", bg="#f5f5f5", font=("Helvetica", 12)).pack(pady=5)
entry_reg_username = tk.Entry(register_frame, font=("Helvetica", 12))
entry_reg_username.pack(pady=5)

tk.Label(register_frame, text="Password:", bg="#f5f5f5", font=("Helvetica", 12)).pack(pady=5)
entry_reg_password = tk.Entry(register_frame, show="*", font=("Helvetica", 12))
entry_reg_password.pack(pady=5)

entry_reg_password.bind("<Key>", block_physical_keyboard)
entry_reg_password.bind("<Button-1>", lambda e: open_virtual_keyboard(entry_reg_password))

btn_register = tk.Button(register_frame, text="Register", command=register, bg="#4CAF50", fg="white", font=("Helvetica", 12), width=20)
btn_register.pack(pady=10)

btn_to_login = tk.Button(register_frame, text="Login", command=show_login_screen, bg="#2196FD", fg="white", font=("Helvetica", 12), width=20)
btn_to_login.pack()


main_frame = tk.Frame(window, bg="#f5f5f5")

tk.Label(main_frame, text="Site:", bg="#f5f5f5", font=("Helvetica", 12)).pack(pady=5)
entry_site_name = tk.Entry(main_frame, font=("Helvetica", 12))
entry_site_name.pack(pady=5)

tk.Label(main_frame, text="Username:", bg="#f5f5f5", font=("Helvetica", 12)).pack(pady=5)
entry_site_username = tk.Entry(main_frame, font=("Helvetica", 12))
entry_site_username.pack(pady=5)

btn_generate_password = tk.Button(main_frame, text="Create Password and Save", command=add_password, bg="#FFC107", fg="black", font=("Helvetica", 12), width=25)
btn_generate_password.pack(pady=10)

list_passwords = tk.Listbox(main_frame, font=("Courier", 10), width=50, height=15)
list_passwords.pack(pady=20)

list_passwords.bind("<Double-Button-1>", copy_to_clipboard)


show_login_screen()
window.mainloop()
conn.close()
