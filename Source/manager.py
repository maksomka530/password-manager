import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import hashlib
import secrets
import string
from cryptography.fernet import Fernet, InvalidToken
import pyperclip  # pip install pyperclip

# ---------- НАСТРОЙКИ ----------
VAULT_DIR = os.path.join(os.path.expanduser("~"), "DMWSM_Vault")
VAULT_KEY_FILE = os.path.join(VAULT_DIR, "vault.key")
VAULT_DATA_FILE = os.path.join(VAULT_DIR, "vault.dat")

# ---------- УТИЛИТЫ ----------
def ensure_vault_dir():
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)

def derive_key(master_password: str) -> bytes:
    digest = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(digest)

def verify_master_password(master_password: str) -> bool:
    if not os.path.exists(VAULT_KEY_FILE):
        return False
    with open(VAULT_KEY_FILE, "rb") as f:
        stored_hash = f.read()
    input_hash = hashlib.sha256(master_password.encode()).digest()
    return input_hash == stored_hash

def save_master_password_hash(master_password: str):
    ensure_vault_dir()
    h = hashlib.sha256(master_password.encode()).digest()
    with open(VAULT_KEY_FILE, "wb") as f:
        f.write(h)

def load_vault(master_password: str) -> list:
    if not os.path.exists(VAULT_DATA_FILE):
        return []
    with open(VAULT_DATA_FILE, "rb") as f:
        encrypted_data = f.read()
    key = derive_key(master_password)
    f = Fernet(key)
    try:
        decrypted = f.decrypt(encrypted_data)
        return json.loads(decrypted.decode())
    except InvalidToken:
        raise ValueError("Неверный мастер-пароль или повреждён файл хранилища.")

def save_vault(entries: list, master_password: str):
    ensure_vault_dir()
    key = derive_key(master_password)
    f = Fernet(key)
    data = json.dumps(entries, ensure_ascii=False).encode()
    encrypted = f.encrypt(data)
    with open(VAULT_DATA_FILE, "wb") as f_out:
        f_out.write(encrypted)

def generate_password(length=16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------- ГЛАВНОЕ ОКНО (С УЛУЧШЕННЫМ ИНТЕРФЕЙСОМ) ----------
class PasswordManagerApp:
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.root = tk.Tk()
        self.root.title("DMWSM Password Vault")
        self.root.geometry("900x550")
        self.root.resizable(True, True)

        # Стили для крупных элементов
        style = ttk.Style(self.root)
        style.configure("Tool.TButton", font=("Arial", 11), padding=4)
        style.configure("Treeview.Heading", font=("Arial", 11, "bold"))
        style.configure("Treeview", font=("Arial", 10), rowheight=25)

        try:
            self.entries = load_vault(master_password)
        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
            self.root.destroy()
            return

        self.create_widgets()
        self.refresh_table()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def create_widgets(self):
        # Панель инструментов
        toolbar = tk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="Добавить", style="Tool.TButton", command=self.add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Изменить", style="Tool.TButton", command=self.edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Удалить", style="Tool.TButton", command=self.delete_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Копировать пароль", style="Tool.TButton", command=self.copy_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Сгенерировать", style="Tool.TButton", command=self.generate_and_show).pack(side=tk.LEFT, padx=2)

        # Таблица
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        columns = ("service", "login", "password")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("service", text="Сервис")
        self.tree.heading("login", text="Логин")
        self.tree.heading("password", text="Пароль")
        self.tree.column("service", width=280)
        self.tree.column("login", width=280)
        self.tree.column("password", width=280)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Строка состояния
        self.status = tk.Label(self.root, text="Готов", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 10))
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for entry in self.entries:
            self.tree.insert("", tk.END, values=(entry["service"], entry["login"], entry["password"]))
        self.status.config(text=f"Записей: {len(self.entries)} | Хранилище: {VAULT_DATA_FILE}")

    def add_entry(self):
        dialog = EntryDialog(self.root, "Добавить запись")
        if dialog.result:
            service, login, password = dialog.result
            self.entries.append({"service": service, "login": login, "password": password})
            self.refresh_table()
            self.save()

    def edit_entry(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Выберите запись для редактирования")
            return
        item = selected[0]
        idx = self.tree.index(item)
        entry = self.entries[idx]
        dialog = EntryDialog(self.root, "Изменить запись", entry["service"], entry["login"], entry["password"])
        if dialog.result:
            service, login, password = dialog.result
            self.entries[idx] = {"service": service, "login": login, "password": password}
            self.refresh_table()
            self.save()

    def delete_entry(self):
        selected = self.tree.selection()
        if not selected:
            return
        if messagebox.askyesno("Подтверждение", "Удалить выбранную запись?"):
            idx = self.tree.index(selected[0])
            del self.entries[idx]
            self.refresh_table()
            self.save()

    def copy_password(self):
        selected = self.tree.selection()
        if not selected:
            return
        idx = self.tree.index(selected[0])
        password = self.entries[idx]["password"]
        pyperclip.copy(password)
        self.status.config(text="Пароль скопирован в буфер обмена")

    def generate_and_show(self):
        pwd = generate_password()
        messagebox.showinfo("Сгенерированный пароль", f"Новый пароль:\n{pwd}\n\nОн скопирован в буфер обмена.")
        pyperclip.copy(pwd)

    def save(self):
        try:
            save_vault(self.entries, self.master_password)
            self.status.config(text="Сохранено")
        except Exception as e:
            messagebox.showerror("Ошибка сохранения", str(e))

    def on_close(self):
        self.save()
        self.root.destroy()

# ---------- ДИАЛОГ ДОБАВЛЕНИЯ/РЕДАКТИРОВАНИЯ (КРУПНЫЕ КНОПКИ) ----------
class EntryDialog(tk.Toplevel):
    def __init__(self, parent, title, service="", login="", password=""):
        super().__init__(parent)
        self.title(title)
        self.result = None

        self.geometry("500x280")
        self.resizable(False, False)

        style = ttk.Style(self)
        style.configure("Big.TButton", font=("Arial", 12), padding=6)

        default_font = ("Arial", 11)

        ttk.Label(self, text="Сервис (например, GitHub):", font=default_font).pack(pady=(15,0))
        self.entry_service = ttk.Entry(self, width=45, font=default_font)
        self.entry_service.pack(pady=5)
        self.entry_service.insert(0, service)

        ttk.Label(self, text="Логин:", font=default_font).pack()
        self.entry_login = ttk.Entry(self, width=45, font=default_font)
        self.entry_login.pack(pady=5)
        self.entry_login.insert(0, login)

        ttk.Label(self, text="Пароль:", font=default_font).pack()
        pwd_frame = tk.Frame(self)
        pwd_frame.pack(pady=5)
        self.entry_password = ttk.Entry(pwd_frame, width=35, font=default_font)
        self.entry_password.pack(side=tk.LEFT)
        self.entry_password.insert(0, password)
        ttk.Button(pwd_frame, text="Сгенерировать", style="Big.TButton", command=self.generate).pack(side=tk.LEFT, padx=8)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="OK", style="Big.TButton", command=self.ok).pack(side=tk.LEFT, padx=15)
        ttk.Button(btn_frame, text="Отмена", style="Big.TButton", command=self.cancel).pack(side=tk.LEFT, padx=15)

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.grab_set()
        self.wait_window()

    def generate(self):
        pwd = generate_password()
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, pwd)

    def ok(self):
        s = self.entry_service.get().strip()
        l = self.entry_login.get().strip()
        p = self.entry_password.get().strip()
        if not s or not l or not p:
            messagebox.showwarning("Внимание", "Все поля должны быть заполнены")
            return
        self.result = (s, l, p)
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

# ---------- ТОЧКА ВХОДА ----------
def main():
    if not os.path.exists(VAULT_KEY_FILE):
        root = tk.Tk()
        root.withdraw()
        pwd = simpledialog.askstring("Первый запуск", "Придумайте мастер-пароль:", show='*')
        if not pwd:
            messagebox.showerror("Ошибка", "Мастер-пароль не может быть пустым.")
            return
        pwd2 = simpledialog.askstring("Подтверждение", "Повторите мастер-пароль:", show='*')
        if pwd != pwd2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return
        save_master_password_hash(pwd)
        save_vault([], pwd)
        messagebox.showinfo("Успех", f"Хранилище создано в:\n{VAULT_DIR}")
        root.destroy()

    root = tk.Tk()
    root.withdraw()
    master = simpledialog.askstring("Вход в хранилище", "Введите мастер-пароль:", show='*')
    if not master:
        return
    if not verify_master_password(master):
        messagebox.showerror("Ошибка", "Неверный мастер-пароль.")
        return

    root.destroy()
    app = PasswordManagerApp(master)

if __name__ == "__main__":
    main()