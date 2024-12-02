import os
from tkinter import Tk, Label, Button, Listbox, filedialog, Toplevel, END, Text, messagebox
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

class CentralServer:
    def __init__(self):
        self.user_keys = {}  # 用户和中心的共享密钥
        self.session_keys = {}  # 用户对之间的会话密钥

    def register_user(self, user_id):
        key = get_random_bytes(8) # 每个用户与服务器共享一个8字节密钥（共享密钥）
        self.user_keys[user_id] = key
        return key

    def generate_session_key(self, user_a, user_b):
        session_key = get_random_bytes(8) # 为两个用户生成一个8字节会话密钥（会话密钥，仅短暂生效）
        self.session_keys[(user_a, user_b)] = session_key
        return session_key


class User:
    def __init__(self, user_id, shared_key):
        self.user_id = user_id
        self.shared_key = shared_key

    def encrypt_message(self, message, session_key):
        cipher = DES.new(session_key, DES.MODE_ECB)
        padded_message = message + " " * (8 - len(message) % 8)  # 填充到8的倍数
        return cipher.encrypt(padded_message.encode())

    def decrypt_message(self, encrypted_message, session_key):
        cipher = DES.new(session_key, DES.MODE_ECB)
        decrypted_message = cipher.decrypt(encrypted_message).decode().rstrip()
        return decrypted_message


# 图形用户界面
class KeyDistributionApp:
    def __init__(self, root):
        self.server = CentralServer()
        self.users = {}
        self.init_users()

        self.root = root
        self.root.title("实验五 基于DES的集中式密钥分配协议 E42214088 张瀛中")

        Label(root, text="用户列表").grid(row=0, column=0, padx=10, pady=10)

        # 多选列表
        self.user_listbox = Listbox(root, selectmode="multiple")


        self.user_listbox.grid(row=1, column=0, padx=10, pady=10)

        for user_id in self.users.keys():
            self.user_listbox.insert(END, user_id)

        Label(root, text="会话选择").grid(row=0, column=1, padx=10, pady=10)
        Button(root, text="创建会话", command=self.create_session).grid(row=1, column=1, padx=10, pady=10)
        self.log = Text(root, height=20, width=80)
        self.log.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

    def init_users(self):
        for i in range(10):
            user_id = f"User_{i+1}"
            shared_key = self.server.register_user(user_id)
            self.users[user_id] = User(user_id, shared_key)

    def create_session(self):
        selected_users = [self.user_listbox.get(i) for i in self.user_listbox.curselection()]
        if len(selected_users) != 2:
            messagebox.showerror("错误", "请同时选择两个用户进行会话！")
            return

        user_a, user_b = selected_users
        session_key = self.server.generate_session_key(user_a, user_b)

        # 打开文件选择对话框
        file_path = filedialog.askopenfilename(title="选择会话文件", filetypes=[("Text files", "*.txt")])
        if not file_path:
            return

        with open(file_path, "r") as file:
            original_message = file.read()

        # 加密信息
        encrypted_message = self.users[user_a].encrypt_message(original_message, session_key)
        self.log.insert(END, f"[{user_a} -> {user_b}] 加密消息: {encrypted_message.hex()}\n")

        # 解密信息
        decrypted_message = self.users[user_b].decrypt_message(encrypted_message, session_key)
        self.log.insert(END, f"[{user_b}] 解密消息: {decrypted_message}\n")

        # 验证一致性
        if decrypted_message == original_message:
            self.log.insert(END, f"[验证成功] 解密后消息与原始消息一致。\n\n")
        else:
            self.log.insert(END, f"[验证失败] 解密后消息与原始消息不一致。\n\n")

if __name__ == "__main__":
    root = Tk()
    app = KeyDistributionApp(root)
    root.mainloop()
