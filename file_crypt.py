import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
import base64
import os

class CryptApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Wil-go File Crypt")
        self.root.geometry("600x450")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), padding=5)
        self.style.configure('TEntry', font=('Segoe UI', 10), padding=5)
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', font=('Segoe UI', 10, 'bold'), padding=[10,5])
        
        # Custom button styles
        self.style.map('Primary.TButton',
            foreground=[('active', 'white'), ('!disabled', 'white')],
            background=[('active', '#0069d9'), ('!disabled', '#007bff')])
        
        self.style.configure('Primary.TButton', font=('Segoe UI', 10, 'bold'))
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        self.notebook = ttk.Notebook(self.root)
        
        # Encryption Tab
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.create_encrypt_ui()
        
        # Decryption Tab
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.create_decrypt_ui()
        
        self.notebook.add(self.encrypt_frame, text="Encrypt File")
        self.notebook.add(self.decrypt_frame, text="Decrypt File")
        self.notebook.pack(expand=True, fill='both')

    def create_encrypt_ui(self):
        # Encryption UI components
        ttk.Label(self.encrypt_frame, text="Select File to Encrypt:").pack(pady=(10,5))
        
        file_frame = ttk.Frame(self.encrypt_frame)
        file_frame.pack(fill='x', padx=20, pady=5)
        
        self.encrypt_file_btn = ttk.Button(file_frame, text="Browse", style='Primary.TButton', command=self.select_encrypt_file)
        self.encrypt_file_btn.pack(side='left', padx=(0,10))
        
        self.encrypt_file_info = ttk.Label(file_frame, text="No file selected", style='TLabel')
        self.encrypt_file_info.pack(side='left')
        
        # File handling options
        options_frame = ttk.Frame(self.encrypt_frame)
        options_frame.pack(fill='x', padx=20, pady=(5,0))
        
        ttk.Label(options_frame, text="After encryption:").pack(side='left')
        
        self.file_handling_var = tk.StringVar(value='remove')
        
        ttk.Radiobutton(options_frame, text="Remove original file", 
                       variable=self.file_handling_var, value='remove').pack(side='left', padx=10)
        ttk.Radiobutton(options_frame, text="Keep original file", 
                       variable=self.file_handling_var, value='keep').pack(side='left')
        
        ttk.Label(self.encrypt_frame, text="Encryption Key:").pack(pady=(10,5))
        
        key_frame = ttk.Frame(self.encrypt_frame)
        key_frame.pack(fill='x', padx=20, pady=5)
        
        self.key_entry = ttk.Entry(key_frame, width=50)
        self.key_entry.pack(side='left', fill='x', expand=True, padx=(0,10))
        
        self.gen_key_btn = ttk.Button(key_frame, text="Generate", style='Primary.TButton', command=self.generate_key)
        self.gen_key_btn.pack(side='left')
        
        action_frame = ttk.Frame(self.encrypt_frame)
        action_frame.pack(pady=(20,10))
        
        self.encrypt_btn = ttk.Button(action_frame, text="Encrypt File", style='Primary.TButton', command=self.encrypt_file)
        self.encrypt_btn.pack(pady=10, ipadx=20, ipady=5)

    def create_decrypt_ui(self):
        # Decryption UI components
        ttk.Label(self.decrypt_frame, text="Select File to Decrypt:").pack(pady=(10,5))
        
        file_frame = ttk.Frame(self.decrypt_frame)
        file_frame.pack(fill='x', padx=20, pady=5)
        
        self.decrypt_file_btn = ttk.Button(file_frame, text="Browse", style='Primary.TButton', command=self.select_decrypt_file)
        self.decrypt_file_btn.pack(side='left', padx=(0,10))
        
        self.decrypt_file_info = ttk.Label(file_frame, text="No file selected", style='TLabel')
        self.decrypt_file_info.pack(side='left')
        
        # File handling options
        options_frame = ttk.Frame(self.decrypt_frame)
        options_frame.pack(fill='x', padx=20, pady=(5,0))
        
        ttk.Label(options_frame, text="After decryption:").pack(side='left')
        
        self.decrypt_handling_var = tk.StringVar(value='remove')
        
        ttk.Radiobutton(options_frame, text="Remove encrypted file", 
                       variable=self.decrypt_handling_var, value='remove').pack(side='left', padx=10)
        ttk.Radiobutton(options_frame, text="Keep encrypted file", 
                       variable=self.decrypt_handling_var, value='keep').pack(side='left')
        
        ttk.Label(self.decrypt_frame, text="Decryption Key:").pack(pady=(10,5))
        
        key_frame = ttk.Frame(self.decrypt_frame)
        key_frame.pack(fill='x', padx=20, pady=5)
        
        self.decrypt_key_entry = ttk.Entry(key_frame, width=50)
        self.decrypt_key_entry.pack(fill='x', expand=True)
        
        action_frame = ttk.Frame(self.decrypt_frame)
        action_frame.pack(pady=(20,10))
        
        self.decrypt_btn = ttk.Button(action_frame, text="Decrypt File", style='Primary.TButton', command=self.decrypt_file)
        self.decrypt_btn.pack(pady=10, ipadx=20, ipady=5)

    def generate_key(self):
        key = Fernet.generate_key()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.decode())

    def select_encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if file_path:
            self.encrypt_path = file_path
            self.encrypt_file_info.config(text=os.path.basename(file_path))

    def select_decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if file_path:
            self.decrypt_path = file_path
            self.decrypt_file_info.config(text=os.path.basename(file_path))

    def format_file_size(self, size):
        # Convert bytes to human-readable format
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} GB"

    def encrypt_file(self):
        try:
            if not hasattr(self, 'encrypt_path') or not self.encrypt_path:
                messagebox.showerror('Error', 'Please select a file to encrypt first')
                return
                
            original_path = self.encrypt_path
            
            key = self.key_entry.get().strip()
            if not key:
                messagebox.showerror('Error', 'Please enter an encryption key or generate one')
                return
                
            try:
                key = key.encode()
                fernet = Fernet(key)
            except Exception:
                messagebox.showerror('Error', 'Invalid encryption key format. Please use a valid Fernet key')
                return
            
            try:
                with open(self.encrypt_path, 'rb') as f:
                    file_data = f.read()
            except Exception:
                messagebox.showerror('Error', 'Could not read the selected file. Please check file permissions')
                return
            
            encrypted = fernet.encrypt(file_data)
            
            save_path = filedialog.asksaveasfilename(
                title="Save Encrypted File",
                defaultextension=".enc",
                filetypes=[("Encrypted Files", "*.enc")]
            )
            
            if not save_path:
                return
                
            try:
                with open(save_path, 'wb') as f:
                    f.write(encrypted)
                
                # Handle original file based on user selection
                if self.file_handling_var.get() == 'remove':
                    try:
                        os.remove(original_path)
                        messagebox.showinfo('Success', 
                            'File encrypted successfully! Original file has been securely removed.')
                    except Exception as e:
                        messagebox.showwarning('Warning', 
                            f'File encrypted but could not remove original: {str(e)}')
                else:
                    messagebox.showinfo('Success', 
                        'File encrypted successfully! Original file has been preserved.')
            except Exception:
                messagebox.showerror('Error', 'Failed to save encrypted file. Check if you have write permissions')
        
        except Exception as e:
            messagebox.showerror('Error', f'Encryption failed: {str(e)}')

    def decrypt_file(self):
        try:
            if not hasattr(self, 'decrypt_path') or not self.decrypt_path:
                messagebox.showerror('Error', 'Please select an encrypted file first')
                return
                
            original_path = self.decrypt_path
            
            key = self.decrypt_key_entry.get().strip()
            if not key:
                messagebox.showerror('Error', 'Please enter the decryption key')
                return
                
            try:
                key = key.encode()
                fernet = Fernet(key)
            except Exception:
                messagebox.showerror('Error', 'Invalid decryption key format. Please use a valid Fernet key')
                return
            
            try:
                with open(self.decrypt_path, 'rb') as f:
                    encrypted_data = f.read()
            except Exception:
                messagebox.showerror('Error', 'Could not read the encrypted file. It may be corrupted')
                return
            
            try:
                decrypted = fernet.decrypt(encrypted_data)
            except Exception:
                messagebox.showerror('Error', 'Decryption failed. The key may be incorrect or the file is corrupted')
                return
            
            save_path = filedialog.asksaveasfilename(
                title="Save Decrypted File",
                defaultextension="",
                filetypes=[("All Files", "*.*")]
            )
            
            if not save_path:
                return
                
            try:
                with open(save_path, 'wb') as f:
                    f.write(decrypted)
                
                # Handle encrypted file based on user selection
                if self.decrypt_handling_var.get() == 'remove':
                    try:
                        os.remove(original_path)
                        messagebox.showinfo('Success', 
                            'File decrypted successfully! Encrypted file has been securely removed.')
                    except Exception as e:
                        messagebox.showwarning('Warning', 
                            f'File decrypted but could not remove encrypted file: {str(e)}')
                else:
                    messagebox.showinfo('Success', 
                        'File decrypted successfully! Encrypted file has been preserved.')
            except Exception:
                messagebox.showerror('Error', 'Failed to save decrypted file. Check if you have write permissions')
        
        except Exception as e:
            messagebox.showerror('Error', f'An unexpected error occurred: {str(e)}')

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptApp(root)
    root.mainloop()
