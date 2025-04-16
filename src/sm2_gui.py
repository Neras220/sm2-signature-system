from tkinter import *
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import hashlib
from sm2_core import SM2
from gmssl import sm3, func
import os
from pathlib import Path
from datetime import datetime  # 添加datetime模块导入

class SM2GUI:
    def __init__(self, master):
        """
        初始化SM2图形界面
        使用Tkinter创建一个包含密钥管理、签名和验证三个标签页的界面
        """
        self.master = master
        self.sm2 = SM2()  # 创建SM2算法实例
        
        # 定义支持的文件类型，当前仅支持txt文件
        self.supported_filetypes = [
            ("文本文件", "*.txt"),
        ]
        
        # 创建标签页控件，用于分页显示不同功能
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # 创建三个主要功能页面：密钥管理、签名操作、验证签名
        self.key_frame = ttk.Frame(self.notebook)
        self.sign_frame = ttk.Frame(self.notebook)
        self.verify_frame = ttk.Frame(self.notebook)
        
        # 添加标签页到notebook
        self.notebook.add(self.key_frame, text='密钥管理')
        self.notebook.add(self.sign_frame, text='签名')
        self.notebook.add(self.verify_frame, text='验证')
        
        # 初始化各个页面的界面元素
        self.setup_key_page()    # 设置密钥管理页面
        self.setup_sign_page()   # 设置签名操作页面
        self.setup_verify_page() # 设置验证签名页面
        
        # 程序启动时自动加载或生成密钥对
        self.load_or_generate_keys()

    def setup_key_page(self):
        """
        设置密钥管理页面的界面元素
        包含：
        1. 密钥展示区域：显示当前的公私钥对
        2. 操作按钮区域：生成新密钥、导入导出密钥功能
        """
        # 密钥展示区域
        key_group = ttk.LabelFrame(self.key_frame, text='当前密钥对', padding=10)
        key_group.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(key_group, text="私钥:").grid(row=0, column=0, sticky='w')
        self.priv_key = ttk.Entry(key_group, width=70)
        self.priv_key.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(key_group, text="公钥X:").grid(row=1, column=0, sticky='w')
        self.pub_x = ttk.Entry(key_group, width=70)
        self.pub_x.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(key_group, text="公钥Y:").grid(row=2, column=0, sticky='w')
        self.pub_y = ttk.Entry(key_group, width=70)
        self.pub_y.grid(row=2, column=1, padx=5, pady=2)
        
        # 按钮区域
        btn_frame = ttk.Frame(key_group)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="生成新密钥对", command=self.generate_new_keypair).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="导出密钥对", command=self.export_keypair).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="导入密钥对", command=self.import_keypair).pack(side='left', padx=5)

    def setup_sign_page(self):
        """
        设置签名页面的界面元素
        包含：
        1. 文件选择区域：选择需要签名的文件
        2. 签名结果区域：显示签名值r和s
        3. 文件哈希值显示：显示所选文件的SM3哈希值
        """
        # 文件选择区域
        file_group = ttk.LabelFrame(self.sign_frame, text='选择文件', padding=10)
        file_group.pack(fill='x', padx=5, pady=5)
        
        # 添加文件类型说明
        supported_types = ttk.Label(file_group, 
            text="支持的文件类型: TXT",
            font=('微软雅黑', 8))
        supported_types.grid(row=0, column=0, columnspan=3, sticky='w', pady=(0,5))
        
        ttk.Label(file_group, text="待签名文件:").grid(row=1, column=0, sticky='w')
        self.file_to_sign = ttk.Entry(file_group, width=60)
        self.file_to_sign.grid(row=1, column=1, padx=5)
        ttk.Button(file_group, text="浏览", command=self.select_sign_file).grid(row=1, column=2, padx=5)
        
        # 签名结果区域
        sig_group = ttk.LabelFrame(self.sign_frame, text='签名结果', padding=10)
        sig_group.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(sig_group, text="签名值 r:").grid(row=0, column=0, sticky='w')
        self.sig_r = ttk.Entry(sig_group, width=70)
        self.sig_r.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(sig_group, text="签名值 s:").grid(row=1, column=0, sticky='w')
        self.sig_s = ttk.Entry(sig_group, width=70)
        self.sig_s.grid(row=1, column=1, padx=5, pady=2)
        
        # 操作按钮
        ttk.Button(self.sign_frame, text="生成签名", command=self.generate_signature).pack(pady=10)
        
        # 文件哈希值显示
        hash_group = ttk.LabelFrame(self.sign_frame, text='文件哈希值', padding=10)
        hash_group.pack(fill='x', padx=5, pady=5)
        self.file_hash = ScrolledText(hash_group, height=3, width=70)
        self.file_hash.pack(fill='x', padx=5, pady=5)

    def setup_verify_page(self):
        """
        设置验证页面的界面元素
        包含：
        1. 文件选择：选择待验证的原始文件
        2. 签名文件：选择.sig格式的签名文件
        3. 签名信息：显示签名值r和s
        4. 公钥信息：显示用于验证的公钥
        5. 验证结果显示
        """
        # 文件选择区域
        file_group = ttk.LabelFrame(self.verify_frame, text='选择文件', padding=10)
        file_group.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(file_group, text="待验证文件:").grid(row=0, column=0, sticky='w')
        self.file_to_verify = ttk.Entry(file_group, width=60)
        self.file_to_verify.grid(row=0, column=1, padx=5)
        ttk.Button(file_group, text="浏览", command=self.select_verify_file).grid(row=0, column=2, padx=5)
        
        # 添加.sig文件选择
        ttk.Label(file_group, text="签名文件(.sig):").grid(row=1, column=0, sticky='w')
        self.sig_file = ttk.Entry(file_group, width=60)
        self.sig_file.grid(row=1, column=1, padx=5)
        ttk.Button(file_group, text="浏览", command=self.select_sig_file).grid(row=1, column=2, padx=5)
        
        # 签名输入区域
        sig_group = ttk.LabelFrame(self.verify_frame, text='签名信息', padding=10)
        sig_group.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(sig_group, text="签名值 r:").grid(row=0, column=0, sticky='w')
        self.verify_r = ttk.Entry(sig_group, width=70)
        self.verify_r.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(sig_group, text="签名值 s:").grid(row=1, column=0, sticky='w')
        self.verify_s = ttk.Entry(sig_group, width=70)
        self.verify_s.grid(row=1, column=1, padx=5, pady=2)
        
        # 公钥输入区域
        pubkey_group = ttk.LabelFrame(self.verify_frame, text='公钥信息', padding=10)
        pubkey_group.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(pubkey_group, text="公钥 X:").grid(row=0, column=0, sticky='w')
        self.verify_pub_x = ttk.Entry(pubkey_group, width=70)
        self.verify_pub_x.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(pubkey_group, text="公钥 Y:").grid(row=1, column=0, sticky='w')
        self.verify_pub_y = ttk.Entry(pubkey_group, width=70)
        self.verify_pub_y.grid(row=1, column=1, padx=5, pady=2)
        
        # 操作按钮和结果显示
        btn_frame = ttk.Frame(self.verify_frame)
        btn_frame.pack(fill='x', padx=5, pady=10)
        
        ttk.Button(btn_frame, text="验证签名", command=self.verify_signature).pack(side='left', padx=5)
        self.verify_result = ttk.Label(btn_frame, text="", font=('微软雅黑', 10, 'bold'))
        self.verify_result.pack(side='left', padx=20)

    def load_or_generate_keys(self):
        """
        加载或生成SM2密钥对
        1. 尝试从预设路径加载已存在的密钥文件
        2. 如果密钥文件不存在，则生成新的密钥对并保存
        3. 更新界面显示
        """
        try:
            keyfile_path = Path(__file__).parent / 'assets' / 'keys' / 'sm2_key.txt'
            keyfile_path.parent.mkdir(parents=True, exist_ok=True)
            
            if keyfile_path.exists():
                with open(keyfile_path, 'r') as f:
                    self.sm2.d = int(f.readline().strip(), 16)
            else:
                self.sm2.setSecretKey(True)
                with open(keyfile_path, 'w') as f:
                    f.write(self.sm2.hex(self.sm2.d))
                    
            self.sm2.PBx, self.sm2.PBy = self.sm2.multiPoint([self.sm2.Gx, self.sm2.Gy], self.sm2.d)
            self.update_key_display()
            
        except Exception as e:
            messagebox.showerror("错误", f"加载密钥出错: {str(e)}")

    def update_key_display(self):
        """更新密钥显示"""
        self.priv_key.delete(0, END)
        self.pub_x.delete(0, END)
        self.pub_y.delete(0, END)
        
        self.priv_key.insert(0, self.sm2.hex(self.sm2.d))
        self.pub_x.insert(0, self.sm2.hex(self.sm2.PBx))
        self.pub_y.insert(0, self.sm2.hex(self.sm2.PBy))
        
        # 同时更新验证页面的公钥
        self.verify_pub_x.delete(0, END)
        self.verify_pub_y.delete(0, END)
        self.verify_pub_x.insert(0, self.sm2.hex(self.sm2.PBx))
        self.verify_pub_y.insert(0, self.sm2.hex(self.sm2.PBy))

    def generate_new_keypair(self):
        """生成新的密钥对"""
        try:
            self.sm2.setSecretKey(True)
            keyfile_path = Path(__file__).parent / 'assets' / 'keys.txt'
            with open(keyfile_path, 'w') as f:
                f.write(self.sm2.hex(self.sm2.d))
            self.sm2.PBx, self.sm2.PBy = self.sm2.multiPoint([self.sm2.Gx, self.sm2.Gy], self.sm2.d)
            self.update_key_display()
            messagebox.showinfo("成功", "已生成新的密钥对")
        except Exception as e:
            messagebox.showerror("错误", f"生成密钥对失败: {str(e)}")

    def export_keypair(self):
        """导出密钥对"""
        try:
            filename = filedialog.asksaveasfilename(
                initialdir=str(Path(__file__).parent / 'assets' / 'keys'),
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt")],
                title="导出密钥对"
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(f"私钥: {self.sm2.hex(self.sm2.d)}\n")
                    f.write(f"公钥X: {self.sm2.hex(self.sm2.PBx)}\n")
                    f.write(f"公钥Y: {self.sm2.hex(self.sm2.PBy)}\n")
                messagebox.showinfo("成功", "密钥对已导出")
        except Exception as e:
            messagebox.showerror("错误", f"导出密钥对失败: {str(e)}")

    def import_keypair(self):
        """导入密钥对"""
        try:
            filename = filedialog.askopenfilename(
                initialdir=str(Path(__file__).parent / 'assets' / 'keys'),
                filetypes=[("文本文件", "*.txt")],
                title="导入密钥对"
            )
            if filename:
                with open(filename, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("私钥:"):
                            self.sm2.d = int(line.split(":")[1].strip(), 16)
                            break
                self.sm2.PBx, self.sm2.PBy = self.sm2.multiPoint([self.sm2.Gx, self.sm2.Gy], self.sm2.d)
                self.update_key_display()
                messagebox.showinfo("成功", "密钥对已导入")
        except Exception as e:
            messagebox.showerror("错误", f"导入密钥对失败: {str(e)}")

    def select_sign_file(self):
        """选择要签名的文件"""
        filepath = filedialog.askopenfilename(
            initialdir=str(Path(__file__).parent / 'data' / 'input'),
            title="选择要签名的文件",
            filetypes=[("文本文件", "*.txt")]
        )
        if filepath:
            if not filepath.lower().endswith('.txt'):
                messagebox.showerror("错误", "只支持TXT文本文件")
                return
                
            self.file_to_sign.delete(0, END)
            self.file_to_sign.insert(0, filepath)
            
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                    hash_value = sm3.sm3_hash(func.bytes_to_list(data))
                    self.file_hash.delete('1.0', END)
                    self.file_hash.insert('1.0', f"SM3哈希值:\n{hash_value}")
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败: {str(e)}")

    def select_verify_file(self):
        """选择要验证的文件"""
        filepath = filedialog.askopenfilename(
            initialdir=str(Path(__file__).parent / 'data' / 'input'),
            title="选择要验证的文件",
            filetypes=[("文本文件", "*.txt")]
        )
        if filepath:
            self.file_to_verify.delete(0, END)
            self.file_to_verify.insert(0, filepath)
            
            try:
                # 显示文件哈希值
                with open(filepath, 'rb') as f:
                    data = f.read()
                    hash_value = sm3.sm3_hash(func.bytes_to_list(data))
                    self.file_hash.delete('1.0', END)
                    self.file_hash.insert('1.0', f"文件SM3哈希值:\n{hash_value}")
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败: {str(e)}")

    def select_original_file(self):
        """手动选择原始文件"""
        filepath = filedialog.askopenfilename(
            initialdir=str(Path(__file__).parent / 'data' / 'input'),
            title="选择原始文件",
            filetypes=[("文本文件", "*.txt")]
        )
        if filepath:
            self.file_to_verify.delete(0, END)
            self.file_to_verify.insert(0, filepath)

    def select_sig_file(self):
        """选择签名文件并自动导入签名信息"""
        filepath = filedialog.askopenfilename(
            initialdir=str(Path(__file__).parent / 'data' / 'signed'),
            title="选择签名文件",
            filetypes=[("签名文件", "*.sig")]
        )
        if filepath:
            try:
                # 更新签名文件路径显示
                self.sig_file.delete(0, END)
                self.sig_file.insert(0, filepath)
                
                # 读取签名文件内容
                with open(filepath, 'r') as f:
                    lines = f.readlines()
                    
                # 解析签名文件信息
                for line in lines:
                    if line.startswith("r:"):
                        r_value = line.split(":")[1].strip()
                        self.verify_r.delete(0, END)
                        self.verify_r.insert(0, r_value)
                    elif line.startswith("s:"):
                        s_value = line.split(":")[1].strip()
                        self.verify_s.delete(0, END)
                        self.verify_s.insert(0, s_value)
                    elif line.startswith("公钥X:"):
                        x_value = line.split(":")[1].strip()
                        self.verify_pub_x.delete(0, END)
                        self.verify_pub_x.insert(0, x_value)
                    elif line.startswith("公钥Y:"):
                        y_value = line.split(":")[1].strip()
                        self.verify_pub_y.delete(0, END)
                        self.verify_pub_y.insert(0, y_value)
                    elif line.startswith("原始文件:"):
                        orig_filename = line.split(":")[1].strip()
                        # 查找对应的原始文件
                        orig_file = Path(__file__).parent / 'data' / 'input' / orig_filename
                        if orig_file.exists():
                            self.file_to_verify.delete(0, END)
                            self.file_to_verify.insert(0, str(orig_file))
                            # 更新哈希值显示
                            with open(orig_file, 'rb') as f:
                                data = f.read()
                                hash_value = sm3.sm3_hash(func.bytes_to_list(data))
                                self.file_hash.delete('1.0', END)
                                self.file_hash.insert('1.0', f"原始文件SM3哈希值:\n{hash_value}")
                        
                messagebox.showinfo("成功", "已导入签名信息")
                
            except Exception as e:
                messagebox.showerror("错误", f"读取签名文件失败: {str(e)}")

    def generate_signature(self):
        """
        生成文件的SM2签名
        执行步骤：
        1. 读取选中的文件内容
        2. 使用SM2算法生成签名值(r,s)
        3. 在界面上显示签名结果
        4. 同时在验证页面自动填入签名值
        5. 将签名信息保存为.sig文件，包含：
           - 原始文件信息
           - 签名时间戳
           - 签名值(r,s)
           - 公钥信息
        """
        filepath = self.file_to_sign.get()
        if not filepath:
            messagebox.showerror("错误", "请先选择要签名的文件")
            return
            
        if not Path(filepath).exists():
            messagebox.showerror("错误", "文件不存在")
            return
            
        try:
            # 读取文件内容
            with open(filepath, 'rb') as f:
                file_content = f.read()

            # 生成签名
            r, s = self.sm2.sign(file_content)
            
            # 显示签名结果
            self.sig_r.delete(0, END)
            self.sig_r.insert(0, self.sm2.hex(r))
            self.sig_s.delete(0, END)
            self.sig_s.insert(0, self.sm2.hex(s))
            
            # 同时填入验证页面
            self.verify_r.delete(0, END)
            self.verify_s.delete(0, END)
            self.verify_r.insert(0, self.sm2.hex(r))
            self.verify_s.insert(0, self.sm2.hex(s))
            
            # 保存签名信息
            output_dir = Path(__file__).parent / 'data' / 'signed'
            output_dir.mkdir(exist_ok=True)
            
            original_filename = Path(filepath).name
            signature_filename = f"{original_filename}.sig"
            signature_path = output_dir / signature_filename
            
            # 保存签名文件，包含更多信息
            with open(signature_path, 'w') as f:
                f.write(f"原始文件: {original_filename}\n")
                f.write(f"文件大小: {Path(filepath).stat().st_size} bytes\n")
                f.write(f"签名时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"r: {self.sm2.hex(r)}\n")
                f.write(f"s: {self.sm2.hex(s)}\n")
                f.write(f"公钥X: {self.sm2.hex(self.sm2.PBx)}\n")
                f.write(f"公钥Y: {self.sm2.hex(self.sm2.PBy)}\n")
            
            messagebox.showinfo("成功", 
                f"签名已生成并保存到:\n{signature_path}\n\n"
                f"原始文件: {original_filename}\n"
                f"文件大小: {Path(filepath).stat().st_size / 1024:.1f} KB")
            
        except Exception as e:
            messagebox.showerror("错误", f"签名生成失败: {str(e)}")

    def verify_signature(self):
        """
        验证SM2签名的有效性
        验证步骤：
        1. 收集所需信息：原始文件、签名值(r,s)、公钥(x,y)
        2. 进行基本的格式验证和数值转换
        3. 计算并显示文件的哈希值
        4. 使用SM2算法进行标准的签名验证
        5. 显示验证结果（成功/失败）
        """
        filepath = self.file_to_verify.get()
        r_hex = self.verify_r.get()
        s_hex = self.verify_s.get()
        pub_x_hex = self.verify_pub_x.get()
        pub_y_hex = self.verify_pub_y.get()
        
        if not all([filepath, r_hex, s_hex, pub_x_hex, pub_y_hex]):
            messagebox.showerror("错误", "请填写完整的验证信息")
            return
            
        try:
            # 基本格式验证
            try:
                pub_x = int(pub_x_hex, 16)
                pub_y = int(pub_y_hex, 16)
                r = int(r_hex, 16)
                s = int(s_hex, 16)
            except ValueError:
                messagebox.showerror("错误", "签名值或公钥格式无效")
                return

            # 读取文件内容
            with open(filepath, 'rb') as f:
                file_content = f.read()
                
            # 显示验证信息
            info_text = f"验证信息:\n"
            info_text += f"文件: {Path(filepath).name}\n"
            info_text += f"文件哈希: {sm3.sm3_hash(func.bytes_to_list(file_content))}\n"
            info_text += f"签名值 r: {r_hex}\n"
            info_text += f"签名值 s: {s_hex}\n"
            info_text += f"公钥 X: {pub_x_hex}\n"
            info_text += f"公钥 Y: {pub_y_hex}\n"
            
            self.file_hash.delete('1.0', END)
            self.file_hash.insert('1.0', info_text)
            
            # 执行SM2标准验证
            valid = self.sm2.verify(file_content, (r, s), pub_x, pub_y)
            
            if valid:
                self.verify_result.config(text="✓ 签名验证成功", foreground='green')
            else:
                self.verify_result.config(text="✗ 签名验证失败", foreground='red')

        except Exception as e:
            messagebox.showerror("错误", f"验证过程出错: {str(e)}")