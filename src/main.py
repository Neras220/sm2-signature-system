import argparse
import sys
from pathlib import Path
from tkinter import Tk, ttk, messagebox
from sm2_gui import SM2GUI
from sm2_core import SM2

def create_project_structure():
    """创建项目必要的目录结构"""
    base_path = Path(__file__).parent
    
    # 创建必要的目录
    directories = {
        'assets': ['keys'],  # 存放密钥文件
        'data': ['input', 'signed']  # input存放待签名文件，signed存放签名后的文件
    }
    
    for main_dir, subdirs in directories.items():
        main_path = base_path / main_dir
        main_path.mkdir(exist_ok=True)
        for subdir in subdirs:
            (main_path / subdir).mkdir(exist_ok=True)
    
    # 创建.gitkeep文件以保持空目录
    empty_dirs = [
        base_path / 'data' / 'input',
        base_path / 'data' / 'signed'
    ]
    for dir_path in empty_dirs:
        gitkeep = dir_path / '.gitkeep'
        if not gitkeep.exists():
            gitkeep.touch()

def setup_style(root):
    """设置GUI样式"""
    style = ttk.Style()
    style.configure('TButton', padding=5, font=('微软雅黑', 9))
    style.configure('TLabel', font=('微软雅黑', 9))
    style.configure('TEntry', font=('Consolas', 9))
    
    # 设置窗口大小和位置
    window_width = 800
    window_height = 600
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    root.geometry(f'{window_width}x{window_height}+{x}+{y}')
    root.resizable(True, True)

def run_gui():
    """运行图形界面"""
    try:
        # 创建目录结构
        create_project_structure()
        
        root = Tk()
        root.title("SM2签名验证系统")
        
        # 设置样式和布局
        setup_style(root)
        
        # 创建主应用
        app = SM2GUI(root)
        
        # 运行主循环
        root.mainloop()
    except Exception as e:
        messagebox.showerror("错误", f"程序运行出错: {str(e)}")
        sys.exit(1)

def main():
    """主函数，处理命令行参数或启动GUI"""
    parser = argparse.ArgumentParser(description='SM2签名验证系统')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    
    args = parser.parse_args()
    
    if args.gui or len(sys.argv) == 1:
        run_gui()

if __name__ == "__main__":
    main()