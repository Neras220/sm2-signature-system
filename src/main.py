import argparse
import sys
from pathlib import Path
from tkinter import Tk, ttk, messagebox
from sm2_gui import SM2GUI
from sm2_core import SM2

def create_project_structure():
    """
    创建项目必要的目录结构
    项目结构：
    /src
        /assets
            /keys      - 存放密钥文件
        /data
            /input    - 存放待签名的原始文件
            /signed   - 存放生成的签名文件(.sig)
    
    每个空目录会创建.gitkeep文件以保持目录结构
    """
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
    """
    设置GUI基本样式和布局
    设置内容：
    1. 按钮和标签的字体和填充
    2. 文本输入框的字体
    3. 窗口大小和位置（居中显示）
    4. 窗口缩放属性
    """
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
    """
    运行图形界面
    1. 创建必要的项目目录结构
    2. 初始化主窗口和样式
    3. 创建SM2GUI实例并启动主循环
    4. 捕获和处理异常
    """
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
    """
    主函数，处理命令行参数或启动GUI
    支持的命令行参数：
    --gui: 启动图形界面（默认选项）
    
    如果没有参数，默认启动图形界面
    """
    parser = argparse.ArgumentParser(description='SM2签名验证系统')
    parser.add_argument('--gui', action='store_true', help='启动图形界面')
    
    args = parser.parse_args()
    
    if args.gui or len(sys.argv) == 1:
        run_gui()

if __name__ == "__main__":
    main()