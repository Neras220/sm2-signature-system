import sys
import logging
import traceback
from pathlib import Path
from datetime import datetime
from main import run_gui

VERSION = "1.0.0"

def setup_logging():
    """配置日志"""
    log_dir = Path(sys.executable).parent / 'logs' if getattr(sys, 'frozen', False) else Path(__file__).parent / 'logs'
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f'sm2_app_{datetime.now().strftime("%Y%m%d")}.log'
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

def main():
    """主函数"""
    try:
        # 确保工作目录正确
        exe_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
        sys.path.insert(0, str(exe_dir))
        
        # 设置日志
        setup_logging()
        
        # 记录启动信息
        logging.info(f"SM2签名验证系统 v{VERSION} 启动")
        logging.info(f"工作目录: {exe_dir}")
        
        # 创建必要的目录
        for dir_name in ['assets/keys', 'data/input', 'data/signed']:
            (exe_dir / dir_name).mkdir(parents=True, exist_ok=True)
        
        # 启动GUI
        run_gui()
        
    except Exception as e:
        logging.error(f"程序运行出错: {str(e)}")
        logging.error(traceback.format_exc())
        # 如果是打包后的exe，保持错误窗口
        if getattr(sys, 'frozen', False):
            input("\n程序出错，按回车键退出...")
        sys.exit(1)

if __name__ == "__main__":
    main()