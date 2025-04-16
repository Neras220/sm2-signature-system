# SM2 签名验证系统

基于国密SM2算法的数字签名系统，提供完整的GUI界面，支持密钥管理、文件签名和签名验证功能。

## 功能特点

- 完整实现SM2椭圆曲线数字签名算法
- 图形化界面，易于使用
- 支持密钥对的生成、导入和导出
- 支持文件签名和签名验证
- 兼容国密标准SM2和SM3算法

## 系统要求

- Python 3.8+
- tkinter (GUI库)
- gmssl (国密算法库)

## 安装说明

1. 克隆仓库
```bash
git clone https://github.com/Neras220/sm2-signature-system.git
cd sm2-signature-system
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

## 使用方法

1. 运行程序
```bash
cd src
python main.py
```

2. 在GUI界面中：
   - "密钥管理"标签页：管理SM2密钥对
   - "签名"标签页：对文件进行签名
   - "验证"标签页：验证文件签名

## 目录结构

```
src/
├── assets/         - 资源文件
│   └── keys/       - 密钥存储
├── data/
│   ├── input/      - 待签名文件
│   └── signed/     - 签名后的文件
└── logs/           - 日志文件
```

## 主要文件说明

- `main.py`: 程序入口
- `sm2_core.py`: SM2算法核心实现
- `sm2_gui.py`: 图形界面实现
- `test_*.py`: 测试文件

## 注意事项

- 请妥善保管私钥文件
- 建议定期备份重要的签名文件
- 验证签名时需要确保使用正确的公钥

## 开发相关

本项目遵循以下开发规范：
- 使用Python标准库和gmssl实现SM2算法
- 采用面向对象的设计方法
- 提供完整的单元测试
- 代码注释完整，便于维护

## 许可证

MIT License