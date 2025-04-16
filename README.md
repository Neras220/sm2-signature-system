# SM2签名验证系统

基于国密SM2算法的数字签名系统，提供图形化界面进行密钥管理、文件签名和签名验证操作。

## 功能特性

- **密钥管理**
  - 生成SM2密钥对
  - 导入/导出密钥
  - 安全存储密钥信息

- **文件签名**
  - 支持对任意TXT文本文件进行签名
  - 自动计算并显示文件SM3哈希值
  - 生成标准SM2签名
  - 签名信息自动保存

- **签名验证**
  - 验证文件签名的合法性
  - 支持导入.sig签名文件
  - 自动关联原始文件
  - 实时显示验证结果

## 系统要求

- Windows操作系统
- Python 3.7或更高版本
- 推荐显示器分辨率：1920x1080或更高

## 快速开始

### 方式一：直接运行可执行文件

1. 下载最新发布版本
2. 解压到任意目录
3. 运行`SM2签名验证系统.exe`

### 方式二：从源码运行

1. 克隆仓库
```bash
git clone https://github.com/Neras220/sm2-signature-system.git
cd sm2-signature-system
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 运行程序
```bash
python src/launcher.py
```

## 使用教程

### 密钥管理

1. 启动程序后默认会生成新的密钥对
2. 在"密钥管理"页面可以：
   - 查看当前密钥信息
   - 生成新的密钥对
   - 导出密钥备份
   - 导入已有密钥

### 签名文件

1. 切换到"签名"页面
2. 点击"浏览"选择要签名的文本文件
3. 点击"生成签名"
4. 签名文件(.sig)将自动保存到data/signed目录

### 验证签名

1. 切换到"验证"页面
2. 方式一：手动验证
   - 选择原始文件
   - 输入签名值(r,s)和公钥信息
   - 点击"验证签名"

3. 方式二：通过.sig文件验证
   - 点击"签名文件(.sig)"旁的"浏览"按钮
   - 选择.sig文件
   - 系统会自动填充签名信息
   - 点击"验证签名"

## 目录结构

```
sm2-signature-system/
├── src/                    # 源代码目录
│   ├── launcher.py        # 程序入口
│   ├── main.py           # 主程序
│   ├── sm2_core.py       # SM2算法核心实现
│   ├── sm2_gui.py        # 图形界面实现
│   ├── assets/           # 资源文件
│   │   └── keys/        # 密钥存储
│   └── data/            # 数据目录
│       ├── input/       # 待签名文件
│       └── signed/      # 签名后文件
├── requirements.txt      # 项目依赖
└── README.md            # 项目说明
```

## 安全说明

- 私钥文件保存在assets/keys目录下，请妥善保管
- 建议定期备份重要的密钥信息
- 验证签名时确保使用正确的公钥信息
- 所有敏感信息均在本地存储，不会上传到网络

## 版本历史

### v1.0.0 (2025-04-16)
- 初始版本发布
- 实现基本的签名和验证功能
- 提供图形化操作界面

## 技术栈

- Python 3.x
- tkinter (GUI框架)
- gmssl (国密算法实现)

## 作者

- Neras220

## 开源许可

MIT License