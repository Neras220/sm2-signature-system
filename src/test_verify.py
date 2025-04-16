from sm2_core import SM2
from gmssl import sm3, func, sm2 as gmssl_sm2
import sys
import os

# 获取当前文件所在目录的绝对路径
current_dir = os.path.dirname(os.path.abspath(__file__))
log_file = os.path.join(current_dir, "sm2_debug_log.txt")
test_file = os.path.join(current_dir, "assets", "test1.txt")

sys.stdout = open(log_file, "w", encoding="utf-8")

sm2 = SM2()
Px, Py = sm2.PBx, sm2.PBy

with open(test_file, "rb") as f:
    file_content = f.read()
print("文件内容:", file_content)

# 新高层接口签名，使用标准user_id
r, s = sm2.sign(file_content, user_id="1234567812345678")
print("自实现 r:", sm2.hex(r))
print("自实现 s:", sm2.hex(s))
print("自实现验签结果:", sm2.verify(file_content, (r, s), Px, Py, user_id="1234567812345678"))

# gmssl官方SM2签名/验签
private_key = sm2.hex(sm2.d)
public_key = sm2.hex(sm2.PBx) + sm2.hex(sm2.PBy)
sm2_crypt = gmssl_sm2.CryptSM2(public_key=public_key, private_key=private_key)
gmssl_sign = sm2_crypt.sign(file_content, private_key)
gmssl_r = int(gmssl_sign[:64], 16)
gmssl_s = int(gmssl_sign[64:], 16)
print("gmssl r:", hex(gmssl_r))
print("gmssl s:", hex(gmssl_s))
print("gmssl验签:", sm2_crypt.verify(gmssl_sign, file_content))
# 用自实现验签gmssl签名
gmssl_valid = sm2.verify(file_content, (gmssl_r, gmssl_s), Px, Py, user_id="1234567812345678")
print("自实现验签gmssl签名结果:", gmssl_valid)
