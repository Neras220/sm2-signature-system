import hashlib
import math
import random
import sys
import os
from gmssl import sm3, func

class SM2:
    def __init__(self, keyfile_path=None):
        # SM2椭圆曲线推荐参数：
        # y^2 = x^3 + ax + b over Fp
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF  # 有限域的模数
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC  # 椭圆曲线参数a
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93  # 椭圆曲线参数b
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123  # 基点G的阶，用于生成私钥
        self.Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7  # 基点G的x坐标
        self.Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0  # 基点G的y坐标
        self.h = 1  # 余因子，用于辅助计算公钥
        keyfile_path = os.path.join(os.path.dirname(__file__), 'assets', 'keys.txt')
        if os.path.exists(keyfile_path):
            try:
                with open(keyfile_path, 'r') as f:
                    key_hex = f.readline().strip()
                    self.d = int(key_hex, 16)
            except Exception:
                self.setSecretKey(True)
                with open(keyfile_path, 'w') as f:
                    f.write(self.hex(self.d))
        else:
            self.setSecretKey(True)
            with open(keyfile_path, 'w') as f:
                f.write(self.hex(self.d))
        self.PBx, self.PBy = self.multiPoint([self.Gx, self.Gy], self.d)
        print("公钥:({},{})".format(self.hex(self.PBx), self.hex(self.PBy)))
        if self.PBx + self.PBy == 0:
            sys.exit(-1)

    def getInverse(self, a):
        # 在有限域上计算乘法逆元，使用费马小定理：a^(p-2) ≡ a^(-1) (mod p)
        return pow(a, self.p - 2, self.p)

    # 严格实现椭圆曲线加法和标量乘法，支持无穷远点None
    def addPoint(self, P, Q):
        """椭圆曲线点加法实现
        P + Q = R，根据不同情况计算：
        1. 若P或Q为无穷远点，返回另一点
        2. 若P = -Q，返回无穷远点
        3. 若P = Q，使用切线斜率计算
        4. 其他情况使用割线斜率计算
        """
        if P is None:
            return Q
        if Q is None:
            return P
            
        if P[0] == Q[0]:
            # 如果x相同，检查y是否互为相反数
            if (P[1] + Q[1]) % self.p == 0:
                return None  # 得到无穷远点
            if P[1] == Q[1] == 0:
                return None  # 两点都在x轴上
                
        # P ≠ Q 时的斜率计算
        if P != Q:
            if (Q[0] - P[0]) % self.p == 0:
                return None
            # 注意：这里用 Q-P 而不是 P-Q
            l = ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p)) % self.p
        else:
            if P[1] == 0:
                return None
            # P = Q 时的切线斜率
            l = ((3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, self.p)) % self.p
            
        # 计算新点坐标
        x3 = (l * l - P[0] - Q[0]) % self.p
        # y3计算，注意符号
        y3 = (l * (P[0] - x3) - P[1]) % self.p
        
        return (x3, y3)

    def multiPoint(self, P, k):
        """椭圆曲线标量乘法，计算kP
        使用二进制展开法，从高位到低位扫描k的每一位：
        - k的当前位为1，结果加上对应的2^i倍点
        - 每次将点翻倍
        这是SM2算法中最核心的运算
        """
        R = None  # 无穷远点
        Q = P
        while k > 0:
            if k & 1:
                R = self.addPoint(R, Q)
            Q = self.addPoint(Q, Q)
            k >>= 1
        return R

    def hex(self, num):
        num = hex(num).upper()[2:]
        return "0" * (64 - len(num)) + num

    def KDF(self, bitnum, klen):
        Ha = ""
        hs = hashlib.sha256()
        if (klen > (2**32 - 1) * 64):
            print("too long to calculate")
        rct = math.ceil(klen / 64)
        for i in range(rct):
            ct = hex(i + 1).upper()[2:]
            ct = "0" * (32 - len(ct)) + ct
            x2y2ct = bitnum + ct
            hs.update(x2y2ct.encode("utf-8"))
            Ha += hs.hexdigest()
        return Ha[0:klen]

    def setSecretKey(self, show=False):
        self.d = random.randint(1, self.n)
        if show:
            print("私钥为:", self.hex(self.d))

    def set_key_from_file(self, keyfile_path):
        with open(keyfile_path, 'r') as f:
            key_hex = f.readline().strip()
            if not key_hex:
                self.setSecretKey(True)
                self.PBx, self.PBy = self.multiPoint([self.Gx, self.Gy], self.d)
                with open(keyfile_path, 'w') as fw:
                    fw.write(hex(self.d)[2:])
            else:
                self.d = int(key_hex, 16)
                self.PBx, self.PBy = self.multiPoint([self.Gx, self.Gy], self.d)

    def compute_ZA(self, user_id="1234567812345678", Px=None, Py=None):
        """计算用户ZA值
        ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
        其中：
        - ENTLA为用户ID的比特长度
        - IDA为用户的ID
        - a,b为椭圆曲线参数
        - G为基点
        - A为公钥点
        """
        if isinstance(user_id, str):
            user_id = user_id.encode('utf-8')
            
        if Px is None:
            Px = self.PBx
        if Py is None:
            Py = self.PBy
            
        ENTL = len(user_id) * 8
        entl_bytes = ENTL.to_bytes(2, 'big')
        a_bytes = self.a.to_bytes(32, 'big')
        b_bytes = self.b.to_bytes(32, 'big')
        gx_bytes = self.Gx.to_bytes(32, 'big')
        gy_bytes = self.Gy.to_bytes(32, 'big')
        px_bytes = Px.to_bytes(32, 'big')
        py_bytes = Py.to_bytes(32, 'big')
        
        data = (
            entl_bytes + 
            user_id +
            a_bytes +
            b_bytes +
            gx_bytes +
            gy_bytes +
            px_bytes +
            py_bytes
        )
        return sm3.sm3_hash(func.bytes_to_list(data))

    def sign(self, data, user_id="1234567812345678"):
        """SM2签名算法标准实现
        1. 计算ZA和消息M的杂凑值e = H(ZA || M)
        2. 生成随机数k ∈ [1, n-1]
        3. 计算点(x1, y1) = [k]G
        4. 计算r = (e + x1) mod n，若r=0或r+k=n重新生成k
        5. 计算s = ((1 + dA)^(-1) * (k - r*dA)) mod n，若s=0重新生成k
        6. 签名值为(r,s)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        user_id = user_id.encode('utf-8') if isinstance(user_id, str) else user_id
        ZA_hex = self.compute_ZA(user_id=user_id)
        
        # 计算e = H(ZA || M)
        data_to_hash = bytes.fromhex(ZA_hex) + data
        e = int(sm3.sm3_hash(func.bytes_to_list(data_to_hash)), 16)
        
        while True:
            # 1. 生成随机数k ∈ [1, n-1]
            k = random.randint(1, self.n - 1)
            
            # 2. 计算点(x1, y1) = [k]G
            point = self.multiPoint([self.Gx, self.Gy], k)
            x1 = point[0]
            
            # 3. 计算r = (e + x1) mod n
            r = (e + x1) % self.n
            
            # 4. 如果r = 0或r + k = n则返回步骤1
            if r == 0 or r + k == self.n:
                continue
                
            # 5. 计算s = ((1 + dA)^-1 * (k - r * dA)) mod n
            s = (pow(1 + self.d, -1, self.n) * (k - r * self.d)) % self.n
            
            # 6. 如果s = 0则返回步骤1
            if s == 0:
                continue
                
            break
        
        return (r, s)

    def verify(self, data, signature, Px, Py, user_id="1234567812345678"):
        """SM2验签算法标准实现
        1. 验证签名值r,s ∈ [1,n-1]
        2. 计算ZA和消息M的杂凑值e = H(ZA || M)
        3. 计算t = (r + s) mod n，若t=0验证失败
        4. 计算点R = [s]G + [t]PA
        5. 计算R = (e + x1) mod n
        6. 验证R == r
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        user_id = user_id.encode('utf-8') if isinstance(user_id, str) else user_id
        
        r, s = signature
        if isinstance(r, str):
            r = int(r.replace('0x', ''), 16)
        if isinstance(s, str):
            s = int(s.replace('0x', ''), 16)
        
        # 1. 检验r,s是否属于[1,n-1]
        if not (1 <= r < self.n and 1 <= s < self.n):
            print("签名值范围校验失败")
            return False
            
        # 2. 计算M'的杂凑值e
        ZA_hex = self.compute_ZA(user_id=user_id, Px=Px, Py=Py)
        data_to_hash = bytes.fromhex(ZA_hex) + data
        e = int(sm3.sm3_hash(func.bytes_to_list(data_to_hash)), 16)
        
        # 3. 计算t = (r + s) mod n
        t = (r + s) % self.n
        if t == 0:
            return False
            
        # 4. 计算点(x1', y1') = [s]G + [t]PA
        sG = self.multiPoint([self.Gx, self.Gy], s)
        tPA = self.multiPoint([Px, Py], t)
        R = self.addPoint(sG, tPA)
        if R is None:  # 如果得到无穷远点，验证失败
            return False
        x1, y1 = R
        
        # 5. 计算R = (e + x1') mod n
        R = (e + x1) % self.n
        
        # 6. 检验R == r
        return R == r