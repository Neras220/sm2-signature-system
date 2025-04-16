from sm2_core import SM2
from gmssl import sm2 as gmssl_sm2

# 初始化参数
sm2 = SM2()
Px, Py = sm2.PBx, sm2.PBy
Gx, Gy = sm2.Gx, sm2.Gy
n = sm2.n

# 选取几个随机k进行对比
k_list = [1, 2, 3, 10, 100, 123456, n-1]

private_key = sm2.hex(sm2.d)
public_key = sm2.hex(Px) + sm2.hex(Py)
sm2_crypt = gmssl_sm2.CryptSM2(public_key=public_key, private_key=private_key)

print("对比multiPoint(椭圆曲线标量乘法)结果：")
for k in k_list:
    # 自实现
    my_point = sm2.multiPoint([Gx, Gy], k)
    # gmssl实现
    gmssl_point = sm2_crypt._kg(k, sm2_crypt.ecc_table['g'])
    gmssl_x = int(gmssl_point[0:64], 16)
    gmssl_y = int(gmssl_point[64:], 16)
    print(f"k={k}")
    print(f"  自实现: x={hex(my_point[0])}\ny={hex(my_point[1])}")
    print(f"  gmssl:  x={hex(gmssl_x)}\ny={hex(gmssl_y)}")
    print(f"  是否一致: {my_point[0]==gmssl_x and my_point[1]==gmssl_y}")
    print("-")

# 对比点加法
print("\n对比addPoint(椭圆曲线点加法)结果：")
points = [
    ([Gx, Gy], [Px, Py]),
    ([Gx, Gy], [Gx, Gy]),
    ([Px, Py], [Px, Py]),
]
for P, Q in points:
    my_add = sm2.addPoint(P, Q)
    # gmssl点加法用kg模拟：P+Q = kg(1,P)+kg(1,Q)
    # 这里只对比自实现和gmssl的multiPoint(1,P)+multiPoint(1,Q)
    # gmssl没有直接暴露点加法接口
    print(f"P=({hex(P[0])}, {hex(P[1])})\nQ=({hex(Q[0])}, {hex(Q[1])})")
    print(f"  自实现: x={hex(my_add[0]) if my_add else None}\ny={hex(my_add[1]) if my_add else None}")
    # gmssl没有直接点加法接口，略
    print("-")

print("\n如需更详细对比，可补充更多k和点对。")
