from typing import Tuple
from gost_hash256 import hash_function


def hex_block_to_int(hex_block: str) -> int:
    """
    Получает многострочную запись числа из ГОСТ (с пробелами),
    возвращает целое.
    """
    compact = hex_block.replace(' ', '').replace('\n', '')
    return int(compact, 16)


# --- ПАРАМЕТРЫ ГРУППЫ ---
p_block = """
EE8172AE 8996608F B69359B8 9EB82A69
854510E2 977A4D63 BC97322C E5DC3386
EA0A12B3 43E9190F 23177539 84583978
6BB0C345 D165976E F2195EC9 B1C379E3
"""

q_block = """
98915E7E C8265EDF CDA31E88 F24809DD
B064BDC7 285DD50D 7289F0AC 6F49DD2D
"""

a_block = """
9E960315 00C8774A 869582D4 AFDE2127
AFAD2538 B4B6270A 6F7C8837 B50D50F2
06755984 A49E5093 04D648BE 2AB5AAB1
8EBE2CD4 6AC3D849 5B142AA6 CE23E21C
"""

p = hex_block_to_int(p_block)
q = hex_block_to_int(q_block)
g = hex_block_to_int(a_block)  # «a» в тексте стандарта — это генератор g


class SchnorrKey:
    """
    Ключ и методы подписи/проверки для схемы Шнорра «key-prefixed», описанной в задании.
    Закрытый ключ x выбран случайно из [1, q-1].
    Открытый ключ P = g^x mod p.
    """

    def __init__(self, prng) -> None:
        """
        Генерация ключа:
          prng — экземпляр ГПСЧ (они возвращают 32 байта).
        """
        # Секретный ключ x ∈ [1, q−1]
        rnd = prng.next()                   # 32 байта
        self.x = int.from_bytes(rnd, 'big') % (q - 1) + 1  # прибавляем 1, чтобы гарантировать x ненулевое.

        # Параметры группы
        self.p = p
        self.q = q
        self.g = g

        # Открытый ключ
        self.P = pow(self.g, self.x, self.p)

    def sign(self, message: bytes, prng) -> Tuple[int, int]:
        """
        Подписывает сообщение message, возвращает пару (R, s):

          1) выбираем r ∈ [1, q−1] при помощи prng
          2) R = g ^ r mod p
          3) e = hash_function(R||P||message) mod q
          4) s = (r + x * e) mod q
        """
        # 1) выбор случайного r
        rnd = prng.next()
        r = int.from_bytes(rnd, 'big') % (self.q - 1) + 1

        # 2) вычисление R
        R = pow(self.g, r, self.p)

        # 3) вычисление e = H(R || P || m) mod q
        R_bytes = R.to_bytes((self.p.bit_length() + 7)//8, 'big')
        P_bytes = self.P.to_bytes((self.p.bit_length() + 7)//8, 'big')
        e = int.from_bytes(hash_function(R_bytes + P_bytes + message), 'big') % self.q

        # 4) вычисление s
        s = (r + self.x * e) % self.q

        return R, s

    def verify(self, message: bytes, signature: Tuple[int, int]) -> bool:
        """
        Проверяет подпись signature=(R, s) на сообщении message.
        Условие корректности:
          g^s mod p == R * P^e mod p,
        где e = hash_function(R||P||message) mod q
        """
        R, s = signature

        # Пересчитываем e так же, как при подписи
        R_bytes = R.to_bytes((self.p.bit_length() + 7)//8, 'big')
        P_bytes = self.P.to_bytes((self.p.bit_length() + 7)//8, 'big')
        e = int.from_bytes(hash_function(R_bytes + P_bytes + message), 'big') % self.q

        # Слева: g^s
        lhs = pow(self.g, s, self.p)
        # Справа: R * P^e
        rhs = (R * pow(self.P, e, self.p)) % self.p

        return lhs == rhs


# Тестовый пример:
if __name__ == "__main__":
    from prng import PRNG
    prng = PRNG("Мухаметзянов Данис и Медведева Виктория")
    key = SchnorrKey(prng)
    msg = b"Hello my friend!"
    sig = key.sign(msg, prng)
    print(sig)
    assert key.verify(msg, sig), "Подпись не прошла верификацию"
