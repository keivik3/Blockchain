# Нелинейное биективное преобразование (S-подстановка). (см. п. 5.2)
P = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
]

# Перестановка байтов TAU: 64-элементный массив (см. п. 5.3)
TAU = [
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33, 41, 49, 57,
    2, 10, 18, 26, 34, 42, 50, 58,
    3, 11, 19, 27, 35, 43, 51, 59,
    4, 12, 20, 28, 36, 44, 52, 60,
    5, 13, 21, 29, 37, 45, 53, 61,
    6, 14, 22, 30, 38, 46, 54, 62,
    7, 15, 23, 31, 39, 47, 55, 63
]

# Константы для линейного преобразования L: матрица A задана 64 словами по 64 бита (в двоичном GF(2)).
# Их приводят в стандарте как шестнадцатеричные строки в п. 5.4
A = [
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083
]

# Итерационные константы C1 ... C12 (каждая константа – 512 бит = 64 байта)
# Эти двенадцать 64-байтовых констант заданы в стандарте (см. пункт 5.5).
C = [
    bytes.fromhex("b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc"
                  "4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507"),
    bytes.fromhex("6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b50131"
                  "9ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7"),
    bytes.fromhex("f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7b"
                  "d3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2"),
    bytes.fromhex("ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353f"
                  "a9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e"),
    bytes.fromhex("4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbd"
                  "bfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57"),
    bytes.fromhex("ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6"
                  "cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e"),
    bytes.fromhex("f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c9"
                  "0992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493"),
    bytes.fromhex("9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49a"
                  "f4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e"),
    bytes.fromhex("378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984"
                  "800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb"),
    bytes.fromhex("abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b336103"
                  "9fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced"),
    bytes.fromhex("7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab07612001802114846679"
                  "8a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b"),
    bytes.fromhex("378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b"
                  "5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720")
]


def lps_transform(state: bytes) -> bytes:
    """
    Объединённое преобразование LPS (см. раздел 6, формула (8)):
    1) S-преобразование: замена каждого байта по P
    2) P-преобразование: перестановка по таблице τ (TAU)
    3) L-преобразование: линейное умножение GF(2) через константы A

    Принимает 64 байта, возвращает 64 байта.
    """
    assert len(state) == 64
    # S-преобразование
    s = bytes(P[b] for b in state)
    #print(f"____________SX[K(m)]__________: {s.hex()}")
    # P-преобразование
    internal = bytearray(64)
    for i in range(64):
        internal[i] = s[TAU[i]]
    p = bytes(internal)
    #print(f"____________PSX[K(m)]__________: {p.hex()}")
    # L-преобразование
    out_words = [0] * 8
    for i in range(8):
        acc = 0
        # читаем слово big-endian
        word = int.from_bytes(p[i * 8:(i + 1) * 8], 'big')
        # для каждого бита, справа-налево (63..0)
        for bit in range(63, -1, -1):
            if (word >> bit) & 1:
                acc ^= A[63 - bit]
        out_words[i] = acc
    res = bytearray(64)
    for i, w in enumerate(out_words):
        res[i * 8:(i + 1) * 8] = w.to_bytes(8, 'big')
    return bytes(res)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Вспомогательная функция: побайтное XOR двух одинаковых по длине байтовых строк.
    """
    return bytes(x ^ y for x, y in zip(a, b))


def add_512(a: bytes, b: bytes) -> bytes:
    """
    Сложение двух 512-битных чисел (каждое 64 байта) по модулю 2^512 (см. раздел 7, п. 7).
    a, b — 64-байта (big-endian). Возвращаем 64-байта (big-endian).
    """
    ai = int.from_bytes(a, 'big')
    bi = int.from_bytes(b, 'big')
    return ((ai + bi) & ((1 << 512) - 1)).to_bytes(64, 'big')


def g_func(h: bytes, N: bytes, m: bytes) -> bytes:
    # начальный ключ
    K_1 = lps_transform(xor_bytes(h, N))
    #print(f"\nРаунд 1\nРаундовый ключ K_1: {K_1.hex()}")
    # первый раунд
    #print(f"____________X[K_1(m)]__________: {xor_bytes(m, K_1).hex()}")
    X = lps_transform(xor_bytes(m, K_1))
    #print(f"LPSX[K_1](m): {X.hex()}")
    # Оставшиеся 12 раундов
    K_i = K_1
    for i in range(11):
        #print(f"\nРаунд {i + 2}")
        # Подготовка раундового ключа Ki = LPS(Ki ⊕ C[i])
        K_i = lps_transform(xor_bytes(K_i, C[i]))
        #print(f"Раундовый ключ K_{i + 2}: {K_i.hex()}")
        # Обновление X = LPS(X ⊕ Ki)
        X = lps_transform(xor_bytes(X, K_i))
        #print(f"____________LPSX[K_{i + 2}](m)__________: {X.hex()}")

    # Завершающий этап функции сжатия (раунд 13)
    #print("\nРаунд 13")
    K_i = lps_transform(xor_bytes(K_i, C[11]))
    #print(f"Раундовый ключ K_{13}: {K_i.hex()})")
    X = xor_bytes(X, K_i)
    #print(f"____________X[K_{13}](m)__________: {X.hex()}")
    first_xor = xor_bytes(X, h)
    new_h = xor_bytes(first_xor, m)
    #print(f"\nИтоговый h после выполнения функции g_N(h, m): {new_h.hex()}")
    return new_h


def pad512(data: bytearray) -> bytes:
    # Паддиннг происходит верно для сообщения длиной до 512 бит.
    bit_len = len(data) * 8
    if bit_len == 512:
        return data[:]  # уже ровно 512 бит

    # Сколько бит нужно дописать слева перед единицей
    pad_bits = 512 - bit_len - 1
    # Сколько полных байт нулей
    pad_bytes = pad_bits // 8
    # Сколько дополнительных нулевых бит в следующем байте перед '1'
    pad_bits_rem = pad_bits % 8
    # Построим результат: pad_bytes нулевых байт, байт-маркер с одним битом '1', затем всё data
    marker = 1 << (7 - pad_bits_rem)  # единица в нужной позиции в этом байте

    out = bytearray()
    out.extend(b'\x00' * pad_bytes)
    out.append(marker)
    out.extend(data)

    # Длина out должна быть ровно 64 байта
    assert len(out) % 64 == 0, f"Неверная длина паддинга: {len(out)} байт, ожидалось кратное 64"
    return bytes(out)


def hash_function(data: bytes) -> bytes:
    """
    Функция хэширования. На вход подаётся байтовая переменная data.
    Возвращает 32 байта (младшие 256 бит итогового h).
    """
    # Производим инициализацию.
    h = b'\x01' * 64  # Текущий хэш. Присваиваем ему значение инициализационного вектора
    N = b'\x00' * 64  #
    sigma = b'\x00' * 64  # Контрольная сумма

    # Список длин изначальных блоков
    length_of_original_blocks = list()

    # Корректный padding: если не кратно 64 байтам,
    # только последний фрагмент дополняем до 64
    rem = len(data) % 64
    if rem == 0:
        padded_message = data
        for _ in range (len(data) // 64):
            length_of_original_blocks.append(512)
    elif len(data) * 8 < 512:
        padded_message = pad512(bytearray(data))
        length_of_original_blocks.append(len(data) * 8)
    else:
        full_blocks = data[rem:]  # все полные 64-байтовые блоки
        head = data[:rem]  # неполный левый блок
        #print(full_blocks.hex)
        #print(head.hex())
        length_of_original_blocks.append(len(head) * 8)
        for _ in range(len(full_blocks) // 64):
            length_of_original_blocks.append(512)
        #print(length_of_original_blocks)
        padded_head = pad512(bytearray(head))
        padded_message = padded_head + full_blocks
    assert len(padded_message) % 64 == 0

    number_of_blocks = len(padded_message) // 64
    #print(number_of_blocks)
    count_of_length = 0
    for i in range(number_of_blocks - 1, -1, -1):
        if number_of_blocks == 1:
            block = padded_message[0:64]
        else:
            start = i * 64
            end = start + 64
            block = padded_message[start:end]
            #print("We use this block: ", block.hex())
            #print(block, start, end)

        h = g_func(h, N, block)
        length_of_block = length_of_original_blocks[i]
        N = add_512(N, ((length_of_block).to_bytes(64, 'big')))
        #print(length_of_original_blocks[i], count_of_length * 512)

        #print("New N is: ", N.hex())
        sigma = add_512(sigma, block)
        #print("sigma: ", sigma.hex())
        count_of_length += 1

    #   Первый финальный раунд: используем накопленное N
    h = g_func(h, b'\x00' * 64, N)
    #   Второй финальный раунд: N = 0, m = σ
    h = g_func(h, b'\x00' * 64, sigma)
    return h[:32]


# Тестовый пример:
if __name__ == "__main__":
    # На вход подаётся переменная в байтах.
    # Пусть это М - message.
    message = bytes.fromhex("32313039383736353433323130393837363534333231303938373635343332"
     "3130393837363534333231303938373635343332313039383736353433323130")
    hash_code = hash_function(message).hex()
    print("\nПолучившийся хэш-код программной реализации: ", hash_code)
