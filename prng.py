# Импортируем нашу реализацию ГОСТ-хэша:
from gost_hash256 import hash_function


class PRNG:
    """
    Генератор псевдослучайных чисел:
      - seed_str: строка (имя и фамилия студента) для инициализации h0
      - next() возвращает очередные 32 байта (256 бит) псевдослучайных данных
    """

    def __init__(self, seed_str: str):
        # 1. Кодируем seed_str (Например, Иванов Иван) в байты и дополняем до 64 байт нулями
        seed_bytes = seed_str.encode('utf-8')
        padded = self._pad_or_trim_to_64(seed_bytes)

        # 2. Вычисляем h0 = hash_function(padded_seed)
        #    где hash_function принимает 64 байта и возвращает 32 байта
        self.h0 = hash_function(padded)

        # 3. Счетчик цикла i, начиная с 1
        self._counter = 1

    @staticmethod
    def _pad_or_trim_to_64(data: bytes) -> bytes:
        """
        Дополняет вход до длины 64 байта нулевыми байтами.
        Если вход длиннее 64 — обрезает до первых 64 байт.
        """
        if len(data) >= 64:
            return data[:64]
        return data.ljust(64, b'\x00')

    def next(self) -> bytes:
        """
        Возвращает hi — 32 байта псевдослучайных данных для текущего i.
        Формируется как gost_hash256( h0 ∥ i (4 байта) ∥ padding до 64 байт ).

        При каждом вызове prng.next() мы:
        Формируем блок h0||[i||28 нулей] (64 байта);
        Хэшируем hi = H(...) → получаете 32 байта;
        Увеличиваем _counter;
        Сразу возвращаем весь hi (32 байта);
        Мы никогда не «запоминаем» остаток неиспользованных битов;
        Как только кто‑то взял hi, мы сразу забываем про этот hi и идём к i + 1 при следующем вызове next().
        """
        # 1) Представляем счётчик как 4-байтовое big-endian число
        counter_bytes = self._counter.to_bytes(4, 'big')

        # 2) Формируем 64-байтовый ввод:
        #    h0 (32 байта) ∥ counter_bytes (4 байта) ∥ нули (28 байт)
        data = self.h0 + counter_bytes + b'\x00' * 28

        # 3) Вычисляем hi = gost_hash256(data)
        hi = hash_function(data)

        # 4) Увеличиваем счётчик и возвращаем результат
        self._counter += 1
        return hi


# Тестовый пример:
if __name__ == "__main__":
    prng = PRNG("Мухаметзянов Данис и Медведева Виктория")
    # Первые пять псевдослучайных блоков (32 байта каждый)
    for i in range(5):
        rnd = prng.next()
        print(f"h{i + 1} = {rnd}")


