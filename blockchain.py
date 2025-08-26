import time
import struct
from gost_hash256 import hash_function
from signature import SchnorrKey
from prng import PRNG


class Transaction:
    def __init__(self,
                 payload: bytes,
                 schnorr_key: SchnorrKey,
                 prng: PRNG):
        """
        payload: «полезная нагрузка» транзакции в виде байтов (напр. b"Alice->Bob:10")
        schnorr_key: экземпляр вашего SchnorrKey (в нём хранится x и P)
        prng: генератор псевдослучайных чисел, из которого берутся nonces
        """
        self.payload = payload

        # 1) Подпишем payload с помощью key-prefixed Schnorr:
        #    метод sign() возвращает два целых: R и s.
        (R_int, s_int) = schnorr_key.sign(self.payload, prng)

        # 2) Превратим R и s в фиксированное байтовое представление
        #    Длину в байтах L определим по p (размер ключа) —
        #    чтобы вмещалось любое число < p:
        p = schnorr_key.p
        L = (p.bit_length() + 7) // 8  # число байт, необходимое для p

        # R и s должны лежать в диапазонах [0..p-1] и [0..q-1] соответственно,
        # но мы храним их в ровно L байтов (младшие байты числа, big-endian):
        R_bytes = R_int.to_bytes(L, byteorder='big')
        s_bytes = s_int.to_bytes(L, byteorder='big')

        # 3) Сохраним подпись в поле объекта:
        #    будем хранить просто конкатенацию R||s
        self.signature = R_bytes + s_bytes

    def serialize(self) -> bytes:
        """
        Сериализует payload и подпись:
        байты payload ∥ байты подписи (R||s).
        """
        return self.payload + self.signature

    def hash(self) -> bytes:
        """
        Возвращает 256‑битный хэш всей транзакции (payload + подпись).
        """
        return hash_function(self.serialize())


# Merkle tree computation
def merkle_root(tx_hashes: list[bytes]) -> bytes:
    """
    Строит корень дерева Меркла по хэшам транзакций.
    - При нечётном числе хэшей последний дублируется.
    - Рекурсивно объединяются пары и хэшируются.
    """
    if not tx_hashes:
        # return b"" * 32
        return bytes(32) # корень пустого дерева — 32 нулевых байта
    current = tx_hashes[:]
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
            else:
                # дублируем последний
                right = left
            next_level.append(hash_function(left + right))
        current = next_level
    return current[0]


# Block header structure
class BlockHeader:
    def __init__(self, size: int, prev_hash: bytes, merkle_root: bytes, timestamp: int, nonce: int):
        """
        Представляет заголовок блока.
        - size: количество транзакций
        - prev_hash: хэш предыдущего блока
        - merkle_root: корень дерева Меркла
        - timestamp: временная метка (4 байта)
        - nonce: число для майнинга
        """
        self.size = size  # 4-byte int
        self.prev_hash = prev_hash  # 32-byte
        self.merkle_root = merkle_root  # 32-byte
        self.timestamp = timestamp  # 4-byte fields: hour, day, month, year
        self.nonce = nonce  # 4-byte int

    def serialize(self) -> bytes:
        """
        Сериализует заголовок в байты:
        включает все поля строго по заданному формату.
        """
        # Pack size
        data = struct.pack('>I', self.size)
        # Append previous hash
        data += self.prev_hash
        # Append merkle root
        data += self.merkle_root
        # Timestamp: hour, day, month, year (each 1 byte)
        hour = (self.timestamp >> 24) & 0xFF
        day = (self.timestamp >> 16) & 0xFF
        month = (self.timestamp >> 8) & 0xFF
        year = self.timestamp & 0xFF
        data += struct.pack('BBBB', hour, day, month, year)
        # Append nonce
        data += struct.pack('>I', self.nonce)
        return data

    def hash(self) -> bytes:
        """
        Возвращает хэш заголовка блока.
        """
        return hash_function(self.serialize())


# Block containing header and transactions
class Block:
    def __init__(self, prev_hash: bytes, transactions: list[Transaction]):
        """
        Представляет блок:
        - хэширует все транзакции;
        - формирует корень дерева Меркла;
        - создает заголовок с нулевым nonce.
        """
        # Compute transaction hashes
        tx_hashes = [tx.hash() for tx in transactions]
        # Compute merkle root
        root = merkle_root(tx_hashes)
        # Block size: placeholder 4 non-zero bytes, here number of tx
        self.size = len(transactions)
        # Timestamp: pack current hour-day-month-year into 4 bytes
        t = time.localtime()
        timestamp = (t.tm_hour << 24) | (t.tm_mday << 16) | (t.tm_mon << 8) | (t.tm_year % 256)
        # Initialize header with nonce=0
        self.header = BlockHeader(self.size, prev_hash, root, timestamp, nonce=0)
        self.transactions = transactions

    def mine(self, target_bits: int = 5) -> bytes:
        """
        Производит майнинг блока:
        - подбирает nonce, чтобы первые target_bits хэша заголовка были нулями.
        """
        max_nonce = 2 ** 32 - 1
        for nonce in range(max_nonce):
            self.header.nonce = nonce
            h = self.header.hash()
            # Check if first target_bits bits are zero
            if h[0] >> (8 - target_bits) == 0:
                print(f"Block mined: nonce={nonce}, hash={h.hex()}")
                return h
        raise RuntimeError("Не удалось найти nonce")


# Blockchain chain
class Blockchain:
    def __init__(self):
        """
        Инициализирует блокчейн:
        - создаёт ГПСЧ и SchnorrKey;
        - создает генезис-блок (с заглушкой payload=b"Genesis");
        - добавляет в цепочку.
        """
        # --- Создаём PRNG с каким‑либо seed-строкой (например, "Фамилия Имя")
        # Чтобы при каждом старте программы seed был детерминирован (но не нулевой).
        self.prng = PRNG("Mukhametzianov and Medvedeva")

        # Инициализируем SchnorrKey (генерируется x, P)
        self.schnorr_key = SchnorrKey(self.prng)

        # --- Генерируем 256 бит (32 байта) случайного prev_hash для генезис-блока
        genesis_prev = self.prng.next()

        # Список транзакций‐заглушек для генезис‐блока:
        # теперь передаём в Transaction и schnorr_key, и prng,
        # чтобы он сразу подписал сам payload=b"Genesis".
        genesis_tx = [
            Transaction(b"Genesis", self.schnorr_key, self.prng)]

        # --- Формируем и «добываем» (майним) генезис-блок
        genesis_block = Block(genesis_prev, genesis_tx)
        genesis_hash = genesis_block.mine()

        # --- Сохраняем цепочку в виде списка кортежей (блок, его собственный хэш)
        self.chain = [(genesis_block, genesis_hash)]

    def add_block(self, transactions: list[Transaction]):
        """
        Добавляет новый блок к цепочке.
        """
        prev_hash = self.chain[-1][1]
        block = Block(prev_hash, transactions)
        block_hash = block.mine()
        self.chain.append((block, block_hash))


def generate_payloads():
    """
    Генерирует 5 payload-ов по 200 байт:
    - первые 4 — случайные;
    - пятый содержит ФИО + дополнение до 200 байт.
    """
    payloads = []
    fio_prng = PRNG("Mukhametzianov and Medvedeva")
    accidentally_prng = PRNG("")
    for i in range(4):
        # Для первых 4 транзакций: сразу соберём 200 случайных байт
        data_temp = b""
        while len(data_temp) < 200:
            data_temp += accidentally_prng.next()
        payloads.append(data_temp[:200])
    # Пятая транзакция: записываем ФИО студента в UTF-8,
    # затем дополняем случайными байтами или обрезаем ровно до 200 байт.
    data_temp = b""
    while len(data_temp) < 200:
        data_temp += fio_prng.next()
    payloads.append(data_temp[:200])
    return payloads


def print_block_header(header: BlockHeader):
    """
    Печатает содержимое заголовка блока в человекочитаемом виде.
    """
    hour = (header.timestamp >> 24) & 0xFF
    day = (header.timestamp >> 16) & 0xFF
    month = (header.timestamp >> 8) & 0xFF
    year = header.timestamp & 0xFF

    print("BlockHeader:")
    print(f"  Size         : {header.size} txs")
    print(f"  Prev Hash    : {header.prev_hash.hex()}")
    print(f"  Merkle Root  : {header.merkle_root.hex()}")
    print(f"  Timestamp    : {day:02d}.{month:02d}.20{year:02d} {hour:02d}:00")
    print(f"  Nonce        : {header.nonce}")


if __name__ == "__main__":
    # Генерируем данные для 5 транзакций
    payloads = generate_payloads()
    # Создаём блокчейн
    bc = Blockchain()
    # Формируем транзакции, подписываем
    txs = [
        Transaction(payloads[0], bc.schnorr_key, bc.prng),
        Transaction(payloads[1], bc.schnorr_key, bc.prng),
        Transaction(payloads[2], bc.schnorr_key, bc.prng),
        Transaction(payloads[3], bc.schnorr_key, bc.prng),
        Transaction(payloads[4], bc.schnorr_key, bc.prng)
    ]

    # Добавляем новый блок с этими подписанными транзакциями
    bc.add_block(txs)

    print(f"Blockchain length: {len(bc.chain)}")
    # Теперь в блокчейне два блока (генезис + новый),
    # и каждая транзакция уже подписана Schnorr‑ключом.

    # Выводим заголовки всех блоков в цепочке
    for i, (block, block_hash) in enumerate(bc.chain):
        print(f"\n=== Block {i} ===")
        print_block_header(block.header)
        print(f"Block Hash: {block_hash.hex()}")
