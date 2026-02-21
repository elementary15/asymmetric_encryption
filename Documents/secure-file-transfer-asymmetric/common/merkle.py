import hashlib
from typing import List

CHUNK_SIZE = 1024

def read_file_chunks(file_path: str, chunk_size: int = CHUNK_SIZE) -> List[bytes]:
    chunks = []
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            chunks.append(chunk)
    return chunks

def hash_chunk(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def build_merkle_root(chunks: List[bytes]) -> str:
    if not chunks:
        raise ValueError("Cannot build Merkle tree with no chunks")

    level = [hash_chunk(chunk) for chunk in chunks]

    while len(level) > 1:
        if len(level) % 2 != 0:
            level.append(level[-1])

        next_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            next_level.append(hashlib.sha256(combined).digest())

        level = next_level

    return level[0].hex()