class Blocks:
    __slots__ = ("_block", "_buffer")

    def __init__(self, block):
        self._block = block

        self._buffer = bytearray()

    def update(self, data):
        block = self._block

        buffer = self._buffer

        start = 0

        if buffer:
            start = min(block - len(buffer), len(data))

            buffer += data[:start]

            if len(buffer) < block:
                return

            self._process(buffer, 0)

            buffer.clear()

        end = len(data) - (len(data) - start) % block

        for offset in range(start, end, block):
            self._process(data, offset)

        buffer += data[end:]
