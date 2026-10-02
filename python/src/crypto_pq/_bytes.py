def view(data):
    return memoryview(data).cast("B")


def equal(a, b):
    if len(a) != len(b):
        return False

    difference = 0

    for x, y in zip(a, b):
        difference |= x ^ y

    return difference == 0
