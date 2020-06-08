import numpy as np

# Referenced: https://stackoverflow.com/questions/7133885/fastest-way-to-grow-a-numpy-numeric-array


class PktArray:

    def __init__(self, mtu):
        self.data = np.zeros((1000, mtu), dtype=np.uint8)
        self.capacity = 1000
        self.size = 0
        self.mtu = mtu

    def add(self, x):
        if self.size == self.capacity:
            self.capacity *= 4
            newdata = np.zeros((self.capacity, self.mtu))
            newdata[:self.size] = self.data
            self.data = newdata

        if len(x) <= self.mtu:
            self.data[self.size][:len(x)] = x
        else:
            self.data[self.size] = x[:self.mtu]
        self.size += 1

    def finalize(self):
        data = self.data[:self.size]
        return data
