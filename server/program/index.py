import hashlib
import time

import data

VERSION = "0.0.3"

if __name__ == '__main__':
    print("This is a test program.")
    print(f"Program version {VERSION}")

    print(f"\nData size: {len(data.data)} chars")
    print(f"Num words in data: {data.data.count(' ') + 1}")

    hash_object = hashlib.sha256(data.data.encode())
    print(f"Data SHA256: {hash_object.hexdigest()}")

    # do something

    count = 0

    while True:
        time.sleep(1)
        print(f"Program counting {count}.")
        count += 1
