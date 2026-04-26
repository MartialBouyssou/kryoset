from kryoset.core.quota import QuotaManager
from kryoset.core.storage_manager import StorageManager
test_cases = [0, 512, 1024, 1048576, 1073741824, 1099511627776]
for b in test_cases:
    formatted_quota = QuotaManager._format_bytes(b)
    formatted_storage = StorageManager._format_bytes(b)
    print(f'{b} bytes -> QuotaManager: {formatted_quota}, StorageManager: {formatted_storage}')
