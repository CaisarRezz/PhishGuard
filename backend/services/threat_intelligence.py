from backend.database import get_watchlist_match, get_file_hash_match
from backend.config import DATABASE_PATH

def check_watchlist(target_or_host: str, db_path=DATABASE_PATH):
    return get_watchlist_match(db_path, target_or_host)

def check_file_hash(sha256_hash: str, db_path=DATABASE_PATH):
    return get_file_hash_match(db_path, sha256_hash)
