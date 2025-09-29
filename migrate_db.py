import os
import sqlite3
import base64
import hashlib
import shutil
from typing import Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet


DB_PATH = os.environ.get('DB_PATH', 'database.db')
REQUIRED_SCHEMA_VERSION = '2.0.0'



SERVER_ENCRYPTION_KEY = b'supercell-server-key-2024-secure-encryption-system'


def _server_key_new() -> bytes:
    return hashlib.sha256(SERVER_ENCRYPTION_KEY).digest()


def _derive_new_key(password: str, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode())


def aead_encrypt(plaintext: bytes, key32: bytes) -> bytes:
    aesgcm = AESGCM(key32)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def aead_decrypt(blob: bytes, key32: bytes) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key32)
    return aesgcm.decrypt(nonce, ct, None)


def decrypt_with_old_server_fernet(token: bytes) -> Optional[bytes]:
    try:
        f = Fernet(base64.urlsafe_b64encode(SERVER_ENCRYPTION_KEY[:32]))
        return f.decrypt(token)
    except Exception:
        return None


def decrypt_with_old_data_fernet(encryption_key_raw: bytes, blob: bytes) -> Optional[bytes]:
    try:
        fernet_key = base64.urlsafe_b64encode(encryption_key_raw[:32])
        f = Fernet(fernet_key)
        return f.decrypt(blob)
    except Exception:
        return None


def try_decrypt_new_data(encryption_key_raw: bytes, blob: Optional[bytes]) -> Optional[bytes]:
    if not blob:
        return None
    try:
        key32 = encryption_key_raw if len(encryption_key_raw) == 32 else encryption_key_raw[:32]
        return aead_decrypt(blob, key32)
    except Exception:
        return None


def ensure_metadata(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    conn.commit()


def get_schema_version(conn: sqlite3.Connection) -> Optional[str]:
    cur = conn.cursor()
    try:
        cur.execute('SELECT value FROM metadata WHERE key = ?', ('schema_version',))
        row = cur.fetchone()
        return row[0] if row else None
    except Exception:
        return None


def set_schema_version(conn: sqlite3.Connection, version: str) -> None:
    cur = conn.cursor()
    cur.execute('DELETE FROM metadata WHERE key = ?', ('schema_version',))
    cur.execute('INSERT INTO metadata (key, value) VALUES (?, ?)', ('schema_version', version))
    conn.commit()


def backup_database(src_path: str) -> str:
    backup_path = src_path + '.bak'
    shutil.copy2(src_path, backup_path)
    return backup_path


def column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    cur = conn.cursor()
    cur.execute(f'PRAGMA table_info({table})')
    cols = [r[1] for r in cur.fetchall()]
    return column in cols


def migrate_encryption_keys(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute('SELECT user_id, encryption_key FROM encryption_keys')
    rows = cur.fetchall()
    for user_id, enc_key_blob in rows:
        if enc_key_blob is None:
            continue
        # Try new format first
        try:
            _ = aead_decrypt(enc_key_blob, _server_key_new())
            continue  # already new
        except Exception:
            pass
        # Try old server Fernet
        decrypted = decrypt_with_old_server_fernet(enc_key_blob)
        if decrypted is None:
            continue
        # Re-encrypt with new AES-GCM
        new_blob = aead_encrypt(decrypted, _server_key_new())
        cur.execute('UPDATE encryption_keys SET encryption_key = ? WHERE user_id = ?', (new_blob, user_id))
    conn.commit()


def fetch_user_enc_key(conn: sqlite3.Connection, user_id: int) -> Optional[bytes]:
    cur = conn.cursor()
    cur.execute('SELECT encryption_key FROM encryption_keys WHERE user_id = ?', (user_id,))
    row = cur.fetchone()
    if not row:
        return None
    blob = row[0]
    # Try new decryption
    try:
        return aead_decrypt(blob, _server_key_new())
    except Exception:
        # Try old
        return decrypt_with_old_server_fernet(blob)


def migrate_usernames(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    # Determine columns
    has_plain_username = column_exists(conn, 'users', 'username')
    cur.execute('SELECT id, username_encrypted {} FROM users'.format(', username' if has_plain_username else ''))
    rows = cur.fetchall()
    for row in rows:
        user_id = row[0]
        username_encrypted = row[1]
        username_plain = row[2] if has_plain_username and len(row) > 2 else None
        enc_key = fetch_user_enc_key(conn, user_id)
        if not enc_key:
            continue
        plaintext: Optional[bytes] = None
        # Try new format
        if username_encrypted:
            plaintext = try_decrypt_new_data(enc_key, username_encrypted)
            if plaintext is None:
                # Try old Fernet
                plaintext = decrypt_with_old_data_fernet(enc_key, username_encrypted)
        if plaintext is None and username_plain is not None:
            plaintext = username_plain.encode()
        if plaintext is None:
            continue
        # Re-encrypt with new
        key32 = enc_key if len(enc_key) == 32 else enc_key[:32]
        new_blob = aead_encrypt(plaintext, key32)
        cur.execute('UPDATE users SET username_encrypted = ? WHERE id = ?', (new_blob, user_id))
    conn.commit()


def migrate_passwords(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute('SELECT id, user_id, title_encrypted, username_encrypted, password_encrypted, url_encrypted, notes_encrypted FROM passwords')
    rows = cur.fetchall()
    for pid, user_id, et, eu, ep, eur, en in rows:
        enc_key = fetch_user_enc_key(conn, user_id)
        if not enc_key:
            continue
        key32 = enc_key if len(enc_key) == 32 else enc_key[:32]
        def conv(blob: Optional[bytes]) -> Optional[bytes]:
            if blob is None:
                return None
            # Already new?
            new_plain = try_decrypt_new_data(enc_key, blob)
            if new_plain is not None:
                return blob
            old_plain = decrypt_with_old_data_fernet(enc_key, blob)
            if old_plain is None:
                return blob  # leave as-is if undecipherable
            return aead_encrypt(old_plain, key32)
        new_et = conv(et)
        new_eu = conv(eu)
        new_ep = conv(ep)
        new_eur = conv(eur)
        new_en = conv(en)
        cur.execute('UPDATE passwords SET title_encrypted = ?, username_encrypted = ?, password_encrypted = ?, url_encrypted = ?, notes_encrypted = ? WHERE id = ?',
                    (new_et, new_eu, new_ep, new_eur, new_en, pid))
    conn.commit()


def migrate_files(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.execute('SELECT id, user_id, filename_encrypted, original_filename_encrypted, encrypted_data FROM files')
    rows = cur.fetchall()
    for fid, user_id, fn, ofn, data in rows:
        enc_key = fetch_user_enc_key(conn, user_id)
        if not enc_key:
            continue
        key32 = enc_key if len(enc_key) == 32 else enc_key[:32]
        def conv(blob: Optional[bytes]) -> Optional[bytes]:
            if blob is None:
                return None
            new_plain = try_decrypt_new_data(enc_key, blob)
            if new_plain is not None:
                return blob
            old_plain = decrypt_with_old_data_fernet(enc_key, blob)
            if old_plain is None:
                return blob
            return aead_encrypt(old_plain, key32)
        new_fn = conv(fn)
        new_ofn = conv(ofn)
        new_data = conv(data)
        cur.execute('UPDATE files SET filename_encrypted = ?, original_filename_encrypted = ?, encrypted_data = ? WHERE id = ?',
                    (new_fn, new_ofn, new_data, fid))
    conn.commit()


def main() -> None:
    if not os.path.exists(DB_PATH):
        raise SystemExit(f'Database not found at {DB_PATH}')

    backup = backup_database(DB_PATH)
    print(f'[MIGRATE] Backup created at: {backup}')

    conn = sqlite3.connect(DB_PATH)
    try:
        ensure_metadata(conn)
        current = get_schema_version(conn)
        if current == REQUIRED_SCHEMA_VERSION:
            print('[MIGRATE] Already on required schema version; nothing to do.')
            return

        print('[MIGRATE] Migrating encryption_keys to AES-GCM...')
        migrate_encryption_keys(conn)

        print('[MIGRATE] Migrating usernames to AES-GCM...')
        migrate_usernames(conn)

        print('[MIGRATE] Migrating passwords to AES-GCM...')
        migrate_passwords(conn)

        print('[MIGRATE] Migrating files to AES-GCM...')
        migrate_files(conn)

        set_schema_version(conn, REQUIRED_SCHEMA_VERSION)
        print(f'[MIGRATE] Schema version set to {REQUIRED_SCHEMA_VERSION}')

        print('[MIGRATE] NOTE: users.user_key cannot be migrated without the master password. '
              'Existing users should visit Settings and change their master password to rotate the key into the new format.')
    finally:
        conn.close()


if __name__ == '__main__':
    main()


