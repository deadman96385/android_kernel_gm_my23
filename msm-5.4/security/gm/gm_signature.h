/*
 * Copyright © 2021 General Motors Co open.source@gm.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; version 2.0
 * of the License or any later version. This library is distributed in
 * the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License 2 for more details.
 *
 * The source for this package can be downloaded at:
 * https://www.oss.gm.com/GMNA/7E7/IVAIVD
 *
 */

#define ECRYPTFS_DEFAULT_KEY_BYTES 16

#define KEY_LOOKUP_CREATE          0x01
#define KEY_LOOKUP_FOR_UNLINK      0x04
#define KEY_WRITE                  0x04
#define KEY_SEARCH                 0x08

#define GM_DEFAULT_HASH            "sha256"
#define GM_KEYRING_TYPE            "user"
#define GM_SALT                    "8f3f25c455aa7fec"
#define GM_SALT_LEN                32
#define GM_PROTO_KEY_LEN           32
#define GM_HASH_SIZE               32
#define GM_MSG_SIZE                256
#define GM_MAX_NUM_MAP_ENTRY       16

extern void key_type_put(struct key_type *ktype);
extern struct key_type *key_type_lookup(const char *type);
extern key_ref_t lookup_user_key(key_serial_t id, unsigned long flags, key_perm_t perm);
extern long keyctl_setperm_key(key_serial_t, key_perm_t);
extern long keyctl_read_key(key_serial_t key, char *buffer, size_t buflen);

struct kv_pair {
    char* key;
    char* value;
};
