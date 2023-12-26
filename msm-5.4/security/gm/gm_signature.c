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

#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/syscalls.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/ecryptfs.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/semaphore.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <crypto/hash.h>

#include "gm_signature.h"

#define GM_NL_GET_IDENTIFIER    "getIdentifier"
#define GM_NL_GET_PASSCODE      "getPasscode"
#define GM_NL_SET_KEY           "setKey"
#define GM_NL_REMOVE_KEY        "removeKey"
#define GM_NL_PROTO_KEY_UPDATED "proto-key-updated"
#define GM_NL_SERVICE_READY     "ready"
#define GM_NL_ERROR_RESPONSE    "ERROR"

#define GM_STATE_KEY_NOT_SET    0
#define GM_STATE_KEY_SET        1
#define GM_MAX_WAIT_PID         5

/*
 * Global variables.
 */
static DEFINE_MUTEX(gm_nl_lock);
static const char* __MODULE__ = "gm_signature";

static char proto_key[GM_PROTO_KEY_LEN] = {0};
static struct kv_pair* map[GM_MAX_NUM_MAP_ENTRY] = {0};
static int data_locked = 1;
static int waiting_pids[GM_MAX_WAIT_PID] = {0};
static struct sock *nl_socket = 0;
static int key_state = GM_STATE_KEY_NOT_SET;

/*
 * Transfer byte array to hex array.
 */
static void gm_bytes_to_hex(char *hex, const char *data, const int len)
{
    int i;
    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    for (i = 0; i < len; i++) {
        unsigned char c = data[i];
        *hex++ = '0' + ((c&0xf0)>>4) + (c>=0xa0)*('a'-'9'-1);
        *hex++ = '0' + (c&0x0f) + ((c&0x0f)>=0x0a)*('a'-'9'-1);
    }
    *hex = '\0';
}

static void gm_hex_to_bytes(char *data, const char *hex, const int len)
{
    int count = 0;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    for (count = 0; count < len; count++) {
        char h[3];
        // For unknown reason, sscanf cannot read from constant variable correctly.
        // So copy the data to a stack array first.
        h[0] = hex[count*2];
        h[1] = hex[count*2+1];
        h[2] = 0;
        sscanf(h, "%2hhx", data + count);
    }
}

static int is_zero_array(const char *data, const int len)
{
    int i;
    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    for (i = 0; i < len; i++) {
        if (data[i]) {
            return 0;
        }
    }

    return 1;
}

static void gm_map_add(const char* key, const int key_len, const char* value, const int value_len)
{
    int i;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    for (i = 0; i < GM_MAX_NUM_MAP_ENTRY; i++) {
        if (!map[i]) {
            struct kv_pair* npair = kmalloc(sizeof(struct kv_pair), GFP_KERNEL);
            npair->key = kmemdup(key, key_len, GFP_KERNEL);
            npair->value = kmemdup(value, value_len, GFP_KERNEL);
            map[i] = npair;
            return;
        }
    }
}

static void gm_map_remove(const char* key, const int key_len)
{
    int i;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    for (i = 0; i < GM_MAX_NUM_MAP_ENTRY; i++) {
        if (map[i] && !memcmp(map[i]->key, key, key_len)) {
            map[i] = 0;
        }
    }
}

static char* gm_map_lookup(const char* key, const int key_len)
{
    int i;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    for (i = 0; i < GM_MAX_NUM_MAP_ENTRY; i++) {
        if (map[i] && !memcmp(map[i]->key, key, key_len)) {
            return map[i]->value;
        }
    }

    return 0;
}

static int gm_add_waiting_pid(int pid)
{
    int i;

    for (i = 0; i < GM_MAX_WAIT_PID; i++)
    {
        if (waiting_pids[i] == pid) {
            return 1;
        }
    }

    for (i = 0; i < GM_MAX_WAIT_PID; i++)
    {
        if (waiting_pids[i] == 0) {
            waiting_pids[i] = pid;
            return 1;
        }
    }

    printk(KERN_DEBUG "%s: Too many waiting pids. Ignoring %d\n", __MODULE__, pid);
    return 0;
}

/*
 * Generate sha256 hash from length of src len.
 * Add salt before hashing if salt is not 0
 * dst is preallocated.
 */
static int gm_signature_hash(char *dst, const char *src, const int len, const char* salt, const int slen)
{
    struct crypto_shash *tfm;
    char* ss = 0;
    int rc;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    tfm = crypto_alloc_shash(GM_DEFAULT_HASH, 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
        rc = PTR_ERR(tfm);
        printk(KERN_ERR "%s: Error attempting to "
                "allocate crypto context; rc = [%d]\n", __MODULE__,
                rc);
        rc = -ENOMEM;
        goto out;
    }
    else {
        SHASH_DESC_ON_STACK(desc, tfm);
        desc->tfm = tfm;

        ss = kmalloc(len + slen, GFP_KERNEL);
        if (!ss) {
            printk(KERN_ERR
                    "%s: %s out of memory.\n",
                    __MODULE__, __func__);
            rc = -ENOMEM;
            goto out;
        }

        memcpy(ss, src, len);
        if (salt && slen) {
            memcpy(ss+len, salt, slen);
        }

        rc = crypto_shash_digest(desc, ss, len+slen, dst);
        shash_desc_zero(desc);
        if (rc) {
            printk(KERN_ERR "%s: Error computing crypto hash; rc = [%d]\n",
                    __MODULE__, rc);
            goto out;
        }

    }

out:
    if (ss) {
        kfree(ss);
    }

    return rc;
}

/*
 * Remove the fekek with given signature from keyring.
 */
static int gm_remove_fekek(const char* signature)
{
    struct key_type *ktype;
    key_ref_t keyring_ref, key_ref;
    int rc = 0;
    char signature_hex[ECRYPTFS_SIG_SIZE*2+1] = {0};

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    keyring_ref = lookup_user_key(KEY_SPEC_USER_KEYRING, 0, KEY_SEARCH);
    if (IS_ERR(keyring_ref)) {
        rc = (int)PTR_ERR(keyring_ref);
        goto error1;
    }

    ktype = key_type_lookup(GM_KEYRING_TYPE);
    if (IS_ERR(ktype)) {
        rc = (int)PTR_ERR(ktype);
        goto error2;
    }

    gm_bytes_to_hex(signature_hex, signature, ECRYPTFS_SIG_SIZE);

    key_ref = keyring_search(keyring_ref, ktype, signature_hex, true);
    key_type_put(ktype);

    if (IS_ERR(key_ref)) {
        printk(KERN_ERR
                "%s: %s key & sig pair not found [%s]\n",
                __MODULE__, __func__, signature_hex);
        goto error2;
    }

    /* Remove key from the target keyring */
    key_ref_put(keyring_ref);
    keyring_ref = lookup_user_key(KEY_SPEC_USER_KEYRING,
            KEY_LOOKUP_FOR_UNLINK, KEY_WRITE);
    if (IS_ERR(keyring_ref)) {
        printk(KERN_ERR
                "%s: %s failed to get keying to write.\n",
                __MODULE__, __func__);
        rc = (int)PTR_ERR(keyring_ref);
        key_ref_put(key_ref);
        goto error1;
    }

    rc = key_unlink(key_ref_to_ptr(keyring_ref), key_ref_to_ptr(key_ref));
    key_ref_put(key_ref);

error2:
    key_ref_put(keyring_ref);

error1:
    return rc;
}

/*
 * Generate a fekek from proto_key and the salt.
 * Install the signature and fekek into keyring.
 * Both fekek and signature are in binary form.
 */
static int gm_install_fekek(const char* signature, const char* fekek)
{
    struct key_type *ktype;
    key_ref_t keyring_ref, key_ref;
    struct ecryptfs_auth_tok auth_tok;
    int rc = 0;
    char signature_hex[ECRYPTFS_SIG_SIZE*2+1] = {0};

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    keyring_ref = lookup_user_key(KEY_SPEC_USER_KEYRING, 0, KEY_SEARCH);
    if (IS_ERR(keyring_ref)) {
        rc = (int)PTR_ERR(keyring_ref);
        goto error1;
    }

    ktype = key_type_lookup(GM_KEYRING_TYPE);
    if (IS_ERR(ktype)) {
        rc = (int)PTR_ERR(ktype);
        goto error2;
    }

    gm_bytes_to_hex(signature_hex, signature, ECRYPTFS_SIG_SIZE);

    key_ref = keyring_search(keyring_ref, ktype, signature_hex, true);
    key_type_put(ktype);

    if (!IS_ERR(key_ref)) {
        printk(KERN_ERR
                "%s: %s key & sig pair inserted already [%s]\n",
                __MODULE__, __func__, signature_hex);
        goto error2;
    }

    memset(&auth_tok, 0, sizeof(struct ecryptfs_auth_tok));
    auth_tok.version = (((uint16_t)(ECRYPTFS_VERSION_MAJOR << 8) & 0xFF00) |
            ((uint16_t)ECRYPTFS_VERSION_MINOR & 0x00FF));
    auth_tok.token_type = ECRYPTFS_PASSWORD;
    memcpy(auth_tok.token.password.salt, GM_SALT,
            ECRYPTFS_SALT_SIZE);
    memcpy(auth_tok.token.password.session_key_encryption_key, fekek,
            ECRYPTFS_DEFAULT_KEY_BYTES);
    auth_tok.token.password.session_key_encryption_key_bytes =
        ECRYPTFS_DEFAULT_KEY_BYTES;
    auth_tok.token.password.flags |=
        ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET;
    auth_tok.token.password.flags &=
        ~(ECRYPTFS_PERSISTENT_PASSWORD);

    strncpy((char *)auth_tok.token.password.signature, signature_hex,
            ECRYPTFS_PASSWORD_SIG_SIZE+1);

    /* add key to the target keyring */
    key_ref_put(keyring_ref);
    keyring_ref = lookup_user_key(KEY_SPEC_USER_KEYRING,
            KEY_LOOKUP_CREATE, KEY_WRITE);
    if (IS_ERR(keyring_ref)) {
        printk(KERN_ERR
                "%s: %s failed to get keying to write.\n",
                __MODULE__, __func__);
        rc = (int)PTR_ERR(keyring_ref);
        goto error1;
    }

    key_ref = key_create_or_update(keyring_ref,
            GM_KEYRING_TYPE, signature_hex,
            &auth_tok, sizeof(struct ecryptfs_auth_tok),
            KEY_PERM_UNDEF, KEY_ALLOC_IN_QUOTA);
    if (IS_ERR(key_ref)) {
        rc = (int)PTR_ERR(key_ref);
        printk(KERN_ERR
                "%s: %s failed to add key & sig pair (%d).\n",
                __MODULE__, __func__, rc);
        goto error2;
    }

    rc = (int) keyctl_setperm_key(key_ref_to_ptr(key_ref)->serial,
            (key_perm_t)(KEY_USR_SEARCH|KEY_USR_ALL));
    if (rc == -EINVAL) {
        printk(KERN_ERR "%s: %s Unable to set key permission\n", __MODULE__, __func__);
    }

    key_ref_put(key_ref);

error2:
    key_ref_put(keyring_ref);

error1:
    return rc;
}

/*
 * Generate a fekek from protokey and salt.
 * salt is in binary format.
 * Length of the salt should be equal to GM_SALT_LEN.
 * Generated fekek and signature are in binary format, both size is GM_HASH_SIZE.
 */
static int gm_gen_key(const char *salt, char* signature, char* key)
{
    int rc = 0;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    if (gm_signature_hash(key, proto_key, GM_PROTO_KEY_LEN, salt, GM_SALT_LEN)) {
        printk(KERN_ERR "%s: %s invalid data.\n", __MODULE__, __func__);
        rc = -EINVAL;
        return rc;
    }

    if(signature) {
        if (gm_signature_hash(signature, key, GM_HASH_SIZE, salt, GM_SALT_LEN) ) {
            printk(KERN_ERR "%s: %s invalid fekek.\n", __MODULE__, __func__);
            rc = -EINVAL;
            return rc;
        }
    }

    return rc;
}

/*
 * message format:
 * 1st byte                             -- command length
 * 2nd -> cmd_len byte                  -- command
 * cmd_len+2 byte                       -- data length
 * cmd_len+3 -> cmd_len + data_len + 3  -- data
 * return 0 if parse fails, 1 successful
 */
static int gm_nl_parse_msg(const char* msg, char* cmd, int* cmd_len, char* data, int* data_len)
{
    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    *cmd_len = msg[0];
    if (*cmd_len + 1 >= GM_MSG_SIZE) {
        return 0;
    }

    memcpy(cmd, &msg[1], *cmd_len);
    *data_len = msg[*cmd_len + 1];
    if (*data_len > 0) {
        if (*data_len + *cmd_len + 2 >= GM_MSG_SIZE) {
            return 0;
        }
        memcpy(data, &msg[*cmd_len + 2], *data_len);
    }

    return 1;
}

static int gm_nl_unicast(int pid, const char* msg, const int len)
{
    struct nlmsghdr *nlh;
    struct sk_buff *sig_out;
    int res;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    sig_out = nlmsg_new(len, 0);

    if (!sig_out)
    {
        printk(KERN_ERR "%s: %s Failed to allocate new skb\n", __MODULE__, __func__);
        return 0;
    }
    nlh = nlmsg_put(sig_out, 0, 0, NLMSG_DONE, len, 0);
    NETLINK_CB(sig_out).dst_group = 0; /* not in mcast group */

    if (msg) {
        strncpy(nlmsg_data(nlh), msg, len);
    }
    else {
        char zeros[GM_MSG_SIZE] = {0};
        strncpy(nlmsg_data(nlh), zeros, len);
    }

    res = nlmsg_unicast(nl_socket, sig_out, pid); // nlmsg_free not required after unicast

    if (res < 0) {
        printk(KERN_ERR "%s: %s Error while sending back to user\n", __MODULE__, __func__);
        return 0;
    }

    return 1;
}

static void gm_nl_update_state(void)
{
    int i;
    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);
    for (i = 0; i < GM_MAX_WAIT_PID; i++) {
        int pid = waiting_pids[i];
        if (pid != 0) {
            waiting_pids[i] = 0;
            gm_nl_unicast(pid, GM_NL_PROTO_KEY_UPDATED, strlen(GM_NL_PROTO_KEY_UPDATED));
            printk(KERN_DEBUG "%s: Notified client for protokey. Port ID: %d\n", __MODULE__, pid);
        }
    }
    printk(KERN_DEBUG "%s: Notified %d client(s) for protokey.\n", __MODULE__, i);
}

/*
 * netlink callback method when receve messages from the listeneing socket.
 */
static void gm_nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    char cmd[GM_MSG_SIZE+1] = {0};
    char data[GM_MSG_SIZE+1] = {0};
    int cmd_len, data_len;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    mutex_lock(&gm_nl_lock);

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /*port id of sending process */

    if (gm_nl_parse_msg(nlmsg_data(nlh), cmd, &cmd_len, data, &data_len)) {
        printk(KERN_DEBUG "%s: Netlink recevied message: %s\n", __MODULE__, cmd);

        // Called by the waiting processes.
        if (!strncmp(GM_NL_SERVICE_READY, cmd, strlen(GM_NL_SERVICE_READY))) {

            if (key_state == GM_STATE_KEY_SET) {
                gm_nl_unicast(pid, GM_NL_PROTO_KEY_UPDATED, strlen(GM_NL_PROTO_KEY_UPDATED));
            }
            else {
                gm_add_waiting_pid(pid);
                // else send response later when key is updated.
            }
            goto RET;
        }

        // Called by gm_protokey.
        if (!strncmp(GM_NL_SET_KEY, cmd, strlen(GM_NL_SET_KEY))) {
            if (key_state == GM_STATE_KEY_NOT_SET) {
                char proto_key_hex[GM_PROTO_KEY_LEN*2+1] = {0};

                strncpy(proto_key_hex, data, data_len);
                gm_hex_to_bytes(proto_key, proto_key_hex, GM_PROTO_KEY_LEN);
                if(!is_zero_array(proto_key, GM_PROTO_KEY_LEN)) {
                    key_state = GM_STATE_KEY_SET;
                    gm_nl_update_state();
                }
            }
            goto RET;
        }

        if (!strncmp(GM_NL_GET_IDENTIFIER, cmd, strlen(GM_NL_GET_IDENTIFIER))) {
            if (data_locked) {
                if(is_zero_array(proto_key, GM_PROTO_KEY_LEN)) {
                    printk(KERN_DEBUG "%s: proto-key not yet set, staying in data_locked mode.\n", __MODULE__);
                    gm_nl_unicast(pid, 0, ECRYPTFS_PASSWORD_SIG_SIZE);
                }
                else {
                    printk(KERN_DEBUG "%s: proto-key has been set, leaving data_locked mode.\n", __MODULE__);
                    data_locked = 0;
                }
            }

            if (!data_locked) {
                char salt[GM_PROTO_KEY_LEN] = {0};
                char fekek[GM_HASH_SIZE] = {0};
                char signature[GM_HASH_SIZE] = {0};
                char signature_hex[GM_HASH_SIZE*2+1] = {0};
                int len = data_len>GM_PROTO_KEY_LEN?GM_PROTO_KEY_LEN:data_len;
                char *signature_lookup = gm_map_lookup(data, len);

                if (signature_lookup) {
                    gm_bytes_to_hex(signature_hex, signature_lookup, GM_HASH_SIZE);
                }
                else {
                    gm_hex_to_bytes(salt, data, len);

                    gm_gen_key(salt, signature, fekek);
                    gm_install_fekek(signature, fekek);
                    gm_map_add(data, len, signature, GM_HASH_SIZE);

                    gm_bytes_to_hex(signature_hex, signature, GM_HASH_SIZE);
                }
                gm_nl_unicast(pid, signature_hex, ECRYPTFS_PASSWORD_SIG_SIZE);
            }
            goto RET;
        }

        if (!strncmp(GM_NL_REMOVE_KEY, cmd, strlen(GM_NL_REMOVE_KEY))) {
            int len = data_len>GM_PROTO_KEY_LEN?GM_PROTO_KEY_LEN:data_len;
            char *signature_lookup = gm_map_lookup(data, len);

            if (signature_lookup) {
                gm_remove_fekek(signature_lookup);
                gm_map_remove(data, len);
                printk(KERN_DEBUG "%s: %s fekek removed \n", __MODULE__, __func__);
            }
            else {
                printk(KERN_DEBUG "%s: %s fekek not found \n", __MODULE__, __func__);
            }
            goto RET;
        }

        if (!strncmp(GM_NL_GET_PASSCODE, cmd, strlen(GM_NL_GET_PASSCODE))) {
            if (data_locked) {
                printk(KERN_DEBUG "%s: %s proto-key retrieved\n", __MODULE__, __func__);
                if(is_zero_array(proto_key, GM_PROTO_KEY_LEN)) {
                    printk(KERN_DEBUG "%s: proto-key not yet set, stay in data_locked mode.\n", __MODULE__);
                    gm_nl_unicast(pid, 0, ECRYPTFS_PASSWORD_SIG_SIZE);
                }
                else {
                    printk(KERN_DEBUG "%s: proto-key has been set, leaving data_locked mode.\n", __MODULE__);
                    data_locked = 0;
                }
            }

            if (!data_locked) {
                char salt[GM_PROTO_KEY_LEN] = {0};
                char passcode[GM_HASH_SIZE] = {0};
                char passcode_hex[GM_HASH_SIZE*2+1] = {0};

                int len = data_len>GM_PROTO_KEY_LEN?GM_PROTO_KEY_LEN:data_len;
                char *passcode_lookup = gm_map_lookup(data, len);

                if (passcode_lookup) {
                    gm_bytes_to_hex(passcode_hex, passcode_lookup, GM_HASH_SIZE);
                }
                else {
                    gm_hex_to_bytes(salt, data, len);

                    gm_gen_key(salt, 0, passcode);
                    gm_map_add(data, len, passcode, GM_HASH_SIZE);

                    gm_bytes_to_hex(passcode_hex, passcode, GM_HASH_SIZE);
                }
                gm_nl_unicast(pid, passcode_hex, ECRYPTFS_PASSWORD_SIG_SIZE);
            }

            goto RET;
        }
    }

    printk(KERN_DEBUG "%s: unable to parse incoming message\n", __MODULE__);
    gm_nl_unicast(pid, GM_NL_ERROR_RESPONSE, strlen(GM_NL_ERROR_RESPONSE));

RET:
    mutex_unlock(&gm_nl_lock);
}

/*
 * Initialize the netlink socket.
 */
static int __init gm_nl_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = gm_nl_recv_msg
    };

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    nl_socket = netlink_kernel_create(&init_net, NETLINK_GM_ENCRYPTION, &cfg);

    if (!nl_socket) {
        printk(KERN_ERR "%s: %s Error creating socket.\n", __MODULE__, __func__);
        return -EINVAL;
    }

    return 0;
}

/*
 * clean up when netlink socket is closed.
 */
static void __exit gm_nl_exit(void)
{
    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);
    netlink_kernel_release(nl_socket);
}

static
int __init gm_signature_init(void) {
    int rc;

    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    if (key_state == GM_STATE_KEY_NOT_SET) {
        printk(KERN_DEBUG "%s: proto-key not yet set, staying in data_locked mode.\n", __MODULE__);
    }
    else {
        printk(KERN_DEBUG "%s: proto-key has been set, leaving data_locked mode.\n", __MODULE__);
        data_locked = 0;
    }

    rc = gm_nl_init();

    return rc;
}

static
void __exit gm_signature_exit (void) {
    int i;
    printk(KERN_DEBUG "%s: Entering %s\n", __MODULE__, __func__);

    gm_nl_exit();

    for (i = 0; i < GM_MAX_NUM_MAP_ENTRY; i++) {
        if (map[i]) {
            if (map[i]->key) {
                kfree(map[i]->key);
            }
            if (map[i]->value) {
                kfree(map[i]->value);
            }
            kfree(map[i]);
        }
    }
}

MODULE_AUTHOR("GM");
MODULE_DESCRIPTION("GM PROTO_KEY signature support.");
MODULE_VERSION("0.1");

late_initcall(gm_signature_init);
module_exit(gm_signature_exit);
