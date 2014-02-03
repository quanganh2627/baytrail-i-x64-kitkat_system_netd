/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <cutils/properties.h>
#include <libpfkey.h>
#include <netdb.h>

#define LOG_TAG "IpSecController"

#include <cutils/log.h>
#include <logwrap/logwrap.h>

#include "IpSecController.h"
#include "NetdConstants.h"


struct algo_types {
    char * name;
    int id;
};

struct algo_types g_ealgos[] = {
        {"twofish-cbc", SADB_X_EALG_TWOFISHCBC},
        {"aes-cbc", SADB_X_EALG_AESCBC},
        {"3des-cbc", SADB_EALG_3DESCBC},
        {"null", SADB_EALG_NULL},
        {"none", 0},
        {NULL, 0},
};

struct algo_types g_aalgos[] = {
        {"keyed-md5", SADB_AALG_MD5HMAC},
        {"keyed-sha1", SADB_AALG_SHA1HMAC},
        {"null", SADB_X_AALG_NULL},
        {"none", 0},
        {NULL, 0},
};

#define NIBBLE_VALUE(_src_) ( \
        (_src_) >= 'a' && (_src_) <= 'f' ? (_src_) - 'a' + 10 : \
        (_src_) >= 'A' && (_src_) <= 'F' ? (_src_) - 'A' + 10 : \
        (_src_) >= '0' && (_src_) <= '9' ? (_src_) - '0' : 0)

int hex2bin(caddr_t buf, int buflen, const char * src, int srclen) {
    int i;
    ALOGD("buflen : %d, srclen: %d", buflen, srclen);
    if (srclen / 2 > buflen || srclen % 2)
        return -1;

    for(i=0; i < srclen / 2; i++) {
        if (i*2 > srclen)
            return i;
        buf[i] = (NIBBLE_VALUE(src[i*2]) << 4) | (NIBBLE_VALUE(src[i*2+1]));
    }

    return i;
}

/**
 * Copied from external/ipsec-tools/src/racoon/sockmisc.c
 */
struct sockaddr *str2saddr(const char *host, const char *port)
{
    struct addrinfo hints, *res;
    struct sockaddr *saddr;
    int error;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST;
    error = getaddrinfo(host, port, &hints, &res);
    if (error != 0 || res == NULL) {
       ALOGE("getaddrinfo(%s%s%s): %s\n",
               host, port ? "," : "", port ? port : "", gai_strerror(error));
        return NULL;
    }
    if (res->ai_next != NULL) {
        ALOGV("getaddrinfo(%s%s%s): "
              "resolved to multiple address, "
              "taking the first one\n",
              host, port ? "," : "", port ? port : "");
    }
    saddr = (struct sockaddr*)malloc(res->ai_addrlen);
    if (saddr == NULL) {
        ALOGV("failed to allocate buffer.\n");
        freeaddrinfo(res);
        return NULL;
    }
    memcpy(saddr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return saddr;
}

int getAlgoNumeric(struct algo_types * t, const char *str) {
    struct algo_types *ptr = t;
    int ret = -1;
    while(ptr->name != NULL) {
        if (!strcmp(ptr->name, str)) {
            return ptr->id;
        }
        ptr++;
    }
    return ret;
}

IpSecController::IpSecController()  {
    mReqId = 1;
    mSeq = 1;
}

IpSecController::~IpSecController() {
}

int IpSecController::addSA(const char *src, const char *dst,
        const char *ealgo, const char *eKey, const char *aalgo, const char *aKey,
        int spi, const char *type, const char *mode, long time) {

    int result;
    struct sadb_msg *msg = NULL;
    struct sockaddr *srcAddr = NULL;
    struct sockaddr *dstAddr = NULL;
    int l_type = -1;
    int l_mode = -1;
    int so = -1;
    caddr_t keymat = NULL;

    u_int flags = 0;
    u_int32_t l_alloc = 200000000;
    u_int64_t l_bytes = 0;
    u_int64_t l_addtime = ntohl(time);
    u_int64_t l_usetime = ntohl(time);
    u_int wsize = 64;

    int e_type = getAlgoNumeric(g_ealgos, ealgo);
    if (e_type == -1) {
        ALOGE("Encryption algo not found %s.", ealgo);
        return 0;
    }

    int a_type = getAlgoNumeric(g_aalgos, aalgo);
    if (a_type == -1) {
        ALOGE("Authentication algo not found %s.", aalgo);
        return 0;
    }

    if (!strcmp(type, "esp")) {
        l_type = SADB_SATYPE_ESP;
    } else if (!strcmp(type, "ah")) {
        l_type = SADB_SATYPE_AH;
    }
    if (l_type == -1) {
        ALOGE("Type not supported / implemented %s", type);
        return 0;
    }

    if (!strcmp(mode, "transport")) {
        l_mode = IPSEC_MODE_TRANSPORT;
    } else if (!strcmp(mode, "tunnel")) {
        l_mode = IPSEC_MODE_TRANSPORT;
    } else if (!strcmp(mode, "any")) {
        l_mode = IPSEC_MODE_ANY;
    }

    if (l_mode == -1) {
        ALOGE("Mode not supported / implemented %s", mode);
        return 0;
    }

    srcAddr = str2saddr(src, NULL);
    if (srcAddr == NULL) {
        ALOGE("Error parsing source address (%s)", src);
        return 0;
    }
    dstAddr = str2saddr(dst, NULL);
    if (dstAddr == NULL) {
        ALOGE("Error parsing destination address(%s)", dst);
        free(srcAddr);
        return 0;
    }

    ALOGD("Addresses : src : %s dst : %s", src, dst);

    int keylen = 0;
    int e_keylen = 0;
    int a_keylen = 0;
    if (e_type != SADB_EALG_NULL) {
        e_keylen = strlen(eKey)/2;
        keylen += strlen(eKey)/2;
    }
    if (a_type != SADB_X_AALG_NULL) {
        a_keylen = strlen(aKey)/2;
        keylen += a_keylen;
    }
    keymat = (caddr_t)malloc(keylen);


    if (e_type != SADB_EALG_NULL) {
        e_keylen = hex2bin(keymat, e_keylen, eKey, strlen(eKey));
    }

    if (a_type != SADB_X_AALG_NULL) {
        a_keylen = hex2bin(keymat+e_keylen, a_keylen, aKey, strlen(aKey));
    }

    ALOGD("protos: %d:%d %d:%d", e_type, e_keylen, a_type, a_keylen);
    ALOGD("SPI: %d", spi);

    so = pfkey_open();
    ALOGD("Open pfkey_socket : %d", so);
    if (so < 0) {
        ALOGE("Error opening socket.");
        spi = 0;
        goto out;
    }
    result = pfkey_send_add(so, l_type, l_mode, srcAddr, dstAddr,
                            htonl(spi), mReqId, wsize, keymat, e_type, e_keylen, a_type, a_keylen,
                            flags, l_alloc, l_bytes, l_addtime, l_usetime, mSeq++);
    ALOGD("send_add result: %d", result);
    if (result == -1){
            ALOGE("Problem with IPSEC pfkey_send_add: %d %s", result,
                    ipsec_strerror());
            spi = 0;
            goto out;
    }
    msg = pfkey_recv(so);
    if (msg == NULL) {
        ALOGE("No response from pfkey socket");
        spi = 0;
        goto out;
    }
    ALOGD("pfkey_recv: %p seq: %d type: %d errno: %d", msg, msg->sadb_msg_seq,
            msg->sadb_msg_type,
            msg->sadb_msg_errno);
    if (msg->sadb_msg_errno != 0){
            ALOGE("Problem with IPSEC pfkey_send_add: %d", msg->sadb_msg_errno);
            spi = 0;
    }

out:
    if (so >= 0) pfkey_close(so);
    if (srcAddr) free (srcAddr);
    if (dstAddr) free (dstAddr);
    if (keymat) free (keymat);
    if (msg) free(msg);
    return spi;
}

int IpSecController::removeSA(const char *src, const char *dst, int spi, const char *type,
        const char *mode) {
    int result;
    struct sadb_msg *msg = NULL;
    struct sockaddr *srcAddr = NULL;
    struct sockaddr *dstAddr = NULL;
    int l_type = -1;
    int l_mode = -1;
    int so = -1;

    if (!strcmp(type, "esp")) {
        l_type = SADB_SATYPE_ESP;
    } else if (!strcmp(type, "ah")) {
        l_type = SADB_SATYPE_AH;
    }
    if (l_type == -1) {
        ALOGE("Type not supported / implemented %s", type);
        return 0;
    }

    if (!strcmp(mode, "transport")) {
        l_mode = IPSEC_MODE_TRANSPORT;
    } else if (!strcmp(mode, "tunnel")) {
        l_mode = IPSEC_MODE_TRANSPORT;
    } else if (!strcmp(mode, "any")) {
        l_mode = IPSEC_MODE_ANY;
    }

    if (l_mode == -1) {
        ALOGE("Mode not supported / implemented %s", mode);
        return 0;
    }

    srcAddr = str2saddr(src, NULL);
    if (srcAddr == NULL) {
        ALOGE("Error parsing source address (%s)", src);
        return 0;
    }
    dstAddr = str2saddr(dst, NULL);
    if (dstAddr == NULL) {
        ALOGE("Error parsing destination address(%s)", dst);
        free(srcAddr);
        return 0;
    }

    ALOGD("Addresses : src : %s dst : %s", src, dst);
    ALOGD("SPI: %d", spi);

    so = pfkey_open();
    ALOGD("Open pfkey_socket : %d", so);
    if (so < 0) {
        ALOGE("Error opening socket.");
        spi = 0;
        goto out;
    }

    result = pfkey_send_delete(so, l_type, l_mode, srcAddr, dstAddr, htonl(spi));
    ALOGD("send_delete result: %d", result);
    if (result == -1){
            ALOGE("Problem with IPSEC pfkey_send_delete: %d %s", result,
                    ipsec_strerror());
            spi = 0;
            goto out;
    }
    msg = pfkey_recv(so);
    if (msg == NULL) {
        ALOGE("No response from pfkey socket");
        spi = 0;
        goto out;
    }
    ALOGD("pfkey_recv: %p seq: %d type: %d errno: %d", msg, msg->sadb_msg_seq,
            msg->sadb_msg_type,
            msg->sadb_msg_errno);
    if (msg->sadb_msg_errno != 0){
            ALOGE("Problem with IPSEC pfkey_send_delete: %d", msg->sadb_msg_errno);
            return 0;
    }

out:
    if (so >= 0) pfkey_close(so);
    if (srcAddr) free (srcAddr);
    if (dstAddr) free (dstAddr);
    if (msg) free(msg);
    return spi;
}

int IpSecController::addSP(const char *src, int srcport, const char *dst, int dstport,
        const char *protocol, const char *mode, const char *dir, const char *secProtocol,
        long time)
{
    struct sockaddr *srcAddr = NULL;
    struct sockaddr *dstAddr = NULL;
    struct sadb_msg *msg = NULL;
    int ret = 0;
    int key = -1;
    int t_seq;

    struct __attribute__((packed)) {
        struct sadb_x_policy p;
        struct sadb_x_ipsecrequest q;
        char addresses[sizeof(struct sockaddr_storage) * 2];
    } policy;

    ALOGD("AddSP %s[%d] %s[%d] %s %s %s %lu\n", src, srcport, dst, dstport, protocol, mode, dir, time);
    /* Fill values for outbound policy. */
    memset(&policy, 0, sizeof(policy));
    policy.p.sadb_x_policy_exttype = SADB_X_EXT_POLICY;
    policy.p.sadb_x_policy_type = IPSEC_POLICY_IPSEC;
    policy.p.sadb_x_policy_dir = strcmp(dir, "out") ? IPSEC_DIR_INBOUND : IPSEC_DIR_OUTBOUND;
#ifdef HAVE_PFKEY_POLICY_PRIORITY
    policy.p.sadb_x_policy_priority = PRIORITY_DEFAULT;
#endif
    policy.q.sadb_x_ipsecrequest_proto = strcmp(secProtocol, "ah") ? IPPROTO_ESP : IPPROTO_AH;
    policy.q.sadb_x_ipsecrequest_mode =
            strcmp(mode, "tunnel") ? IPSEC_MODE_TRANSPORT : IPSEC_MODE_TUNNEL;
    policy.q.sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE;

    char srcPortStr[8];
    char dstPortStr[8];

    snprintf(srcPortStr, sizeof(srcPortStr), "%d", srcport);
    snprintf(dstPortStr, sizeof(dstPortStr), "%d", dstport);

    srcAddr = str2saddr(src, srcPortStr);
    if (srcAddr == NULL) {
        ALOGE("Error parsing source address (%s)", src);
        return 0;
    }
    dstAddr = str2saddr(dst, dstPortStr);
    if (dstAddr == NULL) {
        ALOGE("Error parsing destination address(%s)", dst);
        free(srcAddr);
        return 0;
    }
    int src_prefix = (srcAddr->sa_family == AF_INET) ? 32 : 128;
    int dst_prefix = src_prefix; //Either all IPV4 or IPV6
    int length = 0;
    int result;

    ALOGD("Addresses : src : %s dst : %s", src, dst);


    int l_proto = -1;
    if (!strcmp(protocol, "tcp")) {
        l_proto = IPPROTO_TCP;
    } else if (!strcmp(protocol, "udp")) {
        l_proto = IPPROTO_UDP;
    } else if (!strcmp(protocol, "any")) {
        l_proto = IPPROTO_RAW;
    } else {
        ALOGE("Unknown protocol: %s", protocol);
        goto out;
    }

    /* Fix lengths. */
    length += sizeof(policy.q);
    policy.q.sadb_x_ipsecrequest_len = length;
    length += sizeof(policy.p);
    policy.p.sadb_x_policy_len = PFKEY_UNIT64(length);

    key = pfkey_open();
    ALOGD("Open pfkey_socket : %d", key);
    if (key < 0) {
        ALOGE("Error opening socket.");
        goto out;
    }

    /* Set policy. */
    result = pfkey_send_spdadd(key, srcAddr, src_prefix, dstAddr, dst_prefix, l_proto,
            (caddr_t)&policy, length, mSeq++);
    if (result <= 0) {
        ALOGE("Cannot set outbound policy (%d)\n", result);
        goto out;
    }

    msg = pfkey_recv(key);
    if (msg == NULL) {
        ALOGE("No response from pfkey socket");
        goto out;
    }

    ALOGD("pfkey_recv: %p seq: %d type: %d errno: %d len: %d pid: %d", msg, msg->sadb_msg_seq,
            msg->sadb_msg_type,
            msg->sadb_msg_errno,
            msg->sadb_msg_len,
            msg->sadb_msg_pid);
    if (msg->sadb_msg_errno == 0){
        caddr_t mhp[SADB_EXT_MAX + 1];

        if (pfkey_align(msg, mhp)) {
            ALOGE("%s", ipsec_strerror());
            goto out;
        }
        if (pfkey_check(mhp)) {
            ALOGE("%s", ipsec_strerror());
            goto out;
        }
        struct sadb_x_policy * pol = (struct sadb_x_policy *) mhp[SADB_X_EXT_POLICY];
        if (pol == NULL) {
            ALOGE("No policy object in pfkey response");
            goto out;
        }
        ALOGD("pid: %d ", pol->sadb_x_policy_id);
        ret = pol->sadb_x_policy_id;
    }

out:
    if (key >= 0) pfkey_close(key);
    if (msg) free(msg);
    if (srcAddr) free(srcAddr);
    if (dstAddr) free(dstAddr);
    return ret;
}

int IpSecController::removeSP(int spi) {
    int so = pfkey_open();
    int ret;
    ALOGD("Open pfkey_socket : %d", so);
    if (so < 0) {
        ALOGE("Error opening socket.");
        return 0;
    }
    ret = pfkey_send_spddelete2(so, spi);

    ALOGD("spddelete2 returns %d\n", ret);
    return ret;
}
