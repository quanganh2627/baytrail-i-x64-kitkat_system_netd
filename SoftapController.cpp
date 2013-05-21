/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <fcntl.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <cutils/properties.h>
#include <netutils/ifc.h>
#include <private/android_filesystem_config.h>
#include "wifi.h"

#include "SoftapController.h"

/* for ANDROID_SOCKET_* */
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <linux/un.h>

static const char *ENV_SOCKET[32];

static const char HOSTAPD_CONF_FILE[]    = "/data/misc/wifi/hostapd.conf";

SoftapController::SoftapController() {
    mPid = 0;
    mSock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mSock < 0)
        ALOGE("Failed to open socket");
}

SoftapController::~SoftapController() {
    if (mSock >= 0)
        close(mSock);
}

int SoftapController::startDriver(char *iface) {
    int ret;

    ALOGD("Softap driver start");

    if (!iface || (iface[0] == '\0')) {
        ALOGE("Softap driver start - wrong interface");
        return -EINVAL;
    }

    ifc_init();
    ret = ifc_up(iface);
    ifc_close();

    usleep(AP_DRIVER_START_DELAY);

    return ret;
}

int SoftapController::stopDriver(char *iface) {
    int ret;

    ALOGD("Softap driver stop");

    if (!iface || (iface[0] == '\0')) {
        ALOGE("Softap driver stop - wrong interface");
	return -EINVAL;
    }

    ifc_init();
    ret = ifc_down(iface);
    ifc_close();

    return ret;
}

int SoftapController::startSoftap() {
    pid_t pid = 1;
    int ret = 0;
    int fd;

    if (mPid) {
        ALOGE("Softap already started");
        return 0;
    }
    if (mSock < 0) {
        ALOGE("Softap startap - failed to open socket");
        return -1;
    }

    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {
        ensure_entropy_file_exists();

        fd = create_socket("wpa_wlan1", SOCK_DGRAM, 0666, 0, 0);
        if (fd >= 0) {
           publish_socket("wpa_wlan1", fd);
        }

        if (execle("/system/bin/hostapd", "/system/bin/hostapd",
                  "-e", WIFI_ENTROPY_FILE,
                  HOSTAPD_CONF_FILE, (char *) NULL, (char**)ENV_SOCKET)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        return -1;
    } else {
        mPid = pid;
        ALOGD("Softap startap - Ok");
        usleep(AP_BSS_START_DELAY);
    }
    return ret;

}

int SoftapController::stopSoftap() {

    if (mPid == 0) {
        ALOGE("Softap already stopped");
        return 0;
    }

    ALOGD("Stopping Softap service");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);

    if (mSock < 0) {
        ALOGE("Softap stopap - failed to open socket");
        return -1;
    }
    mPid = 0;
    ALOGD("Softap service stopped");
    usleep(AP_BSS_STOP_DELAY);
    return 0;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0 ? true : false);
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - SSID
 *	argv[4] - Security
 *	argv[5] - Key
 *	argv[6] - Channel
 *	argv[7] - Preamble
 *	argv[8] - Max SCB
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    int ret = 0, i = 0, fd;
    char *ssid, *iface;

    if (mSock < 0) {
        ALOGE("Softap set - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        ALOGE("Softap set - missing arguments");
        return -1;
    }

    iface = argv[2];

    char *wbuf = NULL;
    char *fbuf = NULL;

    if (argc > 3) {
        ssid = argv[3];
    } else {
        ssid = (char *)"AndroidAP";
    }

    char ap_channel_s[10];
    int ap_channel = 6;
    property_get("wifi.ap.channel", ap_channel_s, "6");
    ap_channel = atoi(ap_channel_s);

    asprintf(&wbuf, "interface=%s\ndriver=nl80211\nctrl_interface="
            "wlan1\nssid=%s\nchannel=%d\n",
            iface, ssid, ap_channel);

    if (argc > 4) {
        if (!strcmp(argv[4], "wpa-psk")) {
            generatePsk(ssid, argv[5], psk_str);
            asprintf(&fbuf, "%swpa=1\nwpa_pairwise=TKIP CCMP\nwpa_psk=%s\n", wbuf, psk_str);
        } else if (!strcmp(argv[4], "wpa2-psk")) {
            generatePsk(ssid, argv[5], psk_str);
            asprintf(&fbuf, "%swpa=2\nrsn_pairwise=CCMP\nwpa_psk=%s\n", wbuf, psk_str);
        } else if (!strcmp(argv[4], "open")) {
            asprintf(&fbuf, "%s", wbuf);
        }
    } else {
        asprintf(&fbuf, "%s", wbuf);
    }

    fd = open(HOSTAPD_CONF_FILE, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, 0660);
    if (fd < 0) {
        ALOGE("Cannot update \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        free(wbuf);
        free(fbuf);
        return -1;
    }
    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        ALOGE("Cannot write to \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        ret = -1;
    }
    free(wbuf);
    free(fbuf);

    /* Note: apparently open can fail to set permissions correctly at times */
    if (fchmod(fd, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    if (fchown(fd, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    close(fd);
    return ret;
}

void SoftapController::generatePsk(char *ssid, char *passphrase, char *psk_str) {
    unsigned char psk[SHA256_DIGEST_LENGTH];
    int j;
    // Use the PKCS#5 PBKDF2 with 4096 iterations
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase),
            reinterpret_cast<const unsigned char *>(ssid), strlen(ssid),
            4096, SHA256_DIGEST_LENGTH, psk);
    for (j=0; j < SHA256_DIGEST_LENGTH; j++) {
        sprintf(&psk_str[j<<1], "%02x", psk[j]);
    }
    psk_str[j<<1] = '\0';
}


/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    int i = 0;
    char *fwpath;

    if (mSock < 0) {
        ALOGE("Softap fwrealod - failed to open socket");
        return -1;
    }
    if (argc < 4) {
        ALOGE("Softap fwreload - missing arguments");
        return -1;
    }

    if (!strcmp("STA", argv[3]))
        wifi_switch_driver_mode(WIFI_STA_MODE); /* which is STA + P2P... */
    else if (!strcmp("AP", argv[3]))
        wifi_switch_driver_mode(WIFI_AP_MODE);
    else if (!strcmp("P2P", argv[3]))
        wifi_switch_driver_mode(WIFI_P2P_MODE);

    ALOGD("Softap fwReload - done");

    return 0;
}

int SoftapController::clientsSoftap(char **retbuf)
{
    /* TODO: implement over hostapd */
    return 0;
}

/*
 * create_socket - creates a Unix domain socket in ANDROID_SOCKET_DIR
 * ("/dev/socket"). This socket is inherited by the
 * daemon. We communicate the file descriptor's value via the environment
 * variable ANDROID_SOCKET_ENV_PREFIX<name> ("ANDROID_SOCKET_foo").
 */
int SoftapController::create_socket(const char *name, int type, mode_t perm, uid_t uid, gid_t gid)
{
    struct sockaddr_un addr;
    int fd, ret;
#ifdef HAVE_SELINUX
    char *secon;
#endif

    fd = socket(PF_UNIX, type, 0);
    if (fd < 0) {
        ALOGE("Failed to open socket '%s': %s\n", name, strerror(errno));
        return -1;
    }

    memset(&addr, 0 , sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), ANDROID_SOCKET_DIR"/%s",
             name);

    ret = unlink(addr.sun_path);
    if (ret != 0 && errno != ENOENT) {
        ALOGE("Failed to unlink old socket '%s': %s\n", name, strerror(errno));
        goto out_close;
    }

#ifdef HAVE_SELINUX
    secon = NULL;
    if (sehandle) {
        ret = selabel_lookup(sehandle, &secon, addr.sun_path, S_IFSOCK);
        if (ret == 0)
            setfscreatecon(secon);
    }
#endif

    ret = bind(fd, (struct sockaddr *) &addr, sizeof (addr));
    if (ret) {
        ALOGE("Failed to bind socket '%s': %s\n", name, strerror(errno));
        goto out_unlink;
    }
#ifdef HAVE_SELINUX
    setfscreatecon(NULL);
    freecon(secon);
#endif
    chown(addr.sun_path, uid, gid);
    chmod(addr.sun_path, perm);

    ALOGD("Created socket '%s' with mode '%o', user '%d', group '%d'\n",
         addr.sun_path, perm, uid, gid);

    return fd;

out_unlink:
    unlink(addr.sun_path);
out_close:
    close(fd);
    return -1;
}

void SoftapController::publish_socket(const char *name, int fd)
{
    char key[64] = ANDROID_SOCKET_ENV_PREFIX;
    char val[64];

    strlcpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
            name,
            sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
    snprintf(val, sizeof(val), "%d", fd);
    add_environment(key, val);

    /* make sure we don't close-on-exec */
    fcntl(fd, F_SETFD, 0);
}

/* add_environment - add "key=value" to the current environment */
int SoftapController::add_environment(const char *key, const char *val)
{
    int n;

    for (n = 0; n < 31; n++) {
        if (!ENV_SOCKET[n]) {
            size_t len = strlen(key) + strlen(val) + 2;
            char *entry = (char *)malloc(len);
            snprintf(entry, len, "%s=%s", key, val);
            ENV_SOCKET[n] = entry;
            return 0;
        }
    }
    return 1;
}
