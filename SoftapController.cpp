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
#include "ResponseCode.h"

#include "SoftapController.h"

/* for ANDROID_SOCKET_* */
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <linux/un.h>

static const char *ENV_SOCKET[32];

static const char HOSTAPD_CONF_FILE[]    = "/data/misc/wifi/hostapd.conf";
static const char HOSTAPD_BIN_FILE[]    = "/system/bin/hostapd";

SoftapController::SoftapController()
    : mPid(0) {}

SoftapController::~SoftapController() {
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
    int fd;

    if (mPid) {
        ALOGE("SoftAP is already running");
        return ResponseCode::SoftapStatusResult;
    }

    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return ResponseCode::ServiceStartFailed;
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
        ALOGE("SoftAP failed to start");
        return ResponseCode::ServiceStartFailed;
    } else {
        mPid = pid;
        ALOGD("SoftAP started successfully");
        usleep(AP_BSS_START_DELAY);
    }
    return ResponseCode::SoftapStatusResult;
}

int SoftapController::stopSoftap() {

    if (mPid == 0) {
        ALOGE("SoftAP is not running");
        return ResponseCode::SoftapStatusResult;
    }

    ALOGD("Stopping the SoftAP service...");
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);

    mPid = 0;
    ALOGD("SoftAP stopped successfully");
    usleep(AP_BSS_STOP_DELAY);
    return ResponseCode::SoftapStatusResult;
}

bool SoftapController::isSoftapStarted() {
    return (mPid != 0);
}

/*
 * Arguments:
 *  argv[2] - wlan interface
 *  argv[3] - SSID
 *  argv[4] - Broadcast/Hidden
 *  argv[5] - Channel
 *  argv[6] - Security
 *  argv[7] - Key
 *  argv[8] - Preamble
 *  argv[9] - Max SCB
 *  argv[10] - channel width (HT20 HT40 or HT80)
 *  argv[11] - country
 */
#define HT20    "HT20"
#define HT40    "HT40"
#define HT80    "HT80"
#define HT80P80 "HT80P80"
#define HT160   "HT160"
int SoftapController::setSoftap(int argc, char *argv[]) {
    char psk_str[2*SHA256_DIGEST_LENGTH+1];
    int ret = ResponseCode::SoftapStatusResult;
    int aret = 0;
    int i = 0;
    int fd = 0;
    char *hw_mode, *country;
    char *channel_width = NULL;
    int ac_support = 0;
    int hidden = 0;
    int channel = AP_CHANNEL_DEFAULT;
    char *wbuf = NULL;
    char *fbuf = NULL;
    char *hbuf = NULL;
    char *vbuf = NULL;

    ALOGD("setsoftap arg count %d, args", argc);
    for (int j = 0; j < argc; j++)
        ALOGD("%s", argv[j]);
    ALOGD("------");

    if (argc < 5) {
        ALOGE("Softap set is missing arguments. Please use:");
        ALOGE("softap <wlan iface> <SSID> <hidden/broadcast> <channel> <wpa2?-psk|open> <passphrase>");
        return ResponseCode::CommandSyntaxError;
    }

    if (!strcasecmp(argv[4], "hidden"))
        hidden = 1;
     
    if (argc >= 5) {
        channel = atoi(argv[5]);
        if (channel <= 0)
            channel = AP_CHANNEL_DEFAULT;
    } else {
        char ap_channel_s[10];
        property_get("wifi.ap.channel", ap_channel_s, "6");
        channel = atoi(ap_channel_s);
    }

    if (argc > 10) {
        channel_width = argv[10];
        if (!strcmp(channel_width, HT80)) {
            ac_support = 1;
        }
    } else
        channel_width = (char*)HT20;

    if (channel < 36)
        hw_mode = (char*)"g";
    else
        hw_mode = (char*)"a";

    if (argc > 11) {
        country = argv[11];
    } else
        country = (char *)"00";



    aret = asprintf(&wbuf, "interface=%s\ndriver=nl80211\nctrl_interface="
            "wlan1\nssid=%s\nchannel=%d\n"
            "hw_mode=%s\nieee80211n=1\nieee80211ac=%d\nignore_broadcast_ssid=%d\n",
             argv[2], argv[3], channel, hw_mode, ac_support, hidden);

    if (aret == -1)
        goto error;

    /* Set HT capabilities*/
    if (!strcmp(channel_width, HT40) || ac_support) {
        /* Supported channel width set: [HT40-] = both 20 MHz and 40 MHz with secondary
         * channel below the primary channel; [HT40+] = both 20 MHz and 40 MHz
         * with secondary channel below the primary channel
         * (20 MHz only if neither is set)
         * Note: There are limits on which channels can be used with HT40- and
         * HT40+. Following table shows the channels that may be available for
         * HT40- and HT40+ use per IEEE 802.11n Annex J:
         * freq                HT40-                HT40+
         * 2.4 GHz             5-13                 1-7 (1-9 in Europe/Japan)
         * 5 GHz               40,48,56,64          36,44,52,60
         * 5 GHz               153, 161             149, 157
         * (depending on the location, not all of these channels may be available
         * for use)
         * Please note that 40 MHz channels may switch their primary and secondary
         * channels if needed or creation of 40 MHz channel maybe rejected based
         * on overlapping BSSes. These changes are done automatically when hostapd
         * is setting up the 40 MHz channel.
         */

        /* Currently Broadcom only support 40Mhz on 5GHz band */
        if ((channel == 36 )
                || (channel == 44 )
                || (channel == 52 )
                || (channel == 60 )
                || (channel == 149)
                || (channel == 157)) {
            aret = asprintf(&hbuf, "%sht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]\n", wbuf);
        } else if ((channel == 40)
                || (channel == 48)
                || (channel == 56)
                || (channel == 64)
                || (channel == 153)
                || (channel == 161)) {
             aret = asprintf(&hbuf, "%sht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]\n", wbuf);
        } else
            aret = asprintf(&hbuf, "%s", wbuf);
    } else
        aret = asprintf(&hbuf, "%s", wbuf);

    if (aret == -1)
        goto error;

    /* Set VHT capabilities if required */
    if (ac_support == 1) {
        /*
         * ToDo: Proper computation of vht_oper_centr_freq_seg0_idx is required.
         * Curently this has been found using FR and US country code.
         * Could have more channel with other country code.
         */
        int vht_chan = 0;
        if ((channel == 36)
                || (channel == 40)
                || (channel == 44)
                || (channel == 48))
            vht_chan = 42;
        if (channel == 144)
            vht_chan = 138;
        if ((channel == 149)
                || (channel == 153)
                || (channel == 157)
                || (channel == 161))
            vht_chan = 155;
        aret = asprintf(&vbuf, "%svht_oper_chwidth=1\nvht_oper_centr_freq_seg0_idx=%d\n"
                        "vht_capab=[SHORT-GI-80]\n", hbuf, vht_chan);
    } else
        aret = asprintf(&vbuf, "%s", hbuf);

    if (aret == -1)
        goto error;

    if (argc > 7) {
        if (!strcmp(argv[6], "wpa-psk")) {
            generatePsk(argv[3], argv[7], psk_str);
            aret = asprintf(&fbuf, "%swpa=1\nwpa_pairwise=TKIP CCMP\nwpa_psk=%s\n", vbuf, psk_str);
        } else if (!strcmp(argv[6], "wpa2-psk")) {
            generatePsk(argv[3], argv[7], psk_str);
            aret = asprintf(&fbuf, "%swpa=2\nrsn_pairwise=CCMP\nwpa_psk=%s\n", vbuf, psk_str);
        } else if (!strcmp(argv[6], "open")) {
            aret = asprintf(&fbuf, "%s", vbuf);
        }
    } else if (argc > 6) {
        if (!strcmp(argv[6], "open")) {
            aret = asprintf(&fbuf, "%s", vbuf);
        }
    } else
        aret = asprintf(&fbuf, "%s", vbuf);

    if (aret == -1)
        goto error;

    ALOGD("hostapd.conf\n%s\n-----", fbuf);

    fd = open(HOSTAPD_CONF_FILE, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW, 0660);
    if (fd < 0) {
        ALOGE("Cannot update \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        free(wbuf);
        free(fbuf);
        free(hbuf);
        free(vbuf);
        return ResponseCode::OperationFailed;
    }
    if (write(fd, fbuf, strlen(fbuf)) < 0) {
        ALOGE("Cannot write to \"%s\": %s", HOSTAPD_CONF_FILE, strerror(errno));
        ret = ResponseCode::OperationFailed;
    }
error:
    free(wbuf);
    free(fbuf);
    free(hbuf);
    free(vbuf);
    if (aret == -1) {
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return ResponseCode::OperationFailed;
    }

    /* Note: apparently open can fail to set permissions correctly at times */
    if (fchmod(fd, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return ResponseCode::OperationFailed;
    }

    if (fchown(fd, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        close(fd);
        unlink(HOSTAPD_CONF_FILE);
        return ResponseCode::OperationFailed;
    }

    close(fd);
    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or P2P or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    int i = 0;
    char *fwpath = NULL;
    char *iface;

    if (argc < 4) {
        ALOGE("SoftAP fwreload is missing arguments. Please use: softap <wlan iface> <AP|P2P|STA>");
        return ResponseCode::CommandSyntaxError;
    }

    if (!strcmp("STA", argv[3]))
        wifi_switch_driver_mode(WIFI_STA_MODE); /* which is STA + P2P... */
    else if (!strcmp("AP", argv[3]))
        wifi_switch_driver_mode(WIFI_AP_MODE);
    else if (!strcmp("P2P", argv[3]))
        wifi_switch_driver_mode(WIFI_P2P_MODE);

    ALOGD("Softap fwReload - done");

    return ResponseCode::SoftapStatusResult;
}

void SoftapController::generatePsk(char *ssid, char *passphrase, char *psk_str) {
    unsigned char psk[SHA256_DIGEST_LENGTH];
    int j;
    // Use the PKCS#5 PBKDF2 with 4096 iterations
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase),
            reinterpret_cast<const unsigned char *>(ssid), strlen(ssid),
            4096, SHA256_DIGEST_LENGTH, psk);
    for (j=0; j < SHA256_DIGEST_LENGTH; j++) {
        sprintf(&psk_str[j*2], "%02x", psk[j]);
    }
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
    if ( chmod(addr.sun_path, perm) < 0 ) {
         ALOGE("chmod error : %d\n",errno);
    }

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

            if (!entry)
                return -ENOMEM;

            snprintf(entry, len, "%s=%s", key, val);
            ENV_SOCKET[n] = entry;
            return 0;
        }
    }
    return 1;
}
