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
#include <dirent.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/wireless.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#define LOG_TAG "SoftapController"
#include <cutils/log.h>
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>

#include <hardware_legacy/power.h>

#include "SoftapControllerTI.h"
#include <private/android_filesystem_config.h>
#ifdef CONFIG_LIBNL20
/* libnl 2.0 compatibility code */
#define nl_handle_alloc nl_socket_alloc
#define nl_handle_destroy nl_socket_free
#endif

#define TI_MAX_AP_COUNT "8"
#define MAX_SSID_LEN 32

SoftapController::SoftapController() {
    mHostapdStarted = false;
    mApMode = false;
}

SoftapController::~SoftapController() {
}

int SoftapController::startDriver(char *iface) {
    LOGD("softAp startDriver called");
    return 0;
}

int SoftapController::stopDriver(char *iface) {
    LOGD("softAp stopDriver called");
    return 0;
}

int SoftapController::initNl() {
    int err;

    nl_sock = nl_handle_alloc();
    if (!nl_sock) {
        LOGE("Failed to allocate netlink socket.");
        return -ENOMEM;
    }

    if (genl_connect(nl_sock)) {
        LOGE("Failed to connect to generic netlink.");
        err = -ENOLINK;
        goto out_handle_destroy;
    }

#ifdef CONFIG_LIBNL20
    genl_ctrl_alloc_cache(nl_sock, &nl_cache);
#else
    nl_cache = genl_ctrl_alloc_cache(nl_sock);
#endif
    if (!nl_cache) {
        LOGE("Failed to allocate generic netlink cache.");
        err = -ENOMEM;
        goto out_handle_destroy;
    }

    nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211");
    if (!nl80211) {
        LOGE("nl80211 not found.");
        err = -ENOENT;
        goto out_cache_free;
    }

    return 0;

out_cache_free:
    nl_cache_free(nl_cache);
out_handle_destroy:
    nl_handle_destroy(nl_sock);
    return err;
}

void SoftapController::deinitNl() {
    genl_family_put(nl80211);
    nl_cache_free(nl_cache);
    nl_handle_destroy(nl_sock);
}



int SoftapController::executeNlCmd(const char *iface, enum nl80211_iftype type,
				   uint8_t cmd) {
    struct nl_cb *cb;
    struct nl_msg *msg;
    int devidx = 0;
    int err;
    bool add_interface = (cmd == NL80211_CMD_NEW_INTERFACE);


    if (add_interface) {
        devidx = phyLookup();
    } else {
        devidx = if_nametoindex(iface);
        if (devidx == 0) {
            LOGE("failed to translate ifname to idx");
            return -errno;
        }
    }

    msg = nlmsg_alloc();
    if (!msg) {
        LOGE("failed to allocate netlink message");
        return 2;
    }

    cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (!cb) {
        LOGE("failed to allocate netlink callbacks");
        err = 2;
        goto out_free_msg;
    }

    genlmsg_put(msg, 0, 0, genl_family_get_id(nl80211), 0, 0, cmd, 0);

    if (add_interface) {
        NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
    } else {
        NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
    }

    if (add_interface) {
        NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, iface);
        NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, type);
    }

    err = nl_send_auto_complete(nl_sock, msg);
    if (err < 0)
        goto out;

    err = 1;

    nl_cb_err(cb, NL_CB_CUSTOM, NlErrorHandler, &err);
    nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, NlFinishHandler, &err);
    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, NlAckHandler, &err);

    LOGW("err: %d", err);
    while (err > 0)
        nl_recvmsgs(nl_sock, cb);
out:
    nl_cb_put(cb);
out_free_msg:
    nlmsg_free(msg);
    return err;
nla_put_failure:
    LOGW("building message failed");
    return 2;
}

int SoftapController::NlErrorHandler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
    int *ret = (int *)arg;
    LOGE("NlErrorHandler: %d", err->error);
    *ret = err->error;
    return NL_STOP;
}

int SoftapController::NlFinishHandler(struct nl_msg *msg, void *arg)
{
     int *ret = (int *)arg;
     LOGE("NlFinishHandler: 0");
     *ret = 0;
     return NL_SKIP;
}

int SoftapController::NlAckHandler(struct nl_msg *msg, void *arg)
{
    int *ret = (int *)arg;
    LOGE("NlAckHandler: 0");
    *ret = 0;
    return NL_STOP;
}


// ignore the "." and ".." entries
static int dir_filter(const struct dirent *name)
{
    if (0 == strcmp("..", name->d_name) ||
        0 == strcmp(".", name->d_name))
            return 0;

    return 1;
}

// lookup the only active phy
int SoftapController::phyLookup()
{
    char buf[200];
    int fd, pos;
    struct dirent **namelist;
    int n, i;

    n = scandir("/sys/class/ieee80211", &namelist, dir_filter,
                (int (*)(const dirent**, const dirent**))alphasort);
    if (n != 1) {
        LOGE("unexpected - found %d phys in /sys/class/ieee80211", n);
        for (i = 0; i < n; i++)
            free(namelist[i]);
        free(namelist);
        return -1;
    }

    snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index",
             namelist[0]->d_name);
    free(namelist[0]);
    free(namelist);

    fd = open(buf, O_RDONLY);
    if (fd < 0)
        return -1;
    pos = read(fd, buf, sizeof(buf) - 1);
    if (pos < 0) {
        close(fd);
        return -1;
    }
    buf[pos] = '\0';
    close(fd);
    return atoi(buf);
}

int SoftapController::switchInterface(bool apMode) {

    int ret;


    if (mApMode == apMode) {
        LOGE("skipping interface switch. apMode: %d", apMode);
        return 0;
    }

    ret = initNl();
    if (ret != 0)
        return ret;

    if (apMode) {
        LOGD("switchInterface 1");
        ret = executeNlCmd(STA_INTERFACE,
                                NL80211_IFTYPE_STATION,
                                NL80211_CMD_DEL_INTERFACE);
        if (ret != 0) {
            LOGE("could not remove STA interface: %d", ret);
            goto cleanup;
        }
        LOGD("switchInterface 2");
        ret = executeNlCmd(AP_INTERFACE,
                                NL80211_IFTYPE_STATION,
                                NL80211_CMD_NEW_INTERFACE);
        if (ret != 0) {
            LOGE("could not add AP interface: %d", ret);
            goto cleanup;
        }
    } else {
        LOGD("switchInterface 3");
        ret = executeNlCmd(AP_INTERFACE,
                                NL80211_IFTYPE_STATION,
                                NL80211_CMD_DEL_INTERFACE);
        if (ret != 0) {
            LOGE("could not remove STA interface: %d", ret);
            goto cleanup;
        }
        LOGD("switchInterface 4");
        ret = executeNlCmd(STA_INTERFACE,
                                NL80211_IFTYPE_STATION,
                                NL80211_CMD_NEW_INTERFACE);
        if (ret != 0) {
            LOGE("could not add AP interface: %d", ret);
            goto cleanup;
        }
    }

    LOGD("switched interface. apMode: %d", apMode);
    mApMode = apMode;

cleanup:
    deinitNl();
    return ret;
}

int SoftapController::startHostapd() {
    int i;
    char svc_property[100];

    if(mHostapdStarted) {
        LOGE("hostapd is started");
        return 0;
    }

    if (property_set("ctl.start", HOSTAPD_SERVICE_NAME) < 0) {
        LOGE("Failed to start hostapd");
        return -1;
    }

    for(i=0; i < HOSTAPD_START_MAX_RETRIES; i++) {
        usleep(HOSTAPD_START_DELAY_US);
        if (property_get(HOSTAPD_STATE_PROP, svc_property, "no_such_prop") <= 0)
            continue;
        else if (strcmp(svc_property,"running") != 0)
            continue;
       else
           break;
    }

    if (strcmp(svc_property,"running") != 0) {
        LOGE("failed to start hostapd. state: %s", svc_property);
        return -1;
    }

    // give hostapd some more time to actuallly start (connect to driver)
    sleep(2);
    LOGD("hostapd started OK");
    mHostapdStarted = true;

    return 0;
}

int SoftapController::stopHostapd() {
    int ret, pid;
    char pidpropname[PROPERTY_KEY_MAX];
    char pidpropval[PROPERTY_VALUE_MAX];

    snprintf(pidpropname,
            sizeof(pidpropname), "hostapd.pid");

    property_get(pidpropname, pidpropval, NULL);
    if (strlen(pidpropval) != 0)
        pid = atoi(pidpropval);
    else pid=-1;

    LOGD("hostapd pid %d", pid);
    if (pid > 0) {
        /* try a nice hostapd shutdown */
        ret = kill(pid,SIGTERM);
        if (ret==0) {
                waitpid(pid, NULL, 0);
                usleep(HOSTAPD_STOP_DELAY_US);
                LOGD("hostapd pid %d stopped with SIGTERM", pid);
        } else {
                LOGD("hostapd pid %d failed to stop", pid);
        }
        snprintf(pidpropval, sizeof(pidpropval), "%d", -1);
        property_set(pidpropname, pidpropval);
    }
    /* still let the framework know we killed the service */
    if (property_set("ctl.stop", HOSTAPD_SERVICE_NAME) < 0)
        LOGE("Failed to stop hostapd service");

    usleep(HOSTAPD_STOP_DELAY_US);
    LOGD("hostapd successfully stopped");
    sleep(1);
    mHostapdStarted = false;
    return 0;
}

int SoftapController::startSoftap() {
    // don't do anything here - setSoftap is always called
    return 0;
}

int SoftapController::stopSoftap() {

    LOGD("stopSoftap - Ok");

    if (!mHostapdStarted) {
        LOGE("Softap is stopped");
        return 0;
    }

    stopHostapd();
    switchInterface(false);
    release_wake_lock(AP_WAKE_LOCK);
    LOGD("stopSoftAp release_wake_lock");
    return 0;
}

// note: this is valid after setSoftap is called
bool SoftapController::isSoftapStarted() {
    LOGD("returning isSoftapStarted: %d", mHostapdStarted);
    return mHostapdStarted;
}

/*
 * Arguments:
 *      argv[2] - wlan interface
 *      argv[3] - softap interface
 *      argv[4] - SSID
 *	argv[5] - Security
 *	argv[6] - Key
 *	argv[7] - Channel
 *	argv[8] - Preamble
 *	argv[9] - Max SCB
 *  argv[10] - Hidden SSID
 *  argv[11] - Country Code
 */
int SoftapController::setSoftap(int argc, char *argv[]) {
   int ret = 0, len=0,pos=0;
    char buf[2048];
    char * bufptr ;

    LOGD("%s - %s - %s - %s - %s - %s - %s - %s -%s -%s",argv[2],argv[3],argv[4],argv[5],argv[6],argv[7],argv[8],argv[9],argv[10],argv[11]);

    if (argc < 4) {
        LOGE("Softap set - missing arguments");
        return -1;
    }

    FILE* fp = fopen(HOSTAPD_CONF_TEMPLATE_FILE, "r");
    if (!fp) {
       LOGE("Softap set - hostapd template file read failed");
       return -1;
    }

    FILE* fp2 = fopen(HOSTAPD_CONF_FILE, "w");
    if (!fp2) {
       LOGE("Softap set - hostapd.conf file read failed");
       fclose(fp);
       return -1;
    }

    bufptr =buf;

    while (fgets(buf, sizeof(buf), fp)) {
        if((strncmp(buf, "ssid=",5) == 0) ||
           (strncmp(buf, "wpa=",4) == 0) ||
           (strncmp(buf, "wpa_passphrase=",15) == 0) ||
           (strncmp(buf, "wpa_key_mgmt=",12) == 0) ||
           (strncmp(buf, "wpa_pairwise=",12) == 0) ||
           (strncmp(buf, "rsn_pairwise=",12) == 0) ||
           (strncmp(buf, "interface=",10) == 0)) {
           continue;
        }
        fputs(buf,fp2);
    }

    memset(mBackupBuf, 0, sizeof(mBackupBuf));
    memset (buf,0,sizeof(buf));

    // Update interface
    len += sprintf(buf, "interface=%s\n", AP_INTERFACE);
    if (len >= 0) {
    fputs(buf, fp2);
    }


    // Update SSID
    if (strlen(argv[4]) > MAX_SSID_LEN)
        (argv[4][MAX_SSID_LEN+1]) = '\0';
    bufptr =buf+len;
    len+=sprintf(bufptr, "ssid=%s\n",argv[4]);
    fputs(bufptr, fp2);

    // Update security
    if(strncmp(argv[5],"wpa2-psk",8) == 0) {
        if  (strlen(argv[6]) >= 8 || strlen(argv[6]) <= 63) {
            bufptr =buf+len;
            len+= sprintf(bufptr, "wpa=2\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\n"
                "wpa_pairwise=CCMP\nrsn_pairwise=CCMP\n", argv[6]);
            fputs(bufptr, fp2);
        }
    }

    if(strncmp(argv[5],"wpa-psk",7) == 0) {
        if  (strlen(argv[6]) >= 8 || strlen(argv[6]) <= 63) {
            bufptr =buf+len;
            len += sprintf(bufptr, "wpa=1\nwpa_passphrase=%s\nwpa_key_mgmt=WPA-PSK\n"
                  "wpa_pairwise=TKIP\nrsn_pairwise=TKIP\n", argv[6]);
            fputs(bufptr, fp2);
        }
    }
    bufptr =buf+len;

    if (argc >7) {
        len+=sprintf(bufptr, "channel=%s\n", argv[7]);
    }
    else {
        len+=sprintf(bufptr, "channel=11\n");
    }
    fputs(bufptr, fp2);
    bufptr =buf+len;

    if (argc > 9)
    {
        len+= sprintf(bufptr, "max_num_sta=%s\n", argv[9]);
    }
    else {
        len+= sprintf(bufptr, "max_num_sta=8\n");
    }
    fputs(bufptr, fp2);
    bufptr =buf+len;

    if (argc > 10) {
        if (strcmp("false",argv[10]) ==0) {
            len += sprintf(bufptr,  "ignore_broadcast_ssid=%s\n", "0");
        }
        else{
            len += sprintf(bufptr,  "ignore_broadcast_ssid=%s\n", "1");
        }
    }
    else {
        len += sprintf(bufptr,  "ignore_broadcast_ssid=0\n");
    }
    fputs(bufptr, fp2);
    bufptr =buf+len;

    if(aclMode == 0) {
        len+= sprintf(bufptr, "macaddr_acl=%s\n","0");
    }
    else {
        len+= sprintf(bufptr, "macaddr_acl=%s\n","1");
    }
    fputs(bufptr, fp2);

    fclose(fp);
    fclose(fp2);

	/* Note: apparently open can fail to set permissions correctly at times */
    if (chmod(HOSTAPD_CONF_FILE, 0660) < 0) {
        ALOGE("Error changing permissions of %s to 0660: %s",
                HOSTAPD_CONF_FILE, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    if (chown(HOSTAPD_CONF_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        ALOGE("Error changing group ownership of %s to %d: %s",
                HOSTAPD_CONF_FILE, AID_WIFI, strerror(errno));
        unlink(HOSTAPD_CONF_FILE);
        return -1;
    }

    memcpy(mBackupBuf,buf,sizeof(buf));

    // we take the wakelock here because the stop/start is lengthy
    LOGD("setSoftap acquire_wake_lock");
    acquire_wake_lock(PARTIAL_WAKE_LOCK, AP_WAKE_LOCK);

    // switch interface to wlan1
    ret = switchInterface(true);
    if (ret != 0)
        goto fail_switch;

    // restart hostapd to update configuration
    ret = stopHostapd();
    if (ret != 0)
        goto fail;

    ret = startHostapd();
    if (ret != 0)
        goto fail;

    LOGD("hostapd set - Ok");
    return 0;

fail:
    LOGD("hostapd set - failed. AP switching interfaces.");
    switchInterface(false);
fail_switch:
    release_wake_lock(AP_WAKE_LOCK);
    LOGD("hostapd set - failed. AP is off. release_wake_lock");

    return ret;
}

/*
 * Arguments:
 *	argv[2] - interface name
 *	argv[3] - AP or STA
 */
int SoftapController::fwReloadSoftap(int argc, char *argv[])
{
    return 0;
}

int SoftapController::clientsSoftap(char **retbuf)
{
  return 0;
}
