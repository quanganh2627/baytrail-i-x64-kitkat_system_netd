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
#include <sys/types.h>
#include <sys/wait.h>

#include <dirent.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "PppController"
#include <cutils/log.h>

#include "PppController.h"

PppController::PppController() {
    mTtys = new TtyCollection();
    mPid = 0;
}

PppController::~PppController() {
    TtyCollection::iterator it;

    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
        free(*it);
    }
    mTtys->clear();
}

int PppController::attachPppd(const char *tty, struct in_addr local,
                              struct in_addr remote, struct in_addr dns1,
                              struct in_addr dns2) {
    pid_t pid;

    if (mPid) {
        ALOGE("Multiple PPPD instances not currently supported");
        errno = EBUSY;
        return -1;
    }

    TtyCollection::iterator it;
    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
        if (!strcmp(tty, *it)) {
            break;
        }
    }
    if (it == mTtys->end()) {
        ALOGE("Invalid tty '%s' specified", tty);
        errno = -EINVAL;
        return -1;
    }

    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {
        char *l = strdup(inet_ntoa(local));
        char *r = strdup(inet_ntoa(remote));
        char *d1 = strdup(inet_ntoa(dns1));
        char *d2 = strdup(inet_ntoa(dns2));
        char dev[32];
        char *lr;

        asprintf(&lr, "%s:%s", l, r);

        snprintf(dev, sizeof(dev), "/dev/%s", tty);

        // TODO: Deal with pppd bailing out after 99999 seconds of being started
        // but not getting a connection
        if (execl("/system/bin/pppd", "/system/bin/pppd", "-detach", dev, "115200",
                  lr, "ms-dns", d1, "ms-dns", d2, "lcp-max-configure", "99999", (char *) NULL)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        return 0;
    } else {
        mPid = pid;
    }
    return 0;
}

int PppController::detachPppd(const char *tty) {

    if (mPid == 0) {
        ALOGE("PPPD already stopped");
        return 0;
    }

    ALOGD("Stopping PPPD services on port %s", tty);
    kill(mPid, SIGTERM);
    waitpid(mPid, NULL, 0);
    mPid = 0;
    ALOGD("PPPD services on port %s stopped", tty);
    return 0;
}

/**
 * pppd
 * start
 * tty
 * dial
 * user
 * pass
 * apn
 * pin
 */
int PppController::startPppd(int argc, char *argv[]) {
    if (argc < 8) {
        LOGE("Start pppd - missing arguments");
        return -1;
    }

    LOGD("Start pppd %s - %s - %s - %s - %s - %s",
            argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);

    if (mPid) {
        LOGE("Multiple PPPD instances not currently supported");
        errno = EBUSY;
        return -1;
    }

    updateTtyList();

    const char *tty = argv[2];

    TtyCollection::iterator it;
    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
        if (!strcmp(tty, *it)) {
            break;
        }
    }
    if (it == mTtys->end()) {
        LOGE("Invalid tty '%s' specified", tty);
        errno = -EINVAL;
        return -1;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) {
        char dev[32];
        const char *dial = argv[3];
        const char *user = argv[4];
        const char *pass = argv[5];
        const char *apn = argv[6];
        const char *pin = argv[7];

        snprintf(dev, sizeof(dev), "/dev/%s", tty);
        setenv("DONGLEDIAL", dial, 1);
        setenv("DONGLEFUN", "AT+CFUN=1", 1);

        if (strcmp(apn, "*") == 0) {
            setenv("DONGLEAPN", "AT", 1);
        } else {
            char apnstr[64];
            snprintf(apnstr, sizeof(apnstr), "AT+CGDCONT=1,\"IP\",\"%s\"", apn);
            setenv("DONGLEAPN", apnstr, 1);
        }

        if (strcmp(user, "*") == 0) {
            if (execl("/system/bin/pppd", "/system/bin/pppd", "-detach", dev, "115200", "debug",
                        "mtu", "1440", "defaultroute", "usepeerdns", "novj", "novjccomp", "noipdefault",
                        "noaccomp", "ipcp-accept-local", "ipcp-accept-remote", "connect-delay", "5000",
                        "ipcp-max-failure", "60", "ipcp-max-configure", "60", "connect",
                        "/system/xbin/chat -E -s -v -f /etc/ppp/connect-chat",  (char *) NULL)) {
                LOGE("execl failed (%s)", strerror(errno));
            }
        } else {
            if (execl("/system/bin/pppd", "/system/bin/pppd", "-detach", dev, "115200", "debug",
                        "user", user, "password", pass,
                        "mtu", "1440", "defaultroute", "usepeerdns", "novj", "novjccomp", "noipdefault",
                        "noaccomp", "ipcp-accept-local", "ipcp-accept-remote", "connect-delay", "5000",
                        "ipcp-max-failure", "60", "ipcp-max-configure", "60", "connect",
                        "/system/xbin/chat -E -s -v -f /etc/ppp/connect-chat",  (char *) NULL)) {
                LOGE("execl failed (%s)", strerror(errno));
            }
        }

        LOGE("Should never get here!");
        return 0;
    } else {
        mPid = pid;
    }

    return 0;
}

int PppController::stopPppd(const char *tty) {
    return detachPppd(tty);
}

TtyCollection *PppController::getTtyList() {
    updateTtyList();
    return mTtys;
}

int PppController::updateTtyList() {
    TtyCollection::iterator it;

    for (it = mTtys->begin(); it != mTtys->end(); ++it) {
        free(*it);
    }
    mTtys->clear();

    DIR *d = opendir("/sys/class/tty");
    if (!d) {
        ALOGE("Error opening /sys/class/tty (%s)", strerror(errno));
        return -1;
    }

    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        if ((!strncmp(de->d_name, "tty", 3)) && (strlen(de->d_name) > 3)) {
            mTtys->push_back(strdup(de->d_name));
        }
    }
    closedir(d);
    return 0;
}
