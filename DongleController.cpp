/*
 * Copyright (C) 2007-2011 Borqs Ltd. All rights reserved.
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
#include <sys/wait.h>


#define LOG_TAG "DongleController"
#include <cutils/log.h>

#include "DongleController.h"

extern "C" int system_nosh2(const char *command);

const int DongleController::MAX_CMD_LEN = 1024;
const char* DongleController::CONFIG_PATH = "/data/data/com.intel.dongle/app_config";
int tag = 0;

DongleController::DongleController() {
}

DongleController::~DongleController() {
}

int DongleController::switchUsbMode(int vendorId, int productId) {
    LOGD("Switching USB Mode for %d:%d", vendorId, productId);

    char cmd[MAX_CMD_LEN];
    int res;

    if (vendorId < 0 || productId < 0) {
        LOGE("Invalid vendorId (%d) or productId (%d).", vendorId, productId);
        errno = -EINVAL;
        return -1;
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        LOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) { // child
        snprintf(cmd, sizeof(cmd), "/system/xbin/usb_modeswitch -v %04x -p %04x -c %s/%04x.%04x",
                vendorId, productId, CONFIG_PATH, vendorId, productId);

        LOGD("Switching USB Mode, cmd:%s", cmd);

        res = system_nosh2(cmd);
        if (res) {
            LOGE("switchUsbMode(): failed %s res=%d", cmd, res);
        }
        _exit(127);
    } else {
       waitpid(pid, NULL, 0);
    }
    return 0;
}

int DongleController::switchW32UsbMode(int mode) {
    LOGD("Set W32USB mode to %d", mode);
    //mode 1 3G ON else 3G off.

    FILE *fpRST, *fpRF, *fpPOWER, *fpSWITCH;
    char *fname;

    //Open GPIO files
    fpRST = fopen("/sys/class/gpio/gpio46/value", "rb+");
    if (!fpRST) {
        LOGE("Updating Set W32USB mode failed gpio46 (%s)", strerror(errno));
        return -1;
    }

    fpRF = fopen("/sys/class/gpio/gpio74/value", "rb+");
    if (!fpRF) {
        LOGE("Updating Set W32USB mode failed gpio74 (%s)", strerror(errno));
        return -1;
    }

    fpPOWER = fopen("/sys/class/gpio/gpio113/value", "rb+");
    if (!fpPOWER) {
        LOGE("Updating Set W32USB mode failed gpio113 (%s)", strerror(errno));
        return -1;
    }

    fpSWITCH = fopen("/sys/class/gpio/gpio45/value", "rb+");
    if (!fpSWITCH) {
        LOGE("Updating Set W32USB mode failed gpio45 (%s)", strerror(errno));
        return -1;
    }


    //Write GPIO files
    if (mode == 1 && tag == 1){
/*      fprintf(fpRST, "%d\n", 1);
        LOGD("Set RST to %d ", mode);
        sleep(1);
        fprintf(fpRST, "%d\n", 0);
        LOGD("Set RST to 0");
        sleep(1);
        fprintf(fpRF, "%d\n", 1);
        LOGD("Set RF to %d", mode);
        sleep(1);
        fprintf(fpPOWER, "%d\n", 1);
        LOGD("Set POWER to %d", mode);
        sleep(1);
        fprintf(fpPOWER, "%d\n", 0);
        LOGD("Set POWER to %d", mode);
        sleep(1);
*/
        fprintf(fpPOWER, "%d\n", 1);
        LOGD("Set POWER to %d", mode);
        sleep(1);
        fprintf(fpSWITCH, "%d\n", 1);
        LOGD("Set SWITCH to %d", mode);
        LOGD("==============ON done");
        tag++;
    } else if(mode == 1){
        fprintf(fpRST, "%d\n", 1);
        LOGD("Set RST to %d ", mode);
        sleep(1);
        fprintf(fpRST, "%d\n", 0);
        LOGD("Set RST to 0");
        sleep(1);
        fprintf(fpRF, "%d\n", 1);
        LOGD("Set RF to %d", mode);
        sleep(1);
        fprintf(fpPOWER, "%d\n", 1);
        LOGD("Set POWER to %d", mode);
        sleep(1);
        fprintf(fpPOWER, "%d\n", 0);
        LOGD("Set POWER to %d", mode);
        sleep(1);
        fprintf(fpSWITCH, "%d\n", 1);
    } else {
    	fprintf(fpRF, "%d\n", 0);
    	LOGD("Set RF_ON to %d", mode);
    	fprintf(fpSWITCH, "%d\n", 0);
    	LOGD("Set SWITCH to %d", mode);
    	LOGD("==============OFF done");
    }

    int temp;
    //Print GPIO files
    LOGD("===========Print GPIO values====================");
    sleep(1);
    fscanf(fpPOWER,"%d",&temp);
    LOGD("GPIO POWER  ==  %d", temp);
    fscanf(fpRF,"%d",&temp);
    LOGD("GPIO RF_ON  ==  %d", temp);
    fscanf(fpSWITCH,"%d",&temp);
    LOGD("GPIO SWITCH  ==  %d", mode);
    fscanf(fpRST,"%d",&temp);
    LOGD("GPIO RST  ==  %d", temp);


    //Close GPIO files
    fclose(fpRST);
    fclose(fpRF);
    fclose(fpPOWER);
    fclose(fpSWITCH);

    return 0;
}

int DongleController::setUsbAutoSuspendMode(int mode) {
    LOGD("Set USB auto suspend mode to %d", mode);

    FILE *fp;
    char *fname;

    fp = fopen("/sys/module/usbcore/parameters/autosuspend", "w");
    if (!fp) {
        LOGE("Updating USB auto suspend mode failed (%s)", strerror(errno));
        return -1;
    }
    fprintf(fp, "%d\n", mode);
    fclose(fp);
    return 0;
}

int system_nosh2(const char *command)
{
    pid_t pid;
    char buffer[255];
    char *argp[32];
    char *next = buffer;
    char *tmp;
    int i = 0;

    if (!command)           /* just checking... */
        return(1);

    if (strnlen(command, sizeof(buffer) - 1) == sizeof(buffer) - 1) {
        LOGE("command line too long while processing: %s", command);
        errno = E2BIG;
        return -1;
    }
    strcpy(buffer, command); // Command len is already checked.
    while ((tmp = strsep(&next, " "))) {
        argp[i++] = tmp;
        if (i == 32) {
            LOGE("argument overflow while processing: %s", command);
            errno = E2BIG;
            return -1;
        }
    }
    argp[i] = NULL;

    switch (pid = fork()) {
    case -1:                        /* error */
        return(-1);
    case 0:                         /* child */
        execve(argp[0], argp, environ);
        _exit(127);
    }

    return (pid == -1 ? -1 : 0);
}


