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
#ifndef _DONGLE_CONTROLLER_H
#define _DONGLE_CONTROLLER_H

//#include <linux/in.h>
#include <netinet/in.h>
#include <utils/List.h>

class DongleController {
public:
    DongleController();
    virtual ~DongleController();

    int switchUsbMode(int vendorId, int productId);
    int setUsbAutoSuspendMode(int mode);
    int switchW32UsbMode(int mode);

private:
    static const int    MAX_CMD_LEN;
    static const char*  CONFIG_PATH;
};

#endif
