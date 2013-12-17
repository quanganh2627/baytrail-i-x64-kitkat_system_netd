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
#ifndef _TFT_CONTROLLER_H
#define _TFT_CONTROLLER_H

class IpSecController {
public:

    IpSecController();
    virtual ~IpSecController();

    int addSA(const char *src, const char*dst,
            const char *ealgo, const char *eKey, const char *aalgo, const char * aKey,
            int spi, const char *secProtocol, const char *mode, long time);

    int addSP(const char *src, int srcport, const char *dst, int dstport,
            const char *protocol, const char *mode, const char *dir, const char *secProtocol,
            long time);

    int removeSA(const char *src, const char *dst, int spi, const char *secProtocol,
            const char *mode);

    int removeSP(int spi);

private:
    int mSeq;
    int mReqId;
};

#endif
