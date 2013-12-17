LOCAL_PATH:= $(call my-dir)

########################################
ifeq ($(strip $(BOARD_WLAN_DEVICE)),wl12xx-compat)
########################################

include $(CLEAR_VARS)
LOCAL_MODULE:= netd.ti
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_STEM := netd

LOCAL_SRC_FILES:=                                      \
                  BandwidthController.cpp              \
                  ClatdController.cpp                  \
                  CommandListener.cpp                  \
                  DnsProxyListener.cpp                 \
                  FirewallController.cpp               \
                  IdletimerController.cpp              \
                  InterfaceController.cpp              \
                  MDnsSdListener.cpp                   \
                  NatController.cpp                    \
                  NetdCommand.cpp                      \
                  NetdConstants.cpp                    \
                  NetlinkHandler.cpp                   \
                  NetlinkManager.cpp                   \
                  PppController.cpp                    \
                  ResolverController.cpp               \
                  SecondaryTableController.cpp         \
                  TetherController.cpp                 \
                  oem_iptables_hook.cpp                \
                  UidMarkMap.cpp                       \
                  main.cpp                             \
LOCAL_SRC_FILES += SoftapControllerTI.cpp

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    external/mdnsresponder/mDNSShared \
                    external/openssl/include \
                    external/stlport/stlport \
                    bionic \
                    system/core/logwrapper/include/ \
                    bionic/libc/private \
                    $(call include-path-for, libhardware_legacy)/hardware_legacy \

LOCAL_C_INCLUDES += external/libnl-headers
LOCAL_CFLAGS += -DCONFIG_LIBNL20 -Werror=format



LOCAL_SHARED_LIBRARIES := libstlport libsysutils liblog libcutils libnetutils \
                          libcrypto libhardware_legacy libmdnssd libdl liblogwrap

LOCAL_STATIC_LIBRARIES := libnl_2

include $(BUILD_EXECUTABLE)

########################################
else
########################################

include $(CLEAR_VARS)
LOCAL_MODULE:= netd
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS :=
LOCAL_SRC_FILES:=                                      \
                  BandwidthController.cpp              \
                  ClatdController.cpp                  \
                  CommandListener.cpp                  \
                  DnsProxyListener.cpp                 \
                  FirewallController.cpp               \
                  IdletimerController.cpp              \
                  InterfaceController.cpp              \
                  MDnsSdListener.cpp                   \
                  NatController.cpp                    \
                  NetdCommand.cpp                      \
                  NetdConstants.cpp                    \
                  NetlinkHandler.cpp                   \
                  NetlinkManager.cpp                   \
                  PppController.cpp                    \
                  ResolverController.cpp               \
                  SecondaryTableController.cpp         \
                  TetherController.cpp                 \
                  IpSecController.cpp                  \
                  oem_iptables_hook.cpp                \
                  UidMarkMap.cpp                       \
                  main.cpp                             \

LOCAL_SRC_FILES += SoftapController.cpp

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) \
                    external/mdnsresponder/mDNSShared \
                    external/openssl/include \
                    external/stlport/stlport \
                    system/core/logwrapper/include/ \
                    bionic \
                    bionic/libc/private \
                    $(call include-path-for, libhardware_legacy)/hardware_legacy \

LOCAL_CFLAGS += -Werror=format -DPATH_IPSEC_H=\"netinet/ipsec.h\"

LOCAL_SHARED_LIBRARIES := libstlport libsysutils liblog libcutils libnetutils \
                          libcrypto libhardware_legacy libmdnssd libdl \
                          liblogwrap

LOCAL_STATIC_LIBRARIES := libipsec

include $(BUILD_EXECUTABLE)

########################################
endif
########################################

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  ndc.c \

LOCAL_MODULE:= ndc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS :=

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)
