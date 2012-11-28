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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "WidiConnectivity"
#include <cutils/log.h>


#include "WidiConnectivity.h"

WidiConnectivity::WidiConnectivity() {
	dhcpFd = -1;
	dhcpPid = 0;
}

WidiConnectivity::~WidiConnectivity() {
}

int WidiConnectivity::startDhcp(const char *interface, int num_addrs,
				struct in_addr* addrs) {
	if (dhcpPid != 0) {
		LOGI("DHCP already started, restart it!");
		stopDhcp();
	}

	LOGD("Starting WiDi DHCP service");

	pid_t pid;
	int pipefd[2];

	if (pipe(pipefd) < 0) {
		LOGE("pipe failed (%s)", strerror(errno));
		return -1;
	}

	/*
	 * TODO: Create a monitoring thread to handle and restart
	 * the daemon if it exits prematurely
	 */
	if ((pid = fork()) < 0) {
		LOGE("fork failed (%s)", strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if (!pid) {
		close(pipefd[1]);
		if (pipefd[0] != STDIN_FILENO) {
			if (dup2(pipefd[0], STDIN_FILENO) != STDIN_FILENO) {
				LOGE("dup2 failed (%s)", strerror(errno));
				return -1;
			}
			close(pipefd[0]);
		}

		int num_processed_args = 9 + (num_addrs/2) + 1;
						// 1 null for termination
		if (num_addrs == 1)
			num_processed_args++;

		char **args = (char **)malloc(sizeof(char *) *
							num_processed_args);
		args[num_processed_args - 1] = NULL;
		args[0] = (char *)"/system/bin/dnsmasq";
		args[1] = (char *)"--no-daemon";
		args[2] = (char *)"--no-resolv";
		args[3] = (char *)"--no-poll";
		asprintf(&(args[4]),"-i%s", interface);
		args[5] = (char *)"--leasefile-ro";
		args[6] = (char *)"-z";
		args[7] = (char *)"-Ilo";
		args[8] = (char *)"--no-ping";

		int nextArg = 9;
		if (num_addrs == 1)
		{
			char *start = strdup(inet_ntoa(addrs[0]));
			asprintf(&(args[nextArg++]),"--dhcp-range=%s,%s,1h",
							start, start);
		}
		else {
			for (int addrIndex=0; addrIndex < num_addrs;) {
				char *start = strdup(inet_ntoa(addrs[addrIndex++]));
				char *end = strdup(inet_ntoa(addrs[addrIndex++]));
				asprintf(&(args[nextArg++]),"--dhcp-range=%s,%s,1h",
							start, end);
			}
		}

		if (execv(args[0], args)) {
			LOGE("execl failed (%s)", strerror(errno));
		}
		LOGE("Should never get here!");
		free(args);
		return 0;
	}
	else {
		close(pipefd[0]);
		dhcpPid = pid;
		dhcpFd = pipefd[1];
		LOGD("WiDi DHCP service running");
	}

	return 0;
}

int WidiConnectivity::stopDhcp() {

	if (dhcpPid == 0) {
		LOGE("Widi DHCP already stopped");
		return 0;
	}

	LOGD("Stopping WiDi DHCP service");

	kill(dhcpPid, SIGTERM);
	waitpid(dhcpPid, NULL, 0);
	dhcpPid = 0;

	close(dhcpFd);
	dhcpFd = -1;

	LOGD("Widi DHCP service stopped");

	return 0;
}
