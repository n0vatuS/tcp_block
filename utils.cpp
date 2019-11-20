#include "utils.h"

bool compare_method(unsigned char * packet) {
	const char * method[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};
	for(int i = 0; i < 6; i++) {
		if(strstr((char *)packet, method[i]) == (char *)packet && packet[strlen(method[i])] == 0x20)
            return true;
	}
	return false;
}

bool check_host(unsigned char * packet, char * host_name) {
	const char * str = "Host: ";
	char * host = strstr((char *)packet, str);
    if(host == NULL)
        return false;
    if(strstr((char *)host, host_name) == host+strlen(str) && host[strlen(host_name)+strlen(str)] == 0x0d)
        return true;
    return false;
}

