#include "Networkdevices.h"
netdev visibledevices;
void findviableips() {
visibledevices.discover();
while (true) {
	if (visibledevices.complete) {
		return;
	}
}
}
void sendmeassage() {
	std::cout << "sending message"<<std::endl;
	for (size_t x = 0; x < visibledevices.ipaddress.size();x++) {
		std::cout << visibledevices.ipaddress[x] << "\t" << visibledevices.macaddress[x] << std::endl;
	}
}
int main() {
	findviableips();
	sendmeassage();
		return 0;
}