#include <WinSock2.h>
#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <string>
#include <vector>
#include <Windows.h>
#include <iostream>
#include <sstream>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
struct liveandmac { bool live; std::string mac; };
class netdev {
public:
	bool complete = false;
	std::vector<std::string>macaddress = {};
	std::vector<std::string>ipaddress = {};
	
	int getOctectsIP(std::string ip, std::vector<int>& octetsIP) {
		std::stringstream sip(ip);
		std::string temp;
		octetsIP.clear();
		std::vector<bool> ipInRange;
		while (getline(sip, temp, '.'))
			octetsIP.push_back(atoi(temp.c_str()));
		if (octetsIP.size() == 4) {
			for (wchar_t i = 0; i < octetsIP.size(); i++) {
				if (octetsIP[i] >= 0 && octetsIP[i] <= 255)
					ipInRange.push_back(true);
				else
					ipInRange.push_back(false);
			}
			if (ipInRange[0] == true && ipInRange[1] == true && ipInRange[2] == true && ipInRange[3] == true) {
				return 0;
			}
			else {
				return 1;
			}
		}
		else {
			return 1;
		}
	}
	int getOctetsMask(std::string mask, std::vector<int>& octetsMask) {
		std::stringstream smask(mask);
		std::string temp;
		octetsMask.clear();
		std::vector<bool> maskInRange;
		while (getline(smask, temp, '.'))
			octetsMask.push_back(atoi(temp.c_str()));
		if (octetsMask.size() == 4) {
			for (wchar_t i = 0; i < octetsMask.size(); i++) {
				if (octetsMask[i] == 0 || octetsMask[i] == 128 || octetsMask[i] == 192 || octetsMask[i] == 224 || octetsMask[i] == 240 || octetsMask[i] == 248 || octetsMask[i] == 252 || octetsMask[i] == 254 || octetsMask[i] == 255)
					maskInRange.push_back(true);
				else
					maskInRange.push_back(false);
			}
			if (maskInRange[0] == true && maskInRange[1] == true && maskInRange[2] == true && maskInRange[3] == true) {
				return 0;
			}
			else {
				return 1;
			}
		}
		else {
			return 1;
		}
	}
	std::string toString(std::vector<int> octets) {
		std::ostringstream octStrm;
		for (wchar_t j = 0; j < octets.size(); j++){
			if (j > 0)
				octStrm << '.';
			octStrm << octets[j];
		}
		return octStrm.str();
	}
	std::vector<int> toDecimal(std::vector<int> octets, std::vector<int>& decimals) {
		std::stringstream octStrm;
		decimals.clear();
		for (wchar_t j = 0; j < octets.size(); j++){
			if (j > 0)
				octStrm << '.';
			octStrm << octets[j];
		}
		std::string temp;
		while (getline(octStrm, temp, '.'))
			decimals.push_back(atoi(temp.c_str()));
		return decimals;
	}
	int getNHBits(std::vector<int>& octetsIP, std::vector<int>& octetsMask, std::vector<int>& octetsIPBits, std::vector<int>& octetsMaskBits) {
		for (wchar_t j = 0; j < octetsIP.size(); j++){
			if (j > 0)
			{//std::cout << ".";
			}
			int mask = 128;
			while (mask)
			{octetsIPBits.push_back((octetsIP[j] & mask) != 0);
				//std::cout << ((octetsIP[j] & mask) != 0);
				mask >>= 1;
			}
		}
		// Get SUBNET binary rep. // 
		for (wchar_t j = 0; j < octetsMask.size(); j++)
		{	if (j > 0)
			{//std::cout << ".";
			}
			int mask = 128;
			while (mask)
			{	octetsMaskBits.push_back((octetsMask[j] & mask) != 0);
				//std::cout << ((octetsMask[j] & mask) != 0);
				mask >>= 1;
			}
		}
		return 0;
	}
	int getIncrement(std::vector<int> decimalMask, std::vector<int> decimalNetID) {
		int increment = 0;
		for (wchar_t i = 0; i < decimalMask.size(); i++) {
			if (decimalMask[i] == 255) {
				increment = 1;
			}
			else if (decimalMask[i] == 254) {
				increment = 2;
				break;
			}
			else if (decimalMask[i] == 252) {
				increment = 4;
				break;
			}
			else if (decimalMask[i] == 248) {
				increment = 8;
				break;
			}
			else if (decimalMask[i] == 240) {
				increment = 16;
				break;
			}
			else if (decimalMask[i] == 224) {
				increment = 32;
				break;
			}
			else if (decimalMask[i] == 192) {
				increment = 64;
				break;
			}
			else if (decimalMask[i] == 128) {
				increment = 128;
				break;
			}
		}
		return increment;
	}
	int calcClass(std::vector<int>& octetsIP) {
		if (octetsIP[0] == 10) {
			return 1;	// Class A Private address blocks //
		}
		else if (octetsIP[0] == 172 && octetsIP[1] >= 16 && octetsIP[1] <= 31) {
			return 2;	// Class B Private address blocks //
		}
		else if (octetsIP[0] == 192 && octetsIP[1] == 168) {
			return 3;	// Class C Private address blocks //
		}
		else if (octetsIP[0] == 127) {
			return 4;	// Loopback Address Reserved address blocks //
		}
		else if (octetsIP[0] >= 0 && octetsIP[0] < 127) {
			return 5;
		}
		else if (octetsIP[0] > 127 && octetsIP[0] < 192) {
			return 6;
		}
		else if (octetsIP[0] > 191 && octetsIP[0] < 224) {
			return 7;
		}
		else if (octetsIP[0] > 223 && octetsIP[0] < 240) {
			return 8;
		}
		else if (octetsIP[0] > 239 && octetsIP[0] <= 255) {
			return 9;
		}
		else {
			return 0;	// Out of Range //
		}
	}
	std::vector<int> getNetID(std::vector<int>& octetsIPBits, std::vector<int>& octetsMaskBits) {
		std::vector<int> netID;
		for (wchar_t j = 0; j < octetsIPBits.size(); j++)
		{
			if ((j > 0) && (j % 8 == 0))
				std::cout << ".";
			netID.push_back(octetsIPBits[j] & octetsMaskBits[j]);
		}
		return netID;
	}
	std::vector<int> getNetIDRange(std::vector<int>& decimalNetID, int& netInc, std::vector<int>& decimalMask) {
		std::vector<int> netIDEnd;
		for (wchar_t i = 0; i < decimalNetID.size(); i++) {
			if (decimalMask[i] == 255) {
				netIDEnd.push_back(decimalNetID[i]);
			}
			else if (decimalMask[i] < 255 && decimalMask[i] > 0) {
				netIDEnd.push_back((decimalNetID[i] + netInc) - 1);
			}
			else {
				netIDEnd.push_back(255);
			}
		}
		return netIDEnd;
	}
	int getHostsPerSubnet(std::vector<int>& decimalMask) {
		int hostBits = 0;
		for (wchar_t i = 0; i < decimalMask.size(); i++) {
			if (decimalMask[i] == 255) {
				hostBits += 0;
				continue;
			}
			else if (decimalMask[i] == 254) {
				hostBits += 1;
				continue;
			}
			else if (decimalMask[i] == 252) {
				hostBits += 2;
				continue;
			}
			else if (decimalMask[i] == 248) {
				hostBits += 3;
				continue;
			}
			else if (decimalMask[i] == 240) {
				hostBits += 4;
				continue;
			}
			else if (decimalMask[i] == 224) {
				hostBits += 5;
				continue;
			}
			else if (decimalMask[i] == 192) {
				hostBits += 6;
				continue;
			}
			else if (decimalMask[i] == 128) {
				hostBits += 7;
				continue;
			}
			else if (decimalMask[i] == 0) {
				hostBits += 8;
				continue;
			}
			else {
				hostBits = 0;
				break;
			}
		}
		int hostsPerSubnet = (int)pow(2.0, hostBits) - 2;
		return hostsPerSubnet;
	}
	int getSubnets(std::vector<int>& decimalMask, int& ipClass, std::vector<int>& subClassMask) {
		int netBits = 0;
		subClassMask.clear();
		if (ipClass == 1) {
			subClassMask.push_back(255);
			subClassMask.push_back(0);
			subClassMask.push_back(0);
			subClassMask.push_back(0);
		}
		else if (ipClass == 2) {
			subClassMask.push_back(255);
			subClassMask.push_back(255);
			subClassMask.push_back(0);
			subClassMask.push_back(0);
		}
		else if (ipClass == 3) {
			subClassMask.push_back(255);
			subClassMask.push_back(255);
			subClassMask.push_back(255);
			subClassMask.push_back(0);
		}
		else if (ipClass == 4 || ipClass == 5) {
			subClassMask.push_back(decimalMask[0]);
			subClassMask.push_back(decimalMask[1]);
			subClassMask.push_back(decimalMask[2]);
			subClassMask.push_back(decimalMask[3]);
		}
		for (wchar_t i = 0; i < decimalMask.size(); i++) {
			if (decimalMask[i] != subClassMask[i]) {
				if (decimalMask[i] == 255) {
					netBits += 8;
					continue;
				}
				else if (decimalMask[i] == 254) {
					netBits += 7;
					continue;
				}
				else if (decimalMask[i] == 252) {
					netBits += 6;
					continue;
				}
				else if (decimalMask[i] == 248) {
					netBits += 5;
					continue;
				}
				else if (decimalMask[i] == 240) {
					netBits += 4;
					continue;
				}
				else if (decimalMask[i] == 224) {
					netBits += 3;
					continue;
				}
				else if (decimalMask[i] == 192) {
					netBits += 2;
					continue;
				}
				else if (decimalMask[i] == 128) {
					netBits += 1;
					continue;
				}
				else if (decimalMask[i] == 0) {
					netBits += 0;
					continue;
				}
				else {
					netBits += 0;
				}
			}
		}
		int subnets = (int)pow(2.0, netBits);
		return subnets;
	}
	liveandmac sendarp(std::string destination, std::string source) {
		ULONG macaddr[2]; ULONG PhysAddrLen = 6;
		memset(&macaddr, 0xff, sizeof(macaddr));
		IPAddr destinationip,sourceip;
		DWORD dwretval=NULL;
		if (inet_pton(AF_INET , destination.c_str(), &destinationip)&& inet_pton(AF_INET , source.c_str(), &sourceip)) {
			dwretval = SendARP(destinationip, sourceip, &macaddr, &PhysAddrLen);
		}
		else if (inet_pton(AF_INET6, destination.c_str(), &destinationip) && inet_pton(AF_INET6, source.c_str(), &sourceip)) {
			dwretval = SendARP(destinationip, sourceip, &macaddr, &PhysAddrLen);
		}
		else {
			std::cout << "Inet_pton()" << GetLastError() << std::endl;
		}
		liveandmac result;
		if (dwretval == NO_ERROR) {
			result.live = true;
			BYTE* bPhysAddr;
			unsigned int i;
			bPhysAddr = (BYTE*)&macaddr;
			std::string addresses;
			if (PhysAddrLen) {
				for (i = 0; i < (int)PhysAddrLen; i++) {
					std::stringstream stream;
					if (i == (PhysAddrLen - 1)){
						stream << std::hex << ((int)bPhysAddr[i]) << std::showbase << ":";
						addresses.append((std::string)stream.str());
					}
					else {
						stream << std::hex << ((int)bPhysAddr[i]) << std::showbase << ":";
						addresses.append((std::string)stream.str());
					}
				}
				result.mac = addresses;
			}
			else{
				result.mac = "";
			}
			return result;
		}
		result.live = false;
		result.mac = "";
		return result;
	}
	void getips(std::string ipv4, std::string subnet, int x) {
		std::string ip;
		std::vector <int> octetsip;
		while (getOctectsIP(ip, octetsip) == 1) {
			ip = ipv4;
		}
		std::string mask;
		std::vector<int> octetsmask;
		while (getOctetsMask(mask, octetsmask) == 1) {
			mask = subnet;
		}
		std::vector<int> decimals;
		std::vector<int> decimalMask = toDecimal(octetsmask, decimals);
		std::vector<int> octetsIPBits;
		std::vector<int> octetsMaskBits;
		getNHBits(octetsip, octetsmask, octetsIPBits, octetsMaskBits);
		std::vector<int> netID = getNetID(octetsip, octetsmask);
		std::vector<int> decimalNetID = toDecimal(netID, decimals);
		int netInc = getIncrement(decimalMask, decimalNetID);		
		int classResult = calcClass(octetsip);
		int ipClass = 0;
		switch (classResult) {
		case 1:
			ipClass = 1;
			break;
		case 2:			
			ipClass = 2;
			break;
		case 3:
			ipClass = 3;
			break;
		case 4:
			ipClass = 1;
			break;
		case 5:
			ipClass = 1;
			break;
		case 6:
			ipClass = 2;
			break;
		case 7:
			ipClass = 3;
			break;
		case 8:
			ipClass = 4;
			break;
		case 9:
			ipClass = 5;
			break;
		default:
			break;
		}
		std::vector<int> subClassMask;
		getSubnets(decimalMask, ipClass, subClassMask);
		std::vector<int> netIDRange = getNetIDRange(decimalNetID, netInc, decimalMask);
		std::vector<int> usableips = netID;		
		int f = 0;
		for (int i = netID.back(); i < netIDRange.back(); i++) {
			if (i != netID.back()) {
				usableips.pop_back();
				usableips.push_back(i);
				liveandmac r = sendarp(toString(usableips), toString(octetsip));
				if (r.live) {
					ipaddress.push_back(toString(usableips));
					macaddress.push_back(r.mac);
				}				
			}
			if (i == (netIDRange.back() - 1)) {
				complete = true;
			}
		}		
	}
	void discover() {
		PIP_ADAPTER_INFO pAdapterInfo;
		PIP_ADAPTER_INFO pAdapter = NULL;
		DWORD dwRetVal = 0;
		ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
		pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(sizeof(IP_ADAPTER_INFO));
		if (pAdapterInfo == NULL) {
			return;
		}
		if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
			FREE(pAdapterInfo);
			pAdapterInfo = (IP_ADAPTER_INFO*)MALLOC(ulOutBufLen);
			if (pAdapterInfo == NULL) {
				return;
			}
		}
		if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
			pAdapter = pAdapterInfo;
			int x = 0;
			while (pAdapter) {
				x++;
				if ((pAdapter->Type != MIB_IF_TYPE_LOOPBACK) && strcmp((pAdapter->IpAddressList.IpAddress.String), "0.0.0.0") != 0
					&& strcmp((pAdapter->IpAddressList.IpMask.String), "0.0.0.0") != 0) {
					std::string inttype;
					switch (pAdapter->Type) {
					case MIB_IF_TYPE_OTHER:
						inttype = "Other";
						break;
					case MIB_IF_TYPE_ETHERNET:
						inttype = "Ethernet";
						break;
					case MIB_IF_TYPE_TOKENRING:
						inttype = "Token Ring";
						break;
					case MIB_IF_TYPE_FDDI:
						inttype = "FDDI";
						break;
					case MIB_IF_TYPE_PPP:
						inttype = "PPP";
						break;
					case MIB_IF_TYPE_LOOPBACK:
						inttype = "Lookback";
						break;
					case MIB_IF_TYPE_SLIP:
						inttype = "Slip";
						break;
					default:
						inttype = "Unknown type " + pAdapter->Type;
						break;
					}
						 std::cout<<"Type: "<<inttype<<std::endl;
						 std::cout<<"IP Address:"<<pAdapter->IpAddressList.IpAddress.String<<std::endl;
						 std::cout<<"IP Mask:"<<pAdapter->IpAddressList.IpMask.String<<std::endl;
						 std::cout<<"Gateway:"<<pAdapter->GatewayList.IpAddress.String<<std::endl;
						 std::cout << std::endl << std::endl << std::endl;
					getips(pAdapter->IpAddressList.IpAddress.String, pAdapter->IpAddressList.IpMask.String, x);	
				}
				pAdapter = pAdapter->Next;
			}			
		}
		else {
			return;
		}
		if (pAdapterInfo)
			FREE(pAdapterInfo);
		return;
	}
};