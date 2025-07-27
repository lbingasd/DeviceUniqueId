#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <iphlpapi.h>
#include <Wbemidl.h>
#include <cstring>
#include "md5.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")

inline std::string trim(const std::string& s) {
	auto start = s.begin();
	while (start != s.end() && isspace((unsigned char)*start)) ++start;
	auto end = s.end();
	if (start == s.end()) return "";
	do { --end; } while (end > start && isspace((unsigned char)*end));
	return std::string(start, end + 1);
}

std::string GetSystemDriveLetter()
{
	char sysDir[MAX_PATH] = { 0 };
	if (GetWindowsDirectoryA(sysDir, MAX_PATH) > 0 && strlen(sysDir) >= 2 && sysDir[1] == ':') {
		return std::string(sysDir, 2);
	}
	return "";
}

std::string QueryWMI(const wchar_t* wmiClass, const wchar_t* property, const wchar_t* wql_filter = nullptr)
{
	std::string result;
	HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return "";

	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;
	IEnumWbemClassObject* pEnumerator = nullptr;
	IWbemClassObject* pclsObj = nullptr;

	if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc))) goto cleanup;
	if (FAILED(pLoc->ConnectServer(L"ROOT\\CIMV2", nullptr, nullptr, 0, NULL, 0, 0, &pSvc))) goto cleanup;
	CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

	WCHAR wql[512];
	if (wql_filter)
		swprintf_s(wql, L"SELECT %s FROM %s WHERE %s", property, wmiClass, wql_filter);
	else
		swprintf_s(wql, L"SELECT %s FROM %s", property, wmiClass);

	BSTR bstrQuery = SysAllocString(wql);
	HRESULT hrQ = pSvc->ExecQuery(L"WQL", bstrQuery, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumerator);
	SysFreeString(bstrQuery);
	if (FAILED(hrQ)) goto cleanup;
	ULONG uReturn = 0;
	if (pEnumerator && pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
		VARIANT vtProp;
		if (SUCCEEDED(pclsObj->Get(property, 0, &vtProp, 0, 0))) {
			if ((vtProp.vt == VT_BSTR) && vtProp.bstrVal) {
				int bufLen = WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, NULL, 0, NULL, NULL);
				std::vector<char> buf(bufLen);
				WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, buf.data(), bufLen, NULL, NULL);
				result = buf.data();
			}
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}
cleanup:;
	if (pEnumerator) pEnumerator->Release();
	if (pSvc) pSvc->Release();
	if (pLoc) pLoc->Release();
	CoUninitialize();
	return trim(result);
}

std::string GetMotherBoardSerial() {
	return QueryWMI(L"Win32_BaseBoard", L"SerialNumber");
}

std::string GetCpuId() {
	return QueryWMI(L"Win32_Processor", L"ProcessorId");
}

// 自动获取系统盘物理硬盘序列号
std::string GetSystemDiskSerial()
{
	std::string systemDevice = GetSystemDriveLetter();
	if (systemDevice.empty()) return "";

	HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
	if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return "";

	IWbemLocator* pLoc = nullptr;
	IWbemServices* pSvc = nullptr;
	if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc))) return "";
	if (FAILED(pLoc->ConnectServer(L"ROOT\\CIMV2", nullptr, nullptr, 0, NULL, 0, 0, &pSvc))) { pLoc->Release(); return ""; }
	CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

	// 1. 获取系统盘 LogicalDisk -> Partition
	std::wstring assoc1 = L"ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + std::wstring(systemDevice.begin(), systemDevice.end()) + L"'} WHERE AssocClass = Win32_LogicalDiskToPartition";
	BSTR bstrAssoc1 = SysAllocString(assoc1.c_str());
	IEnumWbemClassObject* pEnumPart = nullptr;
	HRESULT hrQ1 = pSvc->ExecQuery(L"WQL", bstrAssoc1, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumPart);
	SysFreeString(bstrAssoc1);
	std::string partitionName = "";
	if (SUCCEEDED(hrQ1)) {
		IWbemClassObject* pPart = nullptr;
		ULONG uReturn2 = 0;
		if (pEnumPart && pEnumPart->Next(WBEM_INFINITE, 1, &pPart, &uReturn2) == S_OK) {
			VARIANT vtProp;
			if (SUCCEEDED(pPart->Get(L"DeviceID", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
				int len = WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, NULL, 0, NULL, NULL);
				std::vector<char> buf(len);
				WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, buf.data(), len, NULL, NULL);
				partitionName = buf.data();
			}
			VariantClear(&vtProp);
			pPart->Release();
		}
		pEnumPart->Release();
	}
	std::string diskSerial = "";
	if (!partitionName.empty()) {
		std::string query = "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='" + partitionName + "'} WHERE AssocClass = Win32_DiskDriveToDiskPartition";
		std::wstring wquery(query.begin(), query.end());
		BSTR bstrDiskQ = SysAllocString(wquery.c_str());
		IEnumWbemClassObject* pEnumDisk = nullptr;
		HRESULT hrQ2 = pSvc->ExecQuery(L"WQL", bstrDiskQ, WBEM_FLAG_FORWARD_ONLY, NULL, &pEnumDisk);
		SysFreeString(bstrDiskQ);
		if (SUCCEEDED(hrQ2)) {
			IWbemClassObject* pDisk = nullptr;
			ULONG uReturn = 0;
			if (pEnumDisk && pEnumDisk->Next(WBEM_INFINITE, 1, &pDisk, &uReturn) == S_OK) {
				VARIANT vtProp;
				if (SUCCEEDED(pDisk->Get(L"SerialNumber", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
					int len = WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, NULL, 0, NULL, NULL);
					std::vector<char> buf(len);
					WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, buf.data(), len, NULL, NULL);
					diskSerial = buf.data();
					VariantClear(&vtProp);
				}
				if (diskSerial.empty() && SUCCEEDED(pDisk->Get(L"PNPDeviceID", 0, &vtProp, 0, 0)) && vtProp.vt == VT_BSTR) {
					int len = WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, NULL, 0, NULL, NULL);
					std::vector<char> buf(len);
					WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1, buf.data(), len, NULL, NULL);
					diskSerial = buf.data();
					VariantClear(&vtProp);
				}
				pDisk->Release();
			}
			pEnumDisk->Release();
		}
	}
	pSvc->Release(); pLoc->Release(); CoUninitialize();
	return trim(diskSerial);
}

// 过滤关键字表（全部小写）
static const char* banlist[] = {
	"virtual", "vmware", "loopback", "bluetooth", "tunnel", "vpn",
	"docker", "nat", "bridge", "br-", "host-only", "tap", "tun", "veth",
	"vbox", "vmbox", "wifi virtual", "teredo", "isatap", "pppoe",
	"wireguard", "npf", "openvpn", "hamachi", "zerotier", "lan adapter",
	"test", "pseudo", "miniport", "pan", "parallels", "apple", "bootcamp",
	"mobile", "hotspot", "hosted", "remote", "virtualbox", "vmnet",
	"virtual adapter", "virtual ethernet", "ndis", "microsoft kernel",
	"wan miniport"
};
static const int banlistCount = sizeof(banlist) / sizeof(banlist[0]);

std::string GetFilteredMacsString() {
	std::vector<std::string> macs;
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD buflen = sizeof(AdapterInfo);
	if (GetAdaptersInfo(AdapterInfo, &buflen) != ERROR_SUCCESS) return "";
	for (PIP_ADAPTER_INFO p = AdapterInfo; p; p = p->Next) {
		if (p->AddressLength != 6) continue;
		if (!(p->Type == MIB_IF_TYPE_ETHERNET || p->Type == IF_TYPE_IEEE80211)) continue;
		bool skip = true;
		for (int i = 0; i < 6; ++i) { if (p->Address[i] != 0) { skip = false; break; } }
		if (skip) continue;
		skip = true;
		for (int i = 0; i < 6; ++i) { if (p->Address[i] != 0xFF) { skip = false; break; } }
		if (skip) continue;
		if ((p->Address[0] & 0x02) != 0) continue;
		if ((p->Address[0] & 0x01) != 0) continue;
		std::string desc = p->Description;
		std::transform(desc.begin(), desc.end(), desc.begin(), ::tolower);
		bool filtered = false;
		for (int i = 0; i < banlistCount; ++i) {
			if (desc.find(banlist[i]) != std::string::npos) { filtered = true; break; }
		}
		if (filtered) continue;
		char mac[18] = { 0 };
		sprintf_s(mac, "%02X-%02X-%02X-%02X-%02X-%02X",
			p->Address[0], p->Address[1], p->Address[2],
			p->Address[3], p->Address[4], p->Address[5]);
		macs.push_back(mac);
	}
	std::sort(macs.begin(), macs.end());
	std::string ret;
	for (const auto& m : macs) ret += m;
	return ret;
}

int main(int argc, char* argv[])
{
	bool debug = false;
	for (int i = 1; i < argc; ++i)
		if (strcmp(argv[i], "debug") == 0) debug = true;

	std::string value, desc;
	value = GetMotherBoardSerial();
	desc = "主板序列号";
	if (value.empty()) {
		value = GetCpuId(); desc = "CPU序列号";
		if (value.empty()) {
			value = GetSystemDiskSerial(); desc = "系统盘序列号";
			if (value.empty()) { value = GetFilteredMacsString(); desc = "MAC地址"; }
		}
	}
	value = trim(value);

	if (!value.empty()) {
		std::cout << MD5::md5(value) << std::endl;
	}
	else {
		std::cout << "" << std::endl;
	}

	if (debug) {
		std::cout << "获取的(" << desc << "): " << value << std::endl;
	}
	return 0;
}
