#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <array>
#include <thread>
#include <iostream> // temporary

// MSVC SPECIFIC
#include <windows.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <intrin.h>

/**
 * ===== HWIDex created by Zex and Kernel =====
 */

/**
 * ===== STAGES =====
 * 1. create functions for vendor, brand, thread count, BIOS serial, etc...
 * 2. invoke all of them into a std::vector
 * 3. merge all of the results in the vector into a single hash
 * 4. return it as a 20-character std::string
 */

 // check for cpuid presence and accessibility
bool CheckCpuid() noexcept {
    int info[4];
    __cpuid(info, 0);
    return (info[0] >= 1);
}

// fetch CPU brand
std::string GetCpuBrand() {
    using u32 = unsigned int;
    std::stringstream ss;

    if (CheckCpuid()) {
        auto cpuid = [](u32& a, u32& b, u32& c, u32& d, const u32 a_leaf, const u32 c_leaf = 0xFF) {
            int x[4];
            __cpuidex(x, a_leaf, c_leaf);
            a = static_cast<u32>(x[0]);
            b = static_cast<u32>(x[1]);
            c = static_cast<u32>(x[2]);
            d = static_cast<u32>(x[3]);
            };

        u32 sig_reg[3] = { 0 };

        if (sig_reg[0] >= 1) {
            u32 features;
            cpuid(features, sig_reg[1], sig_reg[2], sig_reg[3], 1, 2);

            auto strconvert = [](unsigned long long n) -> std::string {
                const std::string& str(reinterpret_cast<char*>(&n));
                return str;
                };

            ss << strconvert(sig_reg[0]);
            ss << strconvert(sig_reg[2]);
            ss << strconvert(sig_reg[1]);
        }
    }

    return ss.str();
}

// fetch CPU vendor
std::string GetCpuVendor() {
    using u32 = unsigned int;
    std::array<u32, 4> buffer{};
    constexpr size_t buffer_size = sizeof(int) * buffer.size();
    std::array<char, 64> charbuffer{};
    constexpr std::array<u32, 3> ids = { 0x80000002, 0x80000003, 0x80000004 };
    std::string brand = "";

    if (CheckCpuid()) {
        auto cpuid = [](u32& a, u32& b, u32& c, u32& d, const u32 a_leaf, const u32 c_leaf = 0xFF) {
            int x[4];
            __cpuidex(x, a_leaf, c_leaf);
            a = static_cast<u32>(x[0]);
            b = static_cast<u32>(x[1]);
            c = static_cast<u32>(x[2]);
            d = static_cast<u32>(x[3]);
            };

        for (const u32& id : ids) {
            cpuid(buffer.at(0), buffer.at(1), buffer.at(2), buffer.at(3), id);

            std::memcpy(charbuffer.data(), buffer.data(), buffer_size);
            const char* convert = charbuffer.data();
            brand += convert;
        }
    }

    return brand;
}

// fetch thread count
unsigned int GetThreadCount() {
    return std::thread::hardware_concurrency();
}

// fetch MAC address
unsigned short GetMacAddress() {
    unsigned char mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    PIP_ADAPTER_INFO AdapterInfo;
    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
    char* mac_addr = static_cast<char*>(std::malloc(18));

    AdapterInfo = (PIP_ADAPTER_INFO)std::malloc(sizeof(IP_ADAPTER_INFO));

    if (AdapterInfo == NULL) {
        free(mac_addr);
        return 0;
    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
        std::free(AdapterInfo);
        AdapterInfo = (PIP_ADAPTER_INFO)std::malloc(dwBufLen);
        if (AdapterInfo == NULL) {
            std::free(mac_addr);
            return 0;
        }
    }

    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
        for (size_t i = 0; i < 6; i++) {
            mac[i] = pAdapterInfo->Address[i];
        }
    }

    std::free(AdapterInfo);

    unsigned short mac_hash = mac[0] + mac[1] + mac[2] + mac[3] + mac[4] + mac[5];
    return mac_hash;
}

// fetch BIOS serial number
unsigned long long GetBiosSerial() {
    std::system("wmic bios get serialnumber > sn.txt");
    wchar_t sn[16];

    FILE* fp;
    if (fopen_s(&fp, "sn.txt", "r, ccs=UTF-8") == 0) {
        fgetws(sn, 16, fp); // dummy read of the first line
        fgetws(sn, 16, fp); // now sn contains the 2nd line
        fclose(fp);         // cleanup temp file
        remove("sn.txt");
        return reinterpret_cast<unsigned long long>(sn); // it works
    }
    else {
        // Handle the error in opening the file
        return 0; // or some other appropriate value
    }
}

// Main function to get HWID
std::string GetHWID() {
    std::string hwid = GetCpuBrand() + GetCpuVendor();
    hwid += std::to_string(GetThreadCount());
    hwid += std::to_string(GetMacAddress());
    hwid += std::to_string(GetBiosSerial());

    // Truncate or hash the combined string to 20 characters if needed
    if (hwid.length() > 20) {
        hwid = hwid.substr(0, 20); // Truncate to 20 characters
    }

    return hwid;
}
