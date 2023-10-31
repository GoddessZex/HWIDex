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
 * ===== STAGES =====
 * 1. create functions for vendor, brand, thread count, BIOS serial, etc...
 * 2. invoke all of them into a std::vector
 * 3. merge all of the results in the vector into a single hash
 * 4. return it as a 20-character std::string
 */

[[nodiscard]] std::string GetHWID() {
    using i32 = std::int32_t;
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;

    // check for cpuid presence and accessibility
    auto check_cpuid = []() noexcept -> bool {
        #if ( \
            !defined(__x86_64__) && \
            !defined(__i386__) && \
            !defined(_M_IX86) && \
            !defined(_M_X64) \
        )
            return false;
        #endif

        i32 info[4];
        __cpuid(info, 0);
        return (info[0] >= 1);
    };

    // cpuid wrapper for MSVC
    auto cpuid = []
    (
        u32 &a, u32 &b, u32 &c, u32 &d, 
        const u32 a_leaf,
        const u32 c_leaf = 0xFF  // default dummy value
    ) noexcept -> void {
        i32 x[4];
        __cpuidex((i32*)x, a_leaf, c_leaf);
        a = static_cast<u32>(x[0]);
        b = static_cast<u32>(x[1]);
        c = static_cast<u32>(x[2]);
        d = static_cast<u32>(x[3]);
    };

    // get cpu brand (e.g. GenuineIntel, AuthenticAMD, etc...)
    [[nodiscard]] auto brand = [&]() -> std::string {
        if (!check_cpuid()) {
            return "";
        }

        auto cpuid_thingy = [&](const u32 p_leaf, u32* regs, std::size_t start = 0, std::size_t end = 4) -> bool {
            u32 x[4];
            cpuid(x[0], x[1], x[2], x[3], p_leaf);

            for (; start < end; start++) { 
                *regs++ = x[start];
            }

            return true;
        };

        u32 sig_reg[3] = {0};

        if (!cpuid_thingy(0, sig_reg, 1)) {
            return "";
        }

        u32 features;
        cpuid_thingy(1, &features, 2, 3);

        auto strconvert = [](u64 n) -> std::string {
            const std::string &str(reinterpret_cast<char*>(&n));
            return str;
        };

        std::stringstream ss;

        ss << strconvert(sig_reg[0]);
        ss << strconvert(sig_reg[2]);
        ss << strconvert(sig_reg[1]);

        return ss.str();
    };

    // fetch cpu vendor 
    [[nodiscard]] auto vendor = [&]() -> std::string {
        if (!check_cpuid()) {
            return "";
        }

        std::array<u32, 4> buffer{};
        constexpr std::size_t buffer_size = sizeof(i32) * buffer.size();
        std::array<char, 64> charbuffer{};

        constexpr std::array<u32, 3> ids = {
            0x80000002,
            0x80000003,
            0x80000004
        };

        std::string brand = "";

        for (const u32 &id : ids) {
            cpuid(buffer.at(0), buffer.at(1), buffer.at(2), buffer.at(3), id);

            std::memcpy(charbuffer.data(), buffer.data(), buffer_size);

            const char* convert = charbuffer.data();
            brand += convert;
        }

        return brand;
    };

    // fetch thread count 
    [[nodiscard]] auto threadcount = []() -> u32 {
        return std::thread::hardware_concurrency();
    };

    // fetch mac address
    [[nodiscard]] auto mac = []() -> u16 {
        // C-style array on purpose
        u8 mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        PIP_ADAPTER_INFO AdapterInfo;
        DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

        char *mac_addr = static_cast<char*>(std::malloc(18));

        AdapterInfo = (IP_ADAPTER_INFO *) std::malloc(sizeof(IP_ADAPTER_INFO));

        if (AdapterInfo == NULL) {
            free(mac_addr);
            return false;
        }

        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
            std::free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO *) std::malloc(dwBufLen);
            if (AdapterInfo == NULL) {
                std::free(mac_addr);
                return false;
            }
        }

        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
            for (std::size_t i = 0; i < 6; i++) {
                mac[i] = pAdapterInfo->Address[i];
            }
        }

        std::free(AdapterInfo);

        const u16 mac_hash = mac[0] + mac[1] + mac[2] + mac[3] + mac[4] + mac[5];
        return mac_hash;
    };

    // bios data thingy idfk
    [[nodiscard]] auto bios_shit = []() -> u64 {
        std::system("wmic bios get serialnumber > sn.txt");
        wchar_t sn[16];

        FILE* fp = fopen("sn.txt", "r, ccs=UTF-8");
        fgetws(sn, 16, fp); // dummy read of first line
        fgetws(sn, 16, fp); // now sn contains 2nd line

        fclose(fp);         // cleanup temp file
        remove("sn.txt");

        return reinterpret_cast<u64>(sn); // extremely messy but whatever, it works
    };


    // TODO: ADD STAGE 2 HERE
}