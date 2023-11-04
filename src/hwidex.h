#pragma once

#include <cstdint>
#include <string>
#include <sstream>
#include <array>
#include <thread>
#include <cstring>
#include <functional>
#include <iostream> // temporary


#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
#define MSVC 1
#else
#define MSVC 0
#endif
#if (defined(__GNUC__) || defined(__linux__))
#define LINUX 1
#else
#define LINUX 0
#endif
#if (defined(__APPLE__) || defined(__APPLE_CPP__) || defined(__MACH__) || defined(__DARWIN))
#define APPLE 1
#else
#define APPLE 0
#endif

#if (MSVC)
#include <windows.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <intrin.h>
#elif(LINUX)
#include <cpuid.h>
#include <x86intrin.h>
#endif

/**
 * ===== HWIDex created by Zex and Kernel =====
 */

/**
 * ===== STAGES =====
 * 1. create functions for vendor, brand, thread count, BIOS serial, etc... [IN PROGRESS]
 * 2. invoke all of them into a std::vector
 * 3. merge all of the results in the vector into a single hash
 * 4. return it as a 20-character std::string
 */

struct HWID {
private:
    using u32 = std::uint32_t;
    using i32 = std::int32_t;
    using funcs = std::array<std::string(*)(), 4>;

    // check for cpuid presence and accessibility
    static inline bool CheckCpuid() noexcept {
        #if \
        ( \
            !defined(__x86_64__) && \
            !defined(__i386__) && \
            !defined(_M_IX86) && \
            !defined(_M_X64) \
        )
        return false;
        #endif

        #if (MSVC)
        i32 info[4];
        __cpuid(info, 0);
        return (info[0] >= 1);
        #elif (LINUX)
        u32 ext = 0;
        return (__get_cpuid_max(ext, nullptr) > 0);
        #else
        return false;
        #endif
    }

    static void Cpuid
    (
        u32 &a, u32 &b, u32 &c, u32 &d, 
        const u32 a_leaf,
        const u32 c_leaf = 0xFF  // dummy value if not set manually
    ) {
        #if (MSVC)
            i32 x[4];
            __cpuidex((i32*)x, a_leaf, c_leaf);
            a = static_cast<u32>(x[0]);
            b = static_cast<u32>(x[1]);
            c = static_cast<u32>(x[2]);
            d = static_cast<u32>(x[3]);
        #elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, a, b, c, d);
        #endif
    };

    static void Cpuid
    (
        i32 x[4],
        const u32 a_leaf,
        const u32 c_leaf = 0xFF
    ) {
        #if (MSVC)
            __cpuidex((i32*)x, a_leaf, c_leaf);
        #elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, x[0], x[1], x[2], x[3]);
        #endif
    };

    // fetch CPU brand
    static std::string GetCpuBrand() {
        if (!CheckCpuid()) {
            return "";
        }

        std::stringstream ss;
        
        u32 sig_reg[3] = { 0 };

        if (sig_reg[0] >= 1) {
            u32 features;
            Cpuid(features, sig_reg[1], sig_reg[2], sig_reg[3], 1, 2);

            auto strconvert = [](unsigned long long n) -> std::string {
                const std::string& str(reinterpret_cast<char*>(&n));
                return str;
            };

            ss << strconvert(sig_reg[0]);
            ss << strconvert(sig_reg[2]);
            ss << strconvert(sig_reg[1]);
        }

        return ss.str();
    }

    // fetch CPU vendor
    static std::string GetCpuVendor() {
        if (!CheckCpuid()) {
            return "";
        }

        using u32 = unsigned int;
        std::array<u32, 4> buffer{};
        constexpr size_t buffer_size = sizeof(int) * buffer.size();
        std::array<char, 64> charbuffer{};
        constexpr std::array<u32, 3> ids = { 0x80000002, 0x80000003, 0x80000004 };
        std::string brand = "";

        for (const u32& id : ids) {
            Cpuid(buffer.at(0), buffer.at(1), buffer.at(2), buffer.at(3), id);

            std::memcpy(charbuffer.data(), buffer.data(), buffer_size);
            const char* convert = charbuffer.data();
            brand += convert;
        }

        return brand;
    }

    // fetch thread count
    static std::string GetThreadCount() {
        return std::to_string(std::thread::hardware_concurrency());
    }

    static std::size_t hasher(const funcs& inputs) {
        std::size_t result = 0; // possibility of overflow on purpose

        for (const auto func : inputs) {
            std::hash<std::string> hash_invoke;
            result += hash_invoke(std::invoke(func));
        }

        return result;
    }

    static std::string GetCpuidHash() {
        int cpuInfo[4] = { 0 };
        Cpuid(cpuInfo, 0);
        unsigned int* ptr = reinterpret_cast<unsigned int*>(cpuInfo);
        std::string cpuId;

        for (int i = 0; i < 4; ++i) {
            cpuId += std::to_string(ptr[i]);
        }

        return cpuId;
    }


    // function lists
    static constexpr funcs inputs {
        GetCpuBrand, GetCpuVendor, GetThreadCount, GetCpuidHash
    };

public:
    HWID() = delete; // Delete default constructor
    HWID(const HWID&) = delete; // Delete copy constructor
    HWID(HWID&&) = delete; // Delete move constructor

    // Main function to get HWID
    static std::string GetHWID() {
        std::size_t initial_hash = hasher(inputs);
        std::string hwid = std::to_string(initial_hash);
        // Truncate or hash the combined string to 20 characters if needed
        if (hwid.length() > 20) {
            hwid = hwid.substr(0, 20); // Truncate to 20 characters
        }

        return hwid;
    }
/*
    // Optional for a lighter output with raw numbers than a string 
    static std::size_t GetHWID() {
        return hasher(inputs);
    }
*/
};