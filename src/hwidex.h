#include <iostream>
#include <cstdint>
#include <string>
#include <sstream>
#include <thread>
#include <cstring>
#include <memory>
#include <functional>
#include <tuple>
#include <array>

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

#if (MSVC)
#include <windows.h>
#include <iptypes.h>
#include <iphlpapi.h>
#include <intrin.h>
#elif(LINUX)
#include <cpuid.h>
#include <x86intrin.h>
#include <linux/hdreg.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <libudev.h>
#endif

struct Hashes {
    std::size_t cpu;
    std::size_t hdd;
    std::size_t sys;

    std::size_t all; // basically all 3 hashes above combined into 1, recommended to use this
};

struct HWID {
private:
    using u8  = std::uint8_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i32 = std::int32_t;

    using functions = std::string(*)();

    #if (MSVC)
        /**
         * @link: https://codereview.stackexchange.com/questions/249034/systeminfo-a-c-class-to-retrieve-system-management-data-from-the-bios
         * @author: arcomber
         */ 
        class Systeminfo {
        private:
            #pragma pack(push) 
            #pragma pack(1)
            /*
            SMBIOS Structure header (System Management BIOS) spec:
            https ://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf
            */
            struct SMBIOSHEADER
            {
                uint8_t type;
                uint8_t length;
                uint16_t handle;
            };

            /*
            Structure needed to get the SMBIOS table using GetSystemFirmwareTable API.
            see https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
            */
            struct SMBIOSData {
                uint8_t  Used20CallingMethod;
                uint8_t  SMBIOSMajorVersion;
                uint8_t  SMBIOSMinorVersion;
                uint8_t  DmiRevision;
                uint32_t  Length;
                uint8_t  SMBIOSTableData[1];
            };

            // System Information (Type 1)
            struct SYSTEMINFORMATION {
                SMBIOSHEADER Header;
                uint8_t Manufacturer;
                uint8_t ProductName;
                uint8_t Version;
                uint8_t SerialNumber;
                uint8_t UUID[16];
                uint8_t WakeUpType;  // Identifies the event that caused the system to power up
                uint8_t SKUNumber;   // identifies a particular computer configuration for sale
                uint8_t Family;
            };
            #pragma pack(pop) 

            // helper to retrieve string at string offset. Optional null string description can be set.
            const char* get_string_by_index(const char* str, int index, const char* null_string_text = "")
            {
                if (0 == index || 0 == *str) {
                    return null_string_text;
                }

                while (--index) {
                    str += strlen(str) + 1;
                }
                return str;
            }

            // retrieve the BIOS data block from the system
            SMBIOSData* get_bios_data() {
                SMBIOSData *bios_data = nullptr;

                // GetSystemFirmwareTable with arg RSMB retrieves raw SMBIOS firmware table
                // return value is either size of BIOS table or zero if function fails
                DWORD bios_size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);

                if (bios_size > 0) {
                    bios_data = (SMBIOSData*)malloc(bios_size);

                    // Retrieve the SMBIOS table
                    DWORD bytes_retrieved = GetSystemFirmwareTable('RSMB', 0, bios_data, bios_size);

                    if (bytes_retrieved != bios_size) {
                        free(bios_data);
                        bios_data = nullptr;
                    }
                }

                return bios_data;
            }


            // locates system information memory block in BIOS table
            SYSTEMINFORMATION* find_system_information(SMBIOSData* bios_data) {

                uint8_t* data = bios_data->SMBIOSTableData;

                while (data < bios_data->SMBIOSTableData + bios_data->Length)
                {
                    uint8_t *next;
                    SMBIOSHEADER *header = (SMBIOSHEADER*)data;

                    if (header->length < 4)
                        break;

                    //Search for System Information structure with type 0x01 (see para 7.2)
                    if (header->type == 0x01 && header->length >= 0x19)
                    {
                        return (SYSTEMINFORMATION*)header;
                    }

                    //skip over formatted area
                    next = data + header->length;

                    //skip over unformatted area of the structure (marker is 0000h)
                    while (next < bios_data->SMBIOSTableData + bios_data->Length && (next[0] != 0 || next[1] != 0)) {
                        next++;
                    }
                    next += 2;

                    data = next;
                }
                return nullptr;
            }

        public:
            // System information data retrieved on construction and string members populated
            Systeminfo() {
                SMBIOSData* bios_data = get_bios_data();

                if (bios_data) {
                    SYSTEMINFORMATION* sysinfo = find_system_information(bios_data);
                    if (sysinfo) {
                        const char* str = (const char*)sysinfo + sysinfo->Header.length;

                        manufacturer_ = get_string_by_index(str, sysinfo->Manufacturer);
                        productname_ = get_string_by_index(str, sysinfo->ProductName);
                        serialnumber_ = get_string_by_index(str, sysinfo->SerialNumber);
                        version_ = get_string_by_index(str, sysinfo->Version);

                        // for v2.1 and later
                        if (sysinfo->Header.length > 0x08)
                        {
                            static const int max_uuid_size{ 50 };
                            char uuid[max_uuid_size] = {};
                            _snprintf_s(uuid, max_uuid_size, max_uuid_size-1, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                sysinfo->UUID[0], sysinfo->UUID[1], sysinfo->UUID[2], sysinfo->UUID[3],
                                sysinfo->UUID[4], sysinfo->UUID[5], sysinfo->UUID[6], sysinfo->UUID[7],
                                sysinfo->UUID[8], sysinfo->UUID[9], sysinfo->UUID[10], sysinfo->UUID[11],
                                sysinfo->UUID[12], sysinfo->UUID[13], sysinfo->UUID[14], sysinfo->UUID[15]);

                            uuid_ = uuid;
                        }

                        if (sysinfo->Header.length > 0x19)
                        {
                            // supported in v 2.4 spec
                            sku_ = get_string_by_index(str, sysinfo->SKUNumber);
                            family_ = get_string_by_index(str, sysinfo->Family);
                        }
                    }
                    free(bios_data);
                }
            }

            // get product family
            const std::string get_family() const {
                return family_;
            }

            // get manufacturer - generally motherboard or system assembler name
            const std::string get_manufacturer() const {
                return manufacturer_;
            }

            // get product name
            const std::string get_productname() const {
                return productname_;
            }

            // get BIOS serial number
            const std::string get_serialnumber() const {
                return serialnumber_;
            }

            // get SKU / system configuration
            const std::string get_sku() const {
                return sku_;
            }

            // get a universally unique identifier for system
            const std::string get_uuid() const {
                return uuid_;
            }

            // get version of system information
            const std::string get_version() const {
                return version_;
            }

            Systeminfo(Systeminfo const&) = delete;
            Systeminfo& operator=(Systeminfo const&) = delete;

        private:
            std::string family_;
            std::string manufacturer_;
            std::string productname_;
            std::string serialnumber_;
            std::string sku_;
            std::string uuid_;
            std::string version_;
        };
    #endif

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
        } else {
            ss << "";
        }

        return ss.str();
    }

    // fetch CPU vendor
    static std::string GetCpuVendor() {
        if (!CheckCpuid()) {
            return "";
        }

        using u32 = std::uint32_t;

        std::array<u32, 4> buffer{};
        constexpr std::size_t buffer_size = sizeof(i32) * buffer.size();
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

    // fetch brand hash 2
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

    // extract model, family, and stepping information
    static std::string GetIDInfoHash() {
        u32 eax, ebx, ecx, edx;
        Cpuid(eax, ebx, ecx, edx, 1);

        const u8 stepping = eax & 0xF;
        const u8 model = (eax >> 4) & 0xF;
        const u8 family = (eax >> 8) & 0xF;
        const u8 extmodel = (eax >> 16) & 0xF;
        const u8 extfamily = (eax >> 20) & 0xFF;

        std::string thingy = std::to_string(stepping) + std::to_string(model) + std::to_string(family) + std::to_string(extmodel) + std::to_string(extfamily);

        return thingy;
    }

    // fetch hard disk unique ID
    static std::string HardDiskID() {
        #if (LINUX)
    /*
            char buf[1000];
            #define DEVICE "sda"
        
        FILE *f = popen("udevadm info --query=all --name=/dev/"
            DEVICE
            " | grep ID_SERIAL=", "r");
        fgets(buf, sizeof buf, f);
        pclose(f);
        
        buf[strcspn(buf, "\n")] = 0;
        printf("%s\n", buf+13);
    */
        //return 0;

            return "";
        #elif (MSVC)
            auto GetVolumeSerialNumber = [](const std::wstring& driveLetter) -> DWORD {
                DWORD volumeSerialNumber;
                if (GetVolumeInformationW(driveLetter.c_str(), nullptr, 0, &volumeSerialNumber, nullptr, nullptr, nullptr, 0)) {
                    return volumeSerialNumber;
                } else {
                    return 0;
                }
            };

            std::wstring driveLetter = L"C:\\";
            return std::to_string(GetVolumeSerialNumber(driveLetter));
        #else
            return "";
        #endif
    }

    static std::string OSName() {
        #if (LINUX)
            return "Linux";
        #elif (MSVC)
            return "Windows";
        #else
            return "";
        #endif
    }

    static std::string GetMac() try {
        u8 mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        #if (LINUX)
            struct ifreq ifr;
            struct ifconf ifc;
            char buf[1024];
            i32 success = 0;

            i32 sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

            if (sock == -1) { 
                return "";
            };

            ifc.ifc_len = sizeof(buf);
            ifc.ifc_buf = buf;

            if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
                return "";
            }

            struct ifreq* it = ifc.ifc_req;
            const struct ifreq* end = it + (ifc.ifc_len / sizeof(struct ifreq));

            for (; it != end; ++it) {
                std::strcpy(ifr.ifr_name, it->ifr_name);

                if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) { 
                    return "";
                }

                if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }

            if (success) { 
                std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
            } else {
                return "";
            }
        #elif (MSVC)
            PIP_ADAPTER_INFO AdapterInfo;
            DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

            char *mac_addr = static_cast<char*>(std::malloc(18));

            AdapterInfo = (IP_ADAPTER_INFO *) std::malloc(sizeof(IP_ADAPTER_INFO));

            if (AdapterInfo == NULL) {
                free(mac_addr);
                return "";
            }

            if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
                std::free(AdapterInfo);
                AdapterInfo = (IP_ADAPTER_INFO *) std::malloc(dwBufLen);
                if (AdapterInfo == NULL) {
                    std::free(mac_addr);
                    return "";
                }
            }

            if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
                PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
                for (std::size_t i = 0; i < 6; i++) {
                    mac[i] = pAdapterInfo->Address[i];
                }
            }

            std::free(AdapterInfo);
        #endif

        std::stringstream ss;

        ss << 
        static_cast<i32>(mac[0]) << 
        static_cast<i32>(mac[1]) << 
        static_cast<i32>(mac[2]) << 
        static_cast<i32>(mac[3]) << 
        static_cast<i32>(mac[4]) << 
        static_cast<i32>(mac[5]);

        return ss.str();
    } catch (...) { 
        return "";
    }

    static std::string BIOSInfo() {
        #if (MSVC)
            Systeminfo info;
            std::stringstream ss;
            ss << info.get_manufacturer()
            << info.get_productname()
            << info.get_serialnumber()
            return ss.str();
        #else
            return "";
        #endif
    }


    static std::string BIOS_UUID() {
        #if (MSVC)
            Systeminfo info;
            return info.get_uuid();
        #else
            return "";
        #endif
    }


    // function lists
    static constexpr functions cpu_functions[] = {
        GetCpuBrand, GetCpuVendor, GetThreadCount, GetCpuidHash, GetIDInfoHash
    };

    static constexpr functions hdd_functions[] = {
        HardDiskID
    };

    static constexpr functions sys_functions[] = {
        OSName, GetMac, BIOSInfo, BIOS_UUID
    };


public:
    HWID() = delete; // Delete default constructor
    HWID(const HWID&) = delete; // Delete copy constructor
    HWID(HWID&&) = delete; // Delete move constructor


    // Main function to get the HWID struct
    static std::unique_ptr<Hashes> GetHWID() {
        // merge the array of function pointers into a hash
        auto hasher = [](const functions* p_functions, const std::size_t length) -> u64 {
            u64 result = 0; // possibility of overflow on purpose

            for (u8 i = 0; i < length; i++) {
                std::hash<std::string> hash_invoke;

                auto invoked_result = std::invoke(p_functions[i]);

                if (!invoked_result.empty()) {
                    result += hash_invoke(invoked_result);
                }
            }

            return result;
        };

        constexpr std::size_t cpu_length = sizeof(cpu_functions) / sizeof(cpu_functions[0]);
        constexpr std::size_t hdd_length = sizeof(hdd_functions) / sizeof(hdd_functions[0]);
        constexpr std::size_t sys_length = sizeof(sys_functions) / sizeof(sys_functions[0]);

        const std::size_t cpu_hash = hasher(cpu_functions, cpu_length);
        const std::size_t hdd_hash = hasher(hdd_functions, hdd_length);
        const std::size_t sys_hash = hasher(sys_functions, sys_length);

        auto hash_accumulator = [&]() noexcept -> std::size_t {
            const constexpr std::uint64_t xor_hash = 0x9e3779b9;
            return std::hash<size_t>{}(((cpu_hash + hdd_hash + sys_hash) << 2) ^ xor_hash);
        };

        std::size_t all_hash = hash_accumulator();

        std::unique_ptr<Hashes> ptr = std::make_unique<Hashes>();

        ptr->cpu = cpu_hash;
        ptr->hdd = hdd_hash;
        ptr->sys = sys_hash;
        ptr->all = all_hash;

        return ptr;
    }
};