#pragma once

#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 300
#endif

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <vector>
#include <string>
#include <optional>

namespace cryptowords {
namespace gpu {

struct DiscoveredDevice {
    int platform_idx = 0;
    int device_idx = 0;
    cl_platform_id platform_id = nullptr;
    cl_device_id device_id = nullptr;
    std::string platform_name;
    std::string device_name;
    std::string vendor;
    std::string version;
    cl_device_type device_type = 0;
    std::string type_str;
    cl_uint compute_units = 0;
    size_t max_work_group = 0;
    cl_ulong global_mem = 0;
    cl_ulong max_alloc = 0;
    cl_ulong local_mem = 0;
    cl_uint clock_freq = 0;
    std::string extensions;
    int score = 0;
    bool is_recommended = false;
};

std::vector<DiscoveredDevice> enumerate_devices();
std::optional<DiscoveredDevice> select_device(int req_platform, int req_device);
void print_device_list();
void print_device_capabilities(const DiscoveredDevice& d);

} // namespace gpu
} // namespace cryptowords
