#ifndef __LATE_INIT_PV_H
#define __LATE_INIT_PV_H

struct domain_info {
    uint16_t domid;
    bool is_hvm;
    bool override_uuid;
    const char *uuid;
    uint32_t num_cpu;
    uint32_t max_cpu;
    struct {
        uint32_t target;
        uint32_t max;
        uint32_t video;
    } mem_info;
    struct {
        uint16_t be_domid;
        uint32_t evtchn_port;
        uint64_t mfn;
    } xs_info;
    struct {
        bool enable;
        uint16_t be_domid;
        uint32_t evtchn_port;
        uint64_t mfn;
    } cons_info;
};

#endif
