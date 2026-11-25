/**
 * @file test_bridge_media.c
 * @brief 单元测试：05_build_and_patch/g4host_bridge_media.h & g4host_bridge_usb.h (v34 全链路修复版)
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/mman.h>

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "TEST_ASSERT FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        abort(); \
    } \
} while (0)

/* 模拟宿主工具函数 */
static char s_last_log[512] = {0};
static int  s_log_count     = 0;

static void logf_(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(s_last_log, sizeof(s_last_log), fmt, ap);
    va_end(ap);
    s_log_count++;
}

static int s_tramp_count = 0;
static int s_patch_jump_count = 0;

static void *make_thumb_trampoline_8(uintptr_t va, void *hook_fn, const char *name)
{
    (void)va; (void)hook_fn; (void)name;
    s_tramp_count++;
    return (void *)(uintptr_t)(0x10000000u + (unsigned)s_tramp_count * 0x10u);
}

static void patch_thumb_jump(void *target, void *replacement, const char *name)
{
    (void)target; (void)replacement; (void)name;
    s_patch_jump_count++;
}

#include "g4host_bridge_media.h"
#include "g4host_bridge_usb.h"

/* 测试可控硬件状态 */
static int         g_mock_sd_inserted   = 0;
static int         g_mock_sd_mounted    = 0;
static int         g_mock_fsys_err      = 0;
static int         g_mock_use_already_start_rpc = 0;
static uint32_t    g_mock_in_cb_calls   = 0;
static uint32_t    g_mock_in_ev[4]      = {0};
static uint32_t    g_mock_notify_slot1  = 0xffu;
static uint32_t    g_mock_notify_slot2  = 0xffu;
static const char *g_mock_real_dev      = "/dev/mmcaa";
static uint16_t    g_mock_real_dev_id   = 0xd110u; /* /dev/mmcaa */
static uintptr_t   g_mock_fake_app_base = 0u;

static void mock_infra_input_cb(int ch, void *ev_ptr)
{
    (void)ch;
    g_mock_in_cb_calls++;
    if (ev_ptr) {
        memcpy(g_mock_in_ev, ev_ptr, sizeof(g_mock_in_ev));
    }
}

/* 模拟四代 libInfraMediaDetect.so 0x11002 (GetInOutStatus) */
static int mock_query_inout_g4(uint32_t media_id, uint8_t *out_inserted, uint16_t *out_dev_id)
{
    if (out_inserted) *out_inserted = 0u;
    if (out_dev_id) *out_dev_id = 0u;

    /* 重要实证案例：四代 ThreadDefault 对 /nondev/simulate (0x4000) 恒返回 inserted=1！
     * 此桩用于检验 v29 是否彻底拒绝被 simulate 误导！ */
    if (media_id == 0x4000u) {
        if (out_inserted) *out_inserted = 1u;
        return 0;
    }
    if (media_id == 0x1000u) {
        if (g_mock_sd_inserted) {
            if (out_inserted) *out_inserted = 1u;
            if (out_dev_id) *out_dev_id = g_mock_real_dev_id;
        }
        return 0;
    }
    return -1;
}

static uint32_t mock_g4_get_mount_drives(void)
{
    return (g_mock_sd_inserted && g_mock_sd_mounted) ? 1u : 0u;
}

static uint8_t mock_g4_get_drive_letter(const char *dev_name)
{
    TEST_ASSERT(dev_name != NULL && (uintptr_t)dev_name >= 0x10000u); /* 严防传小整数 0x1000/0x4000 SIGSEGV */
    if (g_mock_sd_inserted && g_mock_sd_mounted && strcmp(dev_name, g_mock_real_dev) == 0) {
        return 'A';
    }
    return 0u;
}

static int mock_g4_fsys_mount(const char *dev_name, uint32_t mode, uint8_t *out_drv)
{
    TEST_ASSERT(dev_name != NULL && (uintptr_t)dev_name >= 0x10000u);
    (void)mode;
    if (g_mock_sd_inserted && strcmp(dev_name, g_mock_real_dev) == 0) {
        if (g_mock_sd_mounted) {
            if (out_drv) *out_drv = 0u;
            return (int)G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G4;
        }
        g_mock_sd_mounted = 1;
        if (out_drv) *out_drv = 'A';
        return 0;
    }
    return (int)0x80000030u;
}

static int mock_g4_fsys_get_drive_info(uint8_t drv_letter, void *g4_buf)
{
    if (g_mock_fsys_err != 0 || !g_mock_sd_inserted || !g_mock_sd_mounted || drv_letter != 'A') {
        return g_mock_fsys_err ? g_mock_fsys_err : -1;
    }
    uint8_t *b = (uint8_t *)g4_buf;
    memset(b, 0, 0x38u);
    b[0] = 0x25u; b[1] = 0x00u; /* flags=0x25 -> b4=1,b5=0,b6=1,b7=1 */
    b[2] = 0x00u; b[3] = 0x83u; /* exFAT 0x8300 */
    memcpy(b + 0x0au, "SONY_SD_V29", 11u);
    b[0x24] = 0x78u; b[0x25] = 0x56u; b[0x26] = 0x34u; b[0x27] = 0x12u;
    return 0;
}

static int mock_g4_fsys_get_device_info(const char *dev_name, void *g4_buf)
{
    TEST_ASSERT(dev_name != NULL && (uintptr_t)dev_name >= 0x10000u);
    if (g_mock_fsys_err != 0 || !g_mock_sd_inserted || strcmp(dev_name, g_mock_real_dev) != 0) {
        return g_mock_fsys_err ? g_mock_fsys_err : -1;
    }
    uint8_t *b = (uint8_t *)g4_buf;
    memset(b, 0, 0x38u);
    b[0] = 0x25u; b[1] = 0x00u;
    b[2] = 0x00u; b[3] = 0x83u;
    memcpy(b + 0x0au, "SONY_SD_V29", 11u);
    b[0x24] = 0x78u; b[0x25] = 0x56u; b[0x26] = 0x34u; b[0x27] = 0x12u;
    return 0;
}

static int mock_g4_fsys_get_free_space(uint8_t drv_letter, void *g4_buf)
{
    if (g_mock_fsys_err != 0 || !g_mock_sd_inserted || !g_mock_sd_mounted || drv_letter != 'A') {
        return g_mock_fsys_err ? g_mock_fsys_err : -1;
    }
    /* 模拟 64GB SDXC: 512B/sector * 256 sectors/cluster = 128KB/cluster */
    uint32_t *w = (uint32_t *)g4_buf;
    w[0] = 500000u;
    w[1] = 400000u;
    w[2] = 390000u;
    w[3] = 512u;
    w[4] = 256u;
    w[5] = 0x20u;
    return 0;
}

static int mock_g4_fsys_mount4(const char *dev_name, uint32_t mode, uint8_t *out_drv, void *opt)
{
    (void)opt;
    return mock_g4_fsys_mount(dev_name, mode, out_drv);
}

static int mock_g4_fsys_find_first(const char *pattern, uint32_t attr, void *out_find_info)
{
    (void)attr;
    if (!g_mock_sd_inserted || !g_mock_sd_mounted) {
        return (int)0x80010002u;
    }
    if (pattern && strstr(pattern, "DATABASE.BIN") != NULL) {
        return 2; /* 未建库时正常返回 2 (ENOENT) */
    }
    if (out_find_info) {
        uint8_t *p = (uint8_t *)out_find_info;
        memset(p, 0, 0x30u);
        p[0x26u] = 0x10u; /* ATTR_DIRECTORY */
    }
    return 0;
}

static int mock_g4_fsys_stat(const char *path, void *out_stat)
{
    if (!g_mock_sd_inserted || !g_mock_sd_mounted) {
        return (int)0x80010002u;
    }
    if (out_stat) {
        memset(out_stat, 0, 0x20u);
    }
    return (path && strstr(path, "DCIM") != NULL) ? 0 : 2;
}

static int mock_g4_fsys_open(const char *path, uint32_t *out_fd, uint32_t mode)
{
    if (!g_mock_sd_inserted || !g_mock_sd_mounted) {
        return (int)0x80010002u;
    }
    if (!path || !out_fd) {
        return (int)0x80000030u; /* NULL 参数错误（不得伪转为 0x80000051） */
    }
    if ((mode & 0x4u) != 0u && strstr(path, "DATABASE.BIN") != NULL) {
        *out_fd = 0u;
        return (int)0x80000030u; /* 模拟四代路径缺父目录返回 0x80000030 */
    }
    *out_fd = 0x101u;
    return 0;
}

static int mock_g4_fsys_chmod(const char *path, uint32_t mode)
{
    (void)mode;
    return (g_mock_sd_inserted && g_mock_sd_mounted && path) ? 0 : (int)0x80010002u;
}

static int mock_g4_fsys_read(uint32_t fd, void *buf, uint32_t len)
{
    (void)fd;
    if (!g_mock_sd_inserted || !g_mock_sd_mounted) {
        return -1;
    }
    if (buf && len > 0u) {
        memset(buf, 0x22, len);
    }
    return (int)len;
}

static int mock_g4_fsys_write(uint32_t fd, const void *buf, uint32_t len)
{
    (void)fd; (void)buf;
    if (!g_mock_sd_inserted || !g_mock_sd_mounted) {
        return -1;
    }
    return (int)len;
}

static int mock_g4_fsys_write_and_flush(uint32_t fd, const void *buf, uint32_t len)
{
    return mock_g4_fsys_write(fd, buf, len);
}

typedef struct {
    uintptr_t   mod_base;
    uintptr_t   got_off;
    void       *hook_fn;
    const char *label;
} mock_got_rec_t;

static mock_got_rec_t g_mock_got_recs[64];
static size_t         g_mock_got_rec_cnt = 0u;

static void mock_record_got_hook(uintptr_t mod_base, uintptr_t got_off, void *new_fn, const char *label)
{
    if (g_mock_got_rec_cnt < 64u) {
        g_mock_got_recs[g_mock_got_rec_cnt].mod_base = mod_base;
        g_mock_got_recs[g_mock_got_rec_cnt].got_off  = got_off;
        g_mock_got_recs[g_mock_got_rec_cnt].hook_fn  = new_fn;
        g_mock_got_recs[g_mock_got_rec_cnt].label    = label;
    }
    g_mock_got_rec_cnt++;
}

static int g_mock_mpr_init_calls = 0;
static int g_mock_mpr_load_calls = 0;
static int g_mock_mpr_evt_calls  = 0;
static uint32_t g_mock_mpr_last_evt = 0u;

static int mock_real_mpr_init(const void *p)
{
    (void)p;
    g_mock_mpr_init_calls++;
    return 0;
}

static int mock_real_mpr_load(const void *p)
{
    (void)p;
    g_mock_mpr_load_calls++;
    return 0;
}

static int mock_real_mpr_set_issue_event(uint32_t evt_id, const void *param, uint32_t size)
{
    (void)param; (void)size;
    g_mock_mpr_evt_calls++;
    g_mock_mpr_last_evt = evt_id;
    return 0;
}

/* 模拟五代 InitMedia (受 G4MEDIA_OFF_INIT_FLAG_SLOT1_INSN 补丁控制！) */
static void mock_orig_init_media_g4(void)
{
    TEST_ASSERT(g_mock_fake_app_base != 0u);
    *(uint32_t *)(g_mock_fake_app_base + G4MEDIA_OFF_MEDIA_CNT) = 4u;
    g4media_tbl_entry_t *tbl = (g4media_tbl_entry_t *)(g_mock_fake_app_base + G4MEDIA_OFF_MEDIA_TBL);
    memset(tbl, 0, sizeof(*tbl) * 4u);

    uint16_t slot1_imm = *(const uint16_t *)(g_mock_fake_app_base + G4MEDIA_OFF_INIT_FLAG_SLOT1_INSN + 2u);
    int patched_to_48 = (slot1_imm == 0x30a8u);

    /* [0] SIMULATE 0x4000 (flags[0x27]=1 -> 模拟原代码若看0x27会判type=2) */
    tbl[0].media_id   = 0x4000u;
    tbl[0].ev_attr    = 0u;
    tbl[0].media_type = 2u;
    tbl[0].handle     = 0x40000001u;

    /* [1] 真实 Slot1 0x1000: 若 InitMedia 未打 0x48 补丁则误判为 type=3，打补丁后正确判为 type=0 */
    tbl[1].media_id   = 0x1000u;
    tbl[1].ev_attr    = 1u;
    tbl[1].media_type = patched_to_48 ? 0u : 3u;
    tbl[1].handle     = 0x40000002u;

    /* [2] PC_APP 0x3001 */
    tbl[2].media_id   = 0x3001u;
    tbl[2].ev_attr    = 2u;
    tbl[2].media_type = 3u;
    tbl[2].handle     = 0x40000003u;

    /* [3] 无效 Slot2 0x1010 */
    tbl[3].media_id   = 0x1010u;
    tbl[3].ev_attr    = 3u;
    tbl[3].media_type = 3u;
    tbl[3].handle     = 0x40000004u;
}

static int mock_orig_rpc_11000(void *param_in, uint32_t *status_out)
{
    uint32_t slot = param_in ? *(const uint32_t *)param_in : 0u;
    if (status_out) {
        if (g_mock_use_already_start_rpc && slot == 0x1000u) {
            *status_out = G4MEDIA_ERR_ALREADY_STARTED_G5; /* 22 */
        } else {
            *status_out = G4MEDIA_ERR_UNSUPPORTED_G5; /* 27 */
        }
    }
    return 0;
}

/* 模拟真实四代 libObj.so GetMediaInfo (静态属性表永远 valid=1，即使空卡槽!) */
static void mock_orig_get_media_info_g4(g4media_get_info_in_t *in, g4media_get_info_out_t *out)
{
    TEST_ASSERT(in != NULL && in->out_dev_name != NULL);
    memset(out, 0, sizeof(*out));
    if (in->media_id == 0x1000u) {
        out->err = 0u;
        out->valid = 1u;
        out->dev_type = 0u; /* Gen4 未设 Gen5 flags[0x08] */
        out->flags[G4MEDIA_ATTR_USE_FSYS] = 1u;
        out->flags[G4MEDIA_ATTR_USE_MEDIAMOUNT] = 1u;
        out->flags[G4MEDIA_ATTR_MOVIESTILL] = 1u;
        out->flags[G4MEDIA_ATTR_REMOVABLEMEDIA1] = 1u;
        out->flags[G4MEDIA_ATTR_REMOVABLE] = 1u;
        out->flags[G4MEDIA_ATTR_ADJ_SLOT_1_G4] = 1u;
        snprintf(in->out_dev_name, 21u, "%s", "/dev/mmca");
    } else if (in->media_id == 0x4000u) {
        out->err = 0u;
        out->valid = 1u;
        out->dev_type = 3u;
        out->flags[G4MEDIA_ATTR_SIMULATE] = 1u;
        out->flags[G4MEDIA_ATTR_USE_FSYS] = 1u;
        snprintf(in->out_dev_name, 21u, "%s", "/nondev/simulate");
    } else {
        out->err = G4MEDIA_ERR_UNSUPPORTED_G5;
    }
}

static void mock_orig_mount_already(uint32_t *media_id_in, uint32_t *status_out)
{
    (void)media_id_in;
    if (status_out) *status_out = G4MEDIA_ERR_ALREADY_MOUNT_G5; /* 0x24 */
}

static void mock_orig_get_status_zero(uint32_t *media_id_in, g4media_get_status_out_t *out)
{
    (void)media_id_in;
    memset(out, 0, sizeof(*out));
    out->status = 27u;
}

static void mock_orig_cmd11009(uint32_t *media_id_in, g4media_cmd11009_out_t *out)
{
    (void)media_id_in;
    memset(out, 0, sizeof(*out));
    out->status = G4MEDIA_ERR_UNSUPPORTED_G5;
}

static void mock_orig_cmd11008(g4media_cmd11008_in_t *in, uint32_t *status_out)
{
    if (in && in->out_name) in->out_name[0] = '\0';
    if (status_out) *status_out = G4MEDIA_ERR_UNSUPPORTED_G5;
}

static void mock_orig_fsys_mount_g4(g4media_fsys_mount_in_t *in, g4media_fsys_mount_out_t *out)
{
    uint8_t drv = 0u;
    int rc = mock_g4_fsys_mount(in ? in->dev_name : NULL, (in && in->rw_flag) ? 0x300u : 0x100u, &drv);
    out->status = g4media_conv_fsys_err(rc);
    out->drv_letter = drv;
}

static void mock_orig_fsys_get_drv_letter(g4media_fsys_devname_in_t *in, uint8_t *out_drv)
{
    *out_drv = mock_g4_get_drive_letter(in ? in->dev_name : NULL);
}

static void mock_orig_notify(void *self, uint32_t slot1, uint32_t slot2)
{
    (void)self;
    g_mock_notify_slot1 = slot1;
    g_mock_notify_slot2 = slot2;
}

static int      g_mock_dmm_alloc_calls = 0;
static int      g_mock_dmm_close_calls = 0;
static uint32_t g_mock_dmm_last_close_handle = 0u;
static int      g_mock_dcf_remain_calls = 0;
static int      g_mock_get_movie_remain_calls = 0;
static int      g_mock_set_movie_rec_param_calls = 0;
static int      g_mock_get_movie_rec_param_calls = 0;
static int      g_mock_set_playback_param_calls = 0;
static int      g_mock_calc_movie_remain_calls = 0;
static int      g_mock_sidb_get_remain_calls = 0;
static uint8_t  g_mock_last_movie_rec_param[G4MEDIA_MOVIE_REC_PARAM_SIZE] = {0};
static uint8_t  g_mock_last_movie_remain_in[G4MEDIA_MOVIE_REMAIN_IN_SIZE] = {0};
static uint8_t  g_mock_seed_get_movie_rec_param[G4MEDIA_MOVIE_REC_PARAM_SIZE] = {0};

static void *mock_orig_dmm_alloc_null(uint32_t unit_type, uint32_t a1, uint32_t cmd, uint32_t a3,
                                      void *out_unit, uint32_t flag, void *p_munmap)
{
    (void)unit_type; (void)a1; (void)cmd; (void)a3; (void)out_unit; (void)flag; (void)p_munmap;
    g_mock_dmm_alloc_calls++;
    return NULL;
}

static int mock_orig_dmm_close_and_free(uint32_t unit_handle)
{
    g_mock_dmm_close_calls++;
    g_mock_dmm_last_close_handle = unit_handle;
    return 0;
}

static int mock_orig_dcf_load(uint32_t slot_idx, uint32_t enable, const void *dir_str, uint32_t r3, uint32_t sp0)
{
    (void)slot_idx; (void)enable; (void)dir_str; (void)r3; (void)sp0;
    return 0;
}

static uint32_t mock_orig_dcf_remain(const void *slot_mask_arr, uint32_t mode, void *out_arr)
{
    (void)slot_mask_arr; (void)mode; (void)out_arr;
    g_mock_dcf_remain_calls++;
    return 42u;
}

static int mock_orig_get_movie_remain(const void *in_param, void *out_param)
{
    g_mock_get_movie_remain_calls++;
    if (in_param) {
        memcpy(g_mock_last_movie_remain_in, in_param, sizeof(g_mock_last_movie_remain_in));
    }
    if (out_param) {
        g4media_wr32((uint8_t *)out_param + 0x00u, 0u);
        g4media_wr32((uint8_t *)out_param + 0x04u, 75u);
    }
    return 0;
}

static int mock_orig_set_movie_rec_param(const void *param)
{
    g_mock_set_movie_rec_param_calls++;
    if (param) {
        memcpy(g_mock_last_movie_rec_param, param, sizeof(g_mock_last_movie_rec_param));
    }
    return 0;
}

static int mock_orig_get_movie_rec_param(void *out_param)
{
    g_mock_get_movie_rec_param_calls++;
    if (out_param) {
        memcpy(out_param, g_mock_seed_get_movie_rec_param, sizeof(g_mock_seed_get_movie_rec_param));
    }
    return 0;
}

static int mock_orig_set_playback_param(const void *param)
{
    (void)param;
    g_mock_set_playback_param_calls++;
    return 0;
}

static int mock_orig_get_movie_rec_status_internal(void *out_param)
{
    if (out_param) {
        memset(out_param, 0, 0x88u);
        g4media_wr32((uint8_t *)out_param + 0x10u, 88u);
        g4media_wr32((uint8_t *)out_param + 0x50u, 0x1u);
    }
    return 0;
}

static int mock_orig_calc_movie_remain(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)
{
    (void)a0; (void)a1; (void)a2; (void)a3;
    g_mock_calc_movie_remain_calls++;
    return 0;
}

static int mock_orig_sidb_get_remain(uint32_t slot_id, uint32_t content_type, uint32_t *out_remain)
{
    (void)slot_id; (void)content_type;
    g_mock_sidb_get_remain_calls++;
    if (out_remain) *out_remain = 1234u;
    return 0;
}

static void reset_bridge_state(void)
{
    g4media_bridge_initialized = 0u;
    g4media_injected_mask = 0u;
    g4media_slot1_media_id = G4MEDIA_G4_MEDIA_ID_SD_DEFAULT;
    g4media_simulate_media_id = 0u;
    memset(&g4media_g4_fsys, 0, sizeof(g4media_g4_fsys));
    memset(g4media_dev_cache, 0, sizeof(g4media_dev_cache));
    g4media_custom_input_cb = NULL;
    g4media_custom_query_inout = NULL;
    g4media_orig_init_media = NULL;
    g4media_orig_get_media_info = NULL;
    g4media_orig_rpc_11000 = NULL;
    g4media_orig_rpc_12001 = NULL;
    g4media_orig_rpc_12002 = NULL;
    g4media_orig_mount = NULL;
    g4media_orig_get_status = NULL;
    g4media_orig_cmd_11009 = NULL;
    g4media_orig_cmd_11008 = NULL;
    g4media_orig_fsys_mount = NULL;
    g4media_orig_fsys_get_drv_letter = NULL;
    g4media_orig_fsys_get_drive_info = NULL;
    g4media_orig_fsys_get_device_info = NULL;
    g4media_orig_fsys_get_free_space = NULL;
    g4media_orig_fsys_get_free_space2 = NULL;
    g4media_orig_notify_media_status = NULL;
    g4media_orig_mpr_init = NULL;
    g4media_orig_mpr_load = NULL;
    g4media_orig_mpr_set_issue_event = NULL;
    g4media_orig_mpr_get_movie_remain = NULL;
    g4media_orig_mpr_set_movie_rec_param = NULL;
    g4media_orig_mpr_get_movie_rec_param = NULL;
    g4media_orig_mpr_set_playback_param = NULL;
    g4media_orig_mpr_get_movie_rec_status_internal = NULL;
    g4media_orig_calc_movie_remain = NULL;
    g4media_orig_sidb_get_remain = NULL;
    g4media_orig_dmm_alloc_core = NULL;
    g4media_orig_dmm_close_and_free = NULL;
    g4media_orig_dcf_load = NULL;
    g4media_orig_dcf_remain_folders = NULL;
    g4media_mp5_base = 0u;
    g4media_cfys_log_budget = 256u;
    g4media_movie_diag_budget = 96u;
    g4media_drive_raw_logged = 0u;
    memset(g4media_dmm_slots, 0, sizeof(g4media_dmm_slots));
    g4media_dmm_lock = 0u;
    g_mock_mpr_init_calls = 0;
    g_mock_mpr_load_calls = 0;
    g_mock_mpr_evt_calls = 0;
    g_mock_mpr_last_evt = 0u;
    g_mock_dmm_alloc_calls = 0;
    g_mock_dmm_close_calls = 0;
    g_mock_dmm_last_close_handle = 0u;
    g_mock_dcf_remain_calls = 0;
    g_mock_get_movie_remain_calls = 0;
    g_mock_set_movie_rec_param_calls = 0;
    g_mock_get_movie_rec_param_calls = 0;
    g_mock_set_playback_param_calls = 0;
    g_mock_calc_movie_remain_calls = 0;
    g_mock_sidb_get_remain_calls = 0;
    memset(g_mock_last_movie_rec_param, 0, sizeof(g_mock_last_movie_rec_param));
    memset(g_mock_last_movie_remain_in, 0, sizeof(g_mock_last_movie_remain_in));
    memset(g_mock_seed_get_movie_rec_param, 0, sizeof(g_mock_seed_get_movie_rec_param));
    g_mock_in_cb_calls = 0u;
    memset(g_mock_in_ev, 0, sizeof(g_mock_in_ev));
    g_g4usb_cached_slot1_media_id = 0x1000u;
    g_g4usb_cached_simulate_media_id = 0u;
    g_g4usb_real_media_seen = 0;
    s_tramp_count = 0;
    s_patch_jump_count = 0;
}

static uint32_t g_mock_usb_attr8_id  = 0u;
static uint32_t g_mock_usb_attr48_id = 0x1000u;
static uint32_t g_mock_usb_attr42_id = 0u;
static uint32_t g_mock_usb_attr49_id = 0u;
static uint32_t g_mock_usb_attr27_id = 0x4000u;
static uint32_t g_mock_msc_last_req[4] = {0};
static int      g_mock_msc_calls = 0;
static int      g_mock_msc_rc = 0;
static uint32_t g_mock_msc_out_err = 0u;

static int mock_g4usb_get_media_by_attr(uint32_t *attr_in, uint32_t *resp_0x48)
{
    uint32_t attr = attr_in ? *attr_in : 0u;
    memset(resp_0x48, 0, 0x48u);
    if (attr == 8u && g_mock_usb_attr8_id != 0u) {
        resp_0x48[0] = 1u;
        resp_0x48[1] = g_mock_usb_attr8_id;
    } else if (attr == 0x48u && g_mock_usb_attr48_id != 0u) {
        resp_0x48[0] = 1u;
        resp_0x48[1] = g_mock_usb_attr48_id;
    } else if (attr == 0x42u && g_mock_usb_attr42_id != 0u) {
        /* 模拟 Gen4 REMOVABLEMEDIA1 同时返回 simulate(0x4000) 与 Slot1(g_mock_usb_attr42_id) */
        resp_0x48[0] = 2u;
        resp_0x48[1] = g_mock_usb_attr27_id;
        resp_0x48[2] = g_mock_usb_attr42_id;
    } else if (attr == 0x49u && g_mock_usb_attr49_id != 0u) {
        resp_0x48[0] = 1u;
        resp_0x48[1] = g_mock_usb_attr49_id;
    } else if (attr == 0x27u && g_mock_usb_attr27_id != 0u) {
        resp_0x48[0] = 1u;
        resp_0x48[1] = g_mock_usb_attr27_id;
    } else if (attr == 0x23u) {
        resp_0x48[0] = 1u;
        resp_0x48[1] = 0x3001u;
    } else if (attr == 9u) {
        resp_0x48[0] = 0u;
        resp_0x48[17] = 1u;
    }
    return 0;
}

static int mock_g4usb_msc_configure(void *a0, void *out)
{
    uint32_t *media_req = (uint32_t *)a0;
    g_mock_msc_calls++;
    if (media_req) {
        memcpy(g_mock_msc_last_req, media_req, sizeof(g_mock_msc_last_req));
    }
    if (out) {
        *(uint32_t *)out = g_mock_msc_out_err;
    }
    return g_mock_msc_rc;
}

int main(void)
{
    printf("=== 开始运行 g4host_bridge_media.h & g4host_bridge_usb.h (v31 修复版) 单元测试 ===\n");

    /* 1. 空指针保护测试 */
    reset_bridge_state();
    init_bridge_media(0u, 0u);
    TEST_ASSERT(s_tramp_count == 0);
    printf("[PASS 1] 空指针保护\n");

    /* 分配模拟 appFw 虚拟空间 (0x08400000 字节稀疏匿名页, 可读写可执行) */
    size_t map_sz = 0x08400000u;
    uint8_t *fake_app = (uint8_t *)mmap(NULL, map_sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    TEST_ASSERT(fake_app != MAP_FAILED);
    uintptr_t base = (uintptr_t)fake_app;
    g_mock_fake_app_base = base;

    /* 2. 错误签名跳过测试 */
    reset_bridge_state();
    *(uint32_t *)(base + G4MEDIA_OFF_GET_STATUS_CMD_LIT) = 0xdeadbeefu;
    init_bridge_media(base, 0u);
    TEST_ASSERT(s_tramp_count == 0);
    TEST_ASSERT(s_patch_jump_count == 0);
    TEST_ASSERT(*(uint32_t *)(base + G4MEDIA_OFF_GET_STATUS_CMD_LIT) == 0xdeadbeefu);
    printf("[PASS 2] 全签名不匹配安全跳过\n");

    /* 3. 写入真实 ARM Thumb-2 前言签名与字面量，验证全部 16 个跳板与 Patch */
    reset_bridge_state();
    static const uint8_t sig_in_cb[8]      = {0xb0u, 0xb5u, 0x0cu, 0x46u, 0x0du, 0x68u, 0x00u, 0xafu};
    static const uint8_t sig_init_media[8] = {0x2du, 0xe9u, 0xf0u, 0x43u, 0xdfu, 0xb0u, 0x02u, 0xafu};
    static const uint8_t sig_get_info[8]   = {0xf0u, 0xb5u, 0xbfu, 0xb0u, 0x06u, 0x46u, 0x02u, 0xafu};
    static const uint8_t sig_rpc[8]        = {0x2du, 0xe9u, 0xf0u, 0x43u, 0x8du, 0xb0u, 0x05u, 0x46u};
    static const uint8_t sig_mount[8]      = {0x2du, 0xe9u, 0xf0u, 0x41u, 0x8cu, 0xb0u, 0x05u, 0x46u};
    static const uint8_t sig_status[8]     = {0x2du, 0xe9u, 0xf0u, 0x41u, 0x92u, 0xb0u, 0x0cu, 0x46u};
    static const uint8_t sig_11009[8]      = {0xf0u, 0xb5u, 0x91u, 0xb0u, 0x05u, 0x46u, 0x02u, 0xafu};
    static const uint8_t sig_11008[8]      = {0xf0u, 0xb5u, 0x97u, 0xb0u, 0x40u, 0x26u, 0x02u, 0xafu};
    static const uint8_t sig_fs_mount[8]   = {0x2du, 0xe9u, 0xf0u, 0x41u, 0x84u, 0xb0u, 0x02u, 0xafu};
    static const uint8_t sig_fs_letter[8]  = {0x98u, 0xb5u, 0x00u, 0xafu, 0x00u, 0x68u, 0x0cu, 0x46u};
    static const uint8_t sig_fs_drv[8]     = {0xb0u, 0xb5u, 0xa2u, 0xb0u, 0x02u, 0xafu, 0x0cu, 0x46u};
    static const uint8_t sig_fs_dev[8]     = {0xf0u, 0xb5u, 0xa3u, 0xb0u, 0x02u, 0xafu, 0x0cu, 0x46u};
    static const uint8_t sig_fs_free[8]    = {0x2du, 0xe9u, 0xf0u, 0x41u, 0x90u, 0xb0u, 0x80u, 0x46u};
    static const uint8_t sig_fs_free2[8]   = {0x2du, 0xe9u, 0xf0u, 0x43u, 0x91u, 0xb0u, 0x02u, 0xafu};
    static const uint8_t sig_notify[8]     = {0xf0u, 0xb5u, 0x85u, 0xb0u, 0x04u, 0x46u, 0x02u, 0xafu};
    static const uint8_t sig_chk[8]        = {0x03u, 0x68u, 0x80u, 0xb5u, 0x00u, 0xafu, 0x93u, 0xf8u};
    static const uint8_t sig_bne[4]        = {0x0au, 0xd1u, 0x87u, 0xf8u};
    static const uint8_t insn_slot1[4]     = {0x97u, 0xf8u, 0x68u, 0x30u};
    static const uint8_t insn_slot2[4]     = {0x97u, 0xf8u, 0x69u, 0x30u};

    memcpy(fake_app + G4MEDIA_OFF_INFRA_INPUT_CB, sig_in_cb, 8);
    memcpy(fake_app + G4MEDIA_OFF_INIT_MEDIA, sig_init_media, 8);
    memcpy(fake_app + G4MEDIA_OFF_INIT_FLAG_SLOT1_INSN, insn_slot1, 4);
    memcpy(fake_app + G4MEDIA_OFF_INIT_FLAG_SLOT2_INSN, insn_slot2, 4);
    memcpy(fake_app + G4MEDIA_OFF_GET_MEDIA_INFO, sig_get_info, 8);
    memcpy(fake_app + G4MEDIA_OFF_RPC_11000, sig_rpc, 8);
    memcpy(fake_app + G4MEDIA_OFF_RPC_12001, sig_rpc, 8);
    memcpy(fake_app + G4MEDIA_OFF_RPC_12002, sig_rpc, 8);
    memcpy(fake_app + G4MEDIA_OFF_MOUNT, sig_mount, 8);
    memcpy(fake_app + G4MEDIA_OFF_GET_STATUS, sig_status, 8);
    *(uint32_t *)(fake_app + G4MEDIA_OFF_GET_STATUS_CMD_LIT) = G4MEDIA_CMD_GET_STATUS_G5;
    memcpy(fake_app + G4MEDIA_OFF_CMD_11009, sig_11009, 8);
    memcpy(fake_app + G4MEDIA_OFF_CMD_11008, sig_11008, 8);
    memcpy(fake_app + G4MEDIA_OFF_FSYS_MOUNT, sig_fs_mount, 8);
    memcpy(fake_app + G4MEDIA_OFF_FSYS_GET_DRIVE_LETTER, sig_fs_letter, 8);
    memcpy(fake_app + G4MEDIA_OFF_FSYS_GET_DRIVE_INFO, sig_fs_drv, 8);
    memcpy(fake_app + G4MEDIA_OFF_FSYS_GET_DEVICE_INFO, sig_fs_dev, 8);
    memcpy(fake_app + G4MEDIA_OFF_FSYS_GET_FREE_SPACE, sig_fs_free, 8);
    memcpy(fake_app + G4MEDIA_OFF_FSYS_GET_FREE_SPACE2, sig_fs_free2, 8);
    memcpy(fake_app + G4MEDIA_OFF_NOTIFY_MEDIA_STATUS, sig_notify, 8);
    memcpy(fake_app + G4MEDIA_OFF_CHECK_MEDIA_STATUS, sig_chk, 8);
    memcpy(fake_app + G4MEDIA_OFF_ALLOW_REC_BNE, sig_bne, 4);

    init_bridge_media(base, 0x1000u);
    TEST_ASSERT(s_tramp_count == 16);
    TEST_ASSERT(s_patch_jump_count == 1);
    TEST_ASSERT(*(uint32_t *)(fake_app + G4MEDIA_OFF_GET_STATUS_CMD_LIT) == G4MEDIA_CMD_GET_STATUS_G4);
    /* v36 撤回 0x02b8af5e bne->NOP 补丁，保留原厂指令防止走双卡分支 */
    TEST_ASSERT(*(uint16_t *)(fake_app + G4MEDIA_OFF_ALLOW_REC_BNE) == 0xd10au);
    printf("[PASS 3] 16 个跳板装载 (含 InitMedia)、GetStatus 0x11002->0x11003 及 0x02b8af5e 原指令保留通过\n");

    /* 4. QEMU/无 libInfraFsys.so 模式行为验证 (绝不伪造卡，空槽联锁返回 0) */
    g4media_orig_notify_media_status = mock_orig_notify;
    g4media_orig_cmd_11009 = mock_orig_cmd11009;
    uint8_t fake_seq_self[0x400] = {0};
    void *p_seq_self = fake_seq_self;
    TEST_ASSERT(g4media_hook_check_media_status(&p_seq_self) == 0);
    g4media_hook_notify_media_status(fake_seq_self, 0u, 0u);
    TEST_ASSERT(g_mock_notify_slot1 == 0u && fake_seq_self[0x32d] == 0u && fake_seq_self[0x32f] == 0u);
    TEST_ASSERT(g4media_hook_check_media_status(&p_seq_self) == 0);
    g4media_cmd11009_out_t out9;
    uint32_t mid_sd = 0x1000u;
    g4media_hook_cmd_11009(&mid_sd, &out9);
    TEST_ASSERT(out9.status == G4MEDIA_ERR_UNSUPPORTED_G5);
    printf("[PASS 4] QEMU/无 libInfraFsys.so 模式安全透传且 check_media_status 空槽返回 0\n");

    /* 5. 注入四代 Fsys/MediaDetect 模拟环境，验证 InitMedia 跨代属性修正与 Simulate 隔离 */
    g4media_g4_fsys.resolved = 1;
    g4media_g4_fsys.available = 1;
    g4media_g4_fsys.get_mount_drives = mock_g4_get_mount_drives;
    g4media_g4_fsys.get_drive_letter = mock_g4_get_drive_letter;
    g4media_g4_fsys.fsys_mount       = mock_g4_fsys_mount;
    g4media_g4_fsys.get_drive_info   = mock_g4_fsys_get_drive_info;
    g4media_g4_fsys.get_device_info  = mock_g4_fsys_get_device_info;
    g4media_g4_fsys.get_free_space   = mock_g4_fsys_get_free_space;
    g4media_custom_input_cb = mock_infra_input_cb;
    g4media_custom_query_inout = mock_query_inout_g4;

    g4media_orig_init_media = mock_orig_init_media_g4;
    g4media_orig_rpc_11000 = mock_orig_rpc_11000;
    g4media_orig_get_media_info = mock_orig_get_media_info_g4;
    g4media_orig_mount = mock_orig_mount_already;
    g4media_orig_get_status = mock_orig_get_status_zero;
    g4media_orig_cmd_11008 = mock_orig_cmd11008;
    g4media_orig_fsys_mount = mock_orig_fsys_mount_g4;
    g4media_orig_fsys_get_drv_letter = mock_orig_fsys_get_drv_letter;

    g4media_hook_init_media();
    g4media_tbl_entry_t *tbl = (g4media_tbl_entry_t *)(fake_app + G4MEDIA_OFF_MEDIA_TBL);
    TEST_ASSERT(*(uint16_t *)(fake_app + G4MEDIA_OFF_INIT_FLAG_SLOT1_INSN + 2u) == 0x30a8u);
    TEST_ASSERT(*(uint16_t *)(fake_app + G4MEDIA_OFF_INIT_FLAG_SLOT2_INSN + 2u) == 0x30a9u);
    TEST_ASSERT(tbl[0].media_id == 0x4000u && tbl[0].media_type == 2u);
    TEST_ASSERT(tbl[1].media_id == 0x1000u && tbl[1].media_type == 0u);
    TEST_ASSERT(g4media_get_slot1_media_id() == 0x1000u);
    TEST_ASSERT(g4media_get_simulate_media_id() == 0x4000u);
    printf("[PASS 5] InitMedia 修补 flags[0x48]/[0x49]、0x1000 归位 Slot1 且 0x4000 隔离为 Simulate\n");

    /* 6. 真机未插卡场景（即使 0x4000 Simulate 0x11002 返回 1 且 GetMediaInfo 静态返回 valid=1，亦绝不误判） */
    g_mock_sd_inserted = 0;
    g_mock_sd_mounted = 0;
    g_mock_use_already_start_rpc = 1;

    TEST_ASSERT(g4media_probe_phys_card_present_in_g4(0x4000u, NULL, 0u, NULL) == 0);
    TEST_ASSERT(g4media_probe_phys_card_present_in_g4(0x1000u, NULL, 0u, NULL) == 0);

    uint32_t st = 99u;
    g4media_hook_rpc_11000(&mid_sd, &st);
    TEST_ASSERT(st == 0u && g_mock_in_cb_calls == 0u); /* ER_ALREADY_START(22) 防 FATAL 但绝不投递 MEDIA_IN */

    uint32_t mid_sim = 0x4000u;
    st = 99u;
    g4media_hook_rpc_11000(&mid_sim, &st);
    TEST_ASSERT(st == G4MEDIA_ERR_UNSUPPORTED_G5 && g_mock_in_cb_calls == 0u);

    g4media_hook_notify_media_status(fake_seq_self, 0u, 0u);
    TEST_ASSERT(g_mock_notify_slot1 == 0u && fake_seq_self[0x32f] == 0u);
    TEST_ASSERT(g4media_hook_check_media_status(&p_seq_self) == 0);

    g4media_hook_cmd_11009(&mid_sd, &out9);
    TEST_ASSERT(out9.status == G4MEDIA_ERR_UNSUPPORTED_G5 && out9.ok_flag == 0u);
    g4media_hook_cmd_11009(&mid_sim, &out9);
    TEST_ASSERT(out9.status == G4MEDIA_ERR_UNSUPPORTED_G5 && out9.ok_flag == 0u);

    char name_buf[32];
    memset(name_buf, 'X', sizeof(name_buf));
    g4media_cmd11008_in_t in8 = { 0x1000u, name_buf };
    g4media_hook_cmd_11008(&in8, &st);
    TEST_ASSERT(st == G4MEDIA_ERR_UNSUPPORTED_G5 && name_buf[0] == '\0');
    printf("[PASS 6] 真机未插卡时严守零伪造 (排除 0x4000 Simulate 干扰, 空槽 StartInOut=0 不注 MEDIA_IN, check=0)\n");

    /* 7. 真机插卡但四代 Fsys 尚未挂载：0x11002(0x1000) 返回 inserted=1 + dev_id=0xd110 (/dev/mmcaa) */
    g_mock_sd_inserted = 1;
    g_mock_sd_mounted = 0;
    st = 99u;
    g4media_hook_rpc_11000(&mid_sd, &st);
    TEST_ASSERT(st == 0u);
    TEST_ASSERT(g_mock_in_cb_calls == 1u);
    /* tbl[1] 对应 Slot1 0x1000，所以 logical slot 应为 1+1 = 2 (绝非 tbl[0] Simulate) */
    TEST_ASSERT(g_mock_in_ev[0] == 2u && g_mock_in_ev[2] == 1u && g_mock_in_ev[3] == 0x7fffffffu);

    /* 重复调用 StartInOut(0x1000) 去重；Simulate 0x4000 与空槽 0x1010 绝不投递 */
    g4media_hook_rpc_11000(&mid_sd, &st);
    g4media_hook_rpc_11000(&mid_sim, &st);
    uint32_t mid_slot2 = 0x1010u;
    g4media_hook_rpc_11000(&mid_slot2, &st);
    TEST_ASSERT(g_mock_in_cb_calls == 1u);

    char dev_out_buf[32] = {0};
    g4media_get_info_in_t gi_in = { 0x1000u, dev_out_buf };
    g4media_get_info_out_t info_out;
    g4media_hook_get_media_info(&gi_in, &info_out);
    TEST_ASSERT(info_out.err == 0u && info_out.valid == 1u && info_out.dev_type == 2u);
    TEST_ASSERT(info_out.flags[G4MEDIA_ATTR_SLOT_1_G5] == 1u && info_out.flags[G4MEDIA_ATTR_USE_MEDIAMOUNT] == 1u);
    TEST_ASSERT(strcmp(dev_out_buf, "/dev/mmcaa") == 0);

    /* Simulate 0x4000 GetMediaInfo 绝不翻译 SLOT_1，亦不改写 g4media_slot1_media_id */
    g4media_get_info_in_t gi_sim = { 0x4000u, dev_out_buf };
    g4media_hook_get_media_info(&gi_sim, &info_out);
    TEST_ASSERT(info_out.flags[G4MEDIA_ATTR_SLOT_1_G5] == 0u && g4media_get_slot1_media_id() == 0x1000u);

    g4media_get_info_in_t gi_slot2 = { 0x1010u, dev_out_buf };
    g4media_hook_get_media_info(&gi_slot2, &info_out);
    TEST_ASSERT(info_out.err == 27u && info_out.valid == 0u);

    g4media_hook_mount(&mid_sd, &st);
    TEST_ASSERT(st == 0u && tbl[1].mounted == 1u);

    g4media_get_status_out_t st_out;
    g4media_hook_get_status(&mid_sd, &st_out);
    /* Fsys_Mount 尚未完成分配真实盘符时，GetStatus 不得提前伪报 mounted=1 */
    TEST_ASSERT(st_out.mounted == 0u);

    g4media_hook_cmd_11009(&mid_sd, &out9);
    TEST_ASSERT(out9.status == 0u && out9.ok_flag == 1u);
    g4media_hook_cmd_11009(&mid_slot2, &out9);
    TEST_ASSERT(out9.status == G4MEDIA_ERR_UNSUPPORTED_G5);

    in8.media_id = 0x1000u;
    g4media_hook_cmd_11008(&in8, &st);
    TEST_ASSERT(st == 0u && strcmp(name_buf, "/dev/mmcaa") == 0 && name_buf[20] == '\0');
    in8.media_id = 0x1010u;
    g4media_hook_cmd_11008(&in8, &st);
    TEST_ASSERT(st == G4MEDIA_ERR_UNSUPPORTED_G5 && name_buf[0] == '\0');
    printf("[PASS 7] 真机插卡 0x1000 全链路适配 (MEDIA_IN/GetMediaInfo/Mount/GetStatus/Cmd_11009/Cmd_11008) 通过\n");

    /* 8. Fsys_Mount / GetDriveLetter / DriveInfo / DeviceInfo / GetFreeSpace#1/#2 (>4GB) / 联锁校准 */
    in8.media_id = 0x1000u;
    g4media_hook_cmd_11008(&in8, &st);
    g4media_fsys_mount_in_t fin = { name_buf, 1u, {0} };
    g4media_fsys_mount_out_t fout;
    g4media_hook_fsys_mount(&fin, &fout);
    TEST_ASSERT(fout.status == 0u && fout.drv_letter == 'A' && g_mock_sd_mounted == 1);

    /* 已挂载返回 ER_ALREADY_MOUNT 归一 */
    g4media_hook_fsys_mount(&fin, &fout);
    TEST_ASSERT(fout.status == 0u && fout.drv_letter == 'A');

    /* 传入不匹配设备名("/dev/mmca")时自适应命中真实挂载节点("/dev/mmcaa") */
    g4media_fsys_mount_in_t fin_wrong = { "/dev/mmca", 1u, {0} };
    g4media_hook_fsys_mount(&fin_wrong, &fout);
    TEST_ASSERT(fout.status == 0u && fout.drv_letter == 'A');

    /* Fsys_Mount 完成后，GetStatus 应基于真实盘符 'A' 补全 status=0 && mounted=1 */
    g4media_hook_get_status(&mid_sd, &st_out);
    TEST_ASSERT(st_out.status == 0u && st_out.mounted == 1u);

    uint8_t drv = 0u;
    g4media_fsys_devname_in_t dname_in = { name_buf };
    g4media_hook_fsys_get_drive_letter(&dname_in, &drv);
    TEST_ASSERT(drv == 'A');

    g4media_fsys_info_out_t dinfo;
    g4media_hook_fsys_get_drive_info(&drv, &dinfo);
    TEST_ASSERT(dinfo.status == 0u && dinfo.fs_type_g5 == 0x40u && strcmp(dinfo.volume_label, "SONY_SD_V29") == 0);

    g4media_hook_fsys_get_device_info(&dname_in, &dinfo);
    TEST_ASSERT(dinfo.status == 0u && dinfo.b4 == 1u && dinfo.b5 == 0u && dinfo.b6 == 1u && dinfo.b7 == 1u);
    TEST_ASSERT(dinfo.fs_type_g5 == 0x40u && dinfo.volume_id == 0x12345678u);

    g4media_fsys_freespace_out_t fs1;
    g4media_hook_fsys_get_free_space(&drv, &fs1);
    TEST_ASSERT(fs1.status == 0u);
    TEST_ASSERT(fs1.bytes_08 == 500000ULL * 512ULL * 256ULL);
    TEST_ASSERT(fs1.bytes_10 == 400000ULL * 512ULL * 256ULL);
    TEST_ASSERT(fs1.bytes_18 == 390000ULL * 512ULL * 256ULL);

    g4media_fsys_freespace2_out_t fs2;
    g4media_hook_fsys_get_free_space2(&drv, &fs2);
    uint64_t avail2 = ((uint64_t)fs2.avail_hi << 32) | fs2.avail_lo;
    uint64_t total2 = ((uint64_t)fs2.total_hi << 32) | fs2.total_lo;
    TEST_ASSERT(fs2.status == 0u);
    TEST_ASSERT(total2 == 500000ULL * 512ULL * 256ULL);
    TEST_ASSERT(avail2 == 400000ULL * 512ULL * 256ULL);

    /* 错误码路径 */
    g_mock_fsys_err = -1;
    g4media_hook_fsys_get_drive_info(&drv, &dinfo);
    TEST_ASSERT(dinfo.status == 0x29u && dinfo.fs_type_g5 == 0u && dinfo.volume_label[0] == '\0');
    g4media_hook_fsys_get_device_info(&dname_in, &dinfo);
    TEST_ASSERT(dinfo.status == 0x29u && dinfo.fs_type_g5 == 0u);
    g4media_hook_fsys_get_free_space2(&drv, &fs2);
    TEST_ASSERT(fs2.status == 0x29u && fs2.avail_lo == 0u && fs2.total_hi == 0u);
    g_mock_fsys_err = 0;

    /* check_media_status 在真卡在位且 valid==0 时补全返回 1；若显式写保护(valid=1,slot1=1,w1=0)保持返回 0 */
    memset(fake_seq_self, 0, sizeof(fake_seq_self));
    TEST_ASSERT(g4media_hook_check_media_status(&p_seq_self) == 1);
    TEST_ASSERT(fake_seq_self[0x32f] == 1u && fake_seq_self[0x32d] == 1u);
    fake_seq_self[0x32d] = 0u; /* 只读锁定卡 */
    TEST_ASSERT(g4media_hook_check_media_status(&p_seq_self) == 0);

    /* notify_initial_media_status 有卡校准 */
    memset(fake_seq_self, 0, sizeof(fake_seq_self));
    g4media_hook_notify_media_status(fake_seq_self, 0u, 0u);
    TEST_ASSERT(g_mock_notify_slot1 == 1u && fake_seq_self[0x32d] == 1u && fake_seq_self[0x32f] == 1u);
    printf("[PASS 8] Fsys 全套接口 (>4GB)、check_media_status 条件联锁及 notify_initial_media_status 通过\n");

    /* 9. g4host_bridge_usb.h GetMediaIDByAttribute 与 MscConfigureFunc v29 隔离与映射测试 */
    g_g4usb_real_host_ready = 1;
    g_g4usb_real_media_seen = 0;
    g_g4usb_cached_slot1_media_id = 0x1000u;
    g_g4usb_cached_simulate_media_id = 0u;
    g4usb_orig_GetMediaIDByAttribute = mock_g4usb_get_media_by_attr;
    g4usb_orig_MscConfigureFunc = mock_g4usb_msc_configure;
    g_mock_usb_attr8_id = 0u;
    g_mock_usb_attr48_id = 0x1000u;
    g_mock_usb_attr42_id = 0u;
    g_mock_usb_attr49_id = 0u;
    g_mock_usb_attr27_id = 0x4000u;

    /* attr=0x27 (SIMULATE) 必须隔离，绝不能污染 Slot1 缓存 */
    uint32_t usb_attr = 0x27u;
    uint32_t usb_resp[18];
    memset(usb_resp, 0xaa, sizeof(usb_resp));
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 1u && usb_resp[1] == 0x4000u);
    TEST_ASSERT(g_g4usb_cached_simulate_media_id == 0x4000u);
    TEST_ASSERT(g_g4usb_real_media_seen == 0);
    TEST_ASSERT(g4media_get_simulate_media_id() == 0x4000u);

    /* attr=8 映射到 Gen4 ADJ_SLOT_1 (0x48) -> 返回 0x1000，绝不返回 0x4000 */
    memset(usb_resp, 0xaa, sizeof(usb_resp));
    usb_attr = 8u;
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 1u && usb_resp[1] == 0x1000u && usb_resp[17] == 0u);
    TEST_ASSERT(g_g4usb_cached_slot1_media_id == 0x1000u && g_g4usb_real_media_seen == 1);

    /* 若 0x48 未命中而 0x42 (REMOVABLEMEDIA1) 返回 [0x4000, 0x1008]，应过滤掉 0x4000 仅保留 0x1008 */
    g_mock_usb_attr48_id = 0u;
    g_mock_usb_attr42_id = 0x1008u;
    usb_attr = 8u;
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 1u && usb_resp[1] == 0x1008u);
    TEST_ASSERT(g_g4usb_cached_slot1_media_id == 0x1008u);
    g_mock_usb_attr48_id = 0x1000u;
    g_mock_usb_attr42_id = 0u;
    g4media_set_slot1_media_id(0x1000u);
    g_g4usb_cached_slot1_media_id = 0x1000u;

    /* attr=0x23 / attr=9 绝不覆写 Slot1 缓存 */
    usb_attr = 0x23u;
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 1u && usb_resp[1] == 0x3001u && g_g4usb_cached_slot1_media_id == 0x1000u);

    usb_attr = 9u;
    g_mock_usb_attr49_id = 0x1010u;
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 1u && usb_resp[1] == 0x1010u && usb_resp[17] == 0u);
    TEST_ASSERT(g_g4usb_cached_slot1_media_id == 0x1000u);

    /* 即使 0x48 与 0x42 均无 Slot1，也绝不去查 0x27 */
    g_mock_usb_attr48_id = 0u;
    usb_attr = 8u;
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 0u && g_g4usb_real_media_seen == 0);

    /* MscConfigureFunc: 传入 [0x4000, 0x1000] 应滤除 0x4000 仅保留 0x1000；无物理卡时传入 [0x4000] 不补假卡 */
    uint32_t msc_req_with_sim[4] = { 0x4000u, 0x1000u, 0u, 2u };
    uint32_t msc_out = 0u;
    g_mock_sd_inserted = 1;
    g_mock_msc_calls = 0;
    g4usb_hook_MscConfigureFunc(msc_req_with_sim, &msc_out);
    TEST_ASSERT(g_mock_msc_calls == 1 && g_mock_msc_last_req[3] == 1u && g_mock_msc_last_req[0] == 0x1000u);

    g_mock_sd_inserted = 0;
    g_g4usb_real_media_seen = 0;
    uint32_t msc_req_sim_only[4] = { 0x4000u, 0u, 0u, 1u };
    g_mock_msc_calls = 0;
    g_mock_msc_out_err = 1u; /* 即使 n=0 返回错误，无物理卡时绝不强行补入假卡 */
    g4usb_hook_MscConfigureFunc(msc_req_sim_only, &msc_out);
    TEST_ASSERT(g_mock_msc_calls == 1 && g_mock_msc_last_req[3] == 0u);

    /* QEMU 安全路径完整清零 0x48B */
    g_g4usb_real_host_ready = 0;
    memset(usb_resp, 0x5a, sizeof(usb_resp));
    usb_attr = 8u;
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    for (size_t i = 0; i < 18u; i++) {
        TEST_ASSERT(usb_resp[i] == 0u);
    }
    printf("[PASS 9] g4usb GetMediaIDByAttribute(0x8->0x48/0x42, 0x27隔离) 与 MscConfigureFunc 过滤通过\n");

    /* 10. 严防 /nondev/simulate 与 Slot2 (/dev/mmcb) 越权串台到 Slot1，及热插拔循环验证 */
    g_mock_sd_inserted = 1;
    g_mock_sd_mounted = 1;
    g4media_cache_store(0x1000u, "/dev/mmcaa", 'A');
    /* 静态 "/dev/ms" 不得覆盖已缓存的 "/dev/mmcaa" */
    g4media_cache_store(0x1000u, "/dev/ms", 0u);
    TEST_ASSERT(strcmp(g4media_cache_lookup(0x1000u)->dev_name, "/dev/mmcaa") == 0);

    g4media_fsys_mount_in_t fin_sim = { "/nondev/simulate", 1u, {0} };
    g4media_hook_fsys_mount(&fin_sim, &fout);
    TEST_ASSERT(fout.status != 0u && fout.drv_letter == 0u);

    g4media_fsys_mount_in_t fin_slot2 = { "/dev/mmcb", 1u, {0} };
    g4media_hook_fsys_mount(&fin_slot2, &fout);
    TEST_ASSERT(fout.status != 0u && fout.drv_letter == 0u);

    g4media_fsys_devname_in_t dsim = { "/nondev/simulate" };
    drv = 0xffu;
    g4media_hook_fsys_get_drive_letter(&dsim, &drv);
    TEST_ASSERT(drv == 0u);
    g4media_fsys_devname_in_t dslot2 = { "/dev/mmcb" };
    drv = 0xffu;
    g4media_hook_fsys_get_drive_letter(&dslot2, &drv);
    TEST_ASSERT(drv == 0u);

    g4media_hook_fsys_get_device_info(&dsim, &dinfo);
    TEST_ASSERT(dinfo.status != 0u && dinfo.volume_label[0] == '\0');
    g4media_hook_fsys_get_device_info(&dslot2, &dinfo);
    TEST_ASSERT(dinfo.status != 0u && dinfo.volume_label[0] == '\0');

    /* 热拔出 -> StartInOut 清理注入位 -> 再插卡 -> StartInOut 再次投递 MEDIA_IN */
    g_mock_sd_inserted = 0;
    g_mock_sd_mounted = 0;
    st = 99u;
    g4media_hook_rpc_11000(&mid_sd, &st);
    TEST_ASSERT(st == 0u && g_mock_in_cb_calls == 1u);
    TEST_ASSERT(g4media_cache_lookup(0x1000u) == NULL);

    g_mock_sd_inserted = 1;
    st = 99u;
    g4media_hook_rpc_11000(&mid_sd, &st);
    TEST_ASSERT(st == 0u && g_mock_in_cb_calls == 2u);

    /* 冷启动顺序倒置 (simulate_media_id == 0 且 g_media_cnt == 0): attr=8 走 0x42 回退仍能自动预缓存并剔除 0x4000 */
    g_g4usb_real_host_ready = 1;
    g_g4usb_cached_simulate_media_id = 0u;
    g4media_simulate_media_id = 0u;
    *(uint32_t *)(fake_app + G4MEDIA_OFF_MEDIA_CNT) = 0u;
    g_mock_usb_attr48_id = 0u;
    g_mock_usb_attr42_id = 0x1008u;
    usb_attr = 8u;
    memset(usb_resp, 0xaa, sizeof(usb_resp));
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    TEST_ASSERT(usb_resp[0] == 1u && usb_resp[1] == 0x1008u && g_g4usb_cached_simulate_media_id == 0x4000u);

    /* attr=8 未命中时必须清空整个 resp_0x48[0..17] 防止调用者读 resp[1] 泄露脏 ID */
    g_mock_usb_attr42_id = 0u;
    usb_attr = 8u;
    memset(usb_resp, 0x77, sizeof(usb_resp));
    g4usb_hook_GetMediaIDByAttribute(&usb_attr, usb_resp);
    for (size_t i = 0; i < 18u; i++) {
        TEST_ASSERT(usb_resp[i] == 0u);
    }
    printf("[PASS 10] 防串台(/nondev/simulate & Slot2)、热拔插周期及冷启动倒序过滤通过\n");

    /* 11. v30 C-API Fsys_GetDriveInfo (0x38B->0x7cB) 与 Fsys_GetFreeSpace (0x24B->0x34B) 翻译 */
    g_mock_sd_inserted = 1;
    g_mock_sd_mounted  = 1;
    g_mock_fsys_err    = 0;
    g4media_g4_fsys.fsys_mount4       = mock_g4_fsys_mount4;
    g4media_g4_fsys.find_first        = mock_g4_fsys_find_first;
    g4media_g4_fsys.f_stat            = mock_g4_fsys_stat;
    g4media_g4_fsys.f_open            = mock_g4_fsys_open;
    g4media_g4_fsys.f_chmod           = mock_g4_fsys_chmod;
    g4media_g4_fsys.f_read            = mock_g4_fsys_read;
    g4media_g4_fsys.f_write           = mock_g4_fsys_write;
    g4media_g4_fsys.f_write_and_flush = mock_g4_fsys_write_and_flush;

    uint8_t g4_raw[64];
    memset(g4_raw, 0, sizeof(g4_raw));
    g4_raw[0x00] = 0x05u; g4_raw[0x01] = 0x00u; /* flags */
    g4_raw[0x02] = 0x02u; g4_raw[0x03] = 0x84u; /* 0x8402 -> SD */
    g4media_wr32(g4_raw + 0x04u, 0x00400000u);
    g4media_wr16(g4_raw + 0x08u, 0x9000u);
    memcpy(g4_raw + 0x0au, "ZVE10_CARD", 10u);
    g4media_wr32(g4_raw + 0x24u, 0xdeadbeefu);
    g4media_wr16(g4_raw + 0x28u, 0x0010u);      /* exFAT fs_type = 0x10 */

    uint8_t g5_di[G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE];
    memset(g5_di, 0xaau, sizeof(g5_di));
    g4media_translate_drive_info_g4_to_g5('a', g4_raw, g5_di);
    TEST_ASSERT(g4media_rd16(g5_di + 0x00u) == 0x0005u);
    TEST_ASSERT(g4media_rd16(g5_di + 0x02u) == 0x8402u);
    TEST_ASSERT(g4media_rd32(g5_di + 0x04u) == 0x00400000u);
    TEST_ASSERT(g4media_rd16(g5_di + 0x14u) == 0x9000u);
    TEST_ASSERT(memcmp(g5_di + 0x16u, "ZVE10_CARD", 10u) == 0);
    TEST_ASSERT(g5_di[0x16u + 24u] == 0u);
    TEST_ASSERT(g4media_rd32(g5_di + 0x58u) == 0xdeadbeefu);
    TEST_ASSERT(g4media_rd16(g5_di + 0x5cu) == 0x0010u);
    TEST_ASSERT(g5_di[0x6cu] == 1u);
    TEST_ASSERT(g5_di[0x6du] == 'A');

    /* v31 核心修复：真机 G4 内部卷属性 flags=0x00f0 必须剥离高 bit 0x10..0x80，避免触发 mpr::_Load 假只读锁 */
    g4_raw[0x00] = 0xf0u; g4_raw[0x01] = 0x00u;
    memset(g5_di, 0xaau, sizeof(g5_di));
    g4media_translate_drive_info_g4_to_g5('a', g4_raw, g5_di);
    TEST_ASSERT(g4media_rd16(g5_di + 0x00u) == 0x0000u);
    TEST_ASSERT(g5_di[0x6cu] == 0u);

    memset(g5_di, 0xaau, sizeof(g5_di));
    TEST_ASSERT(g4media_c_fsys_get_drive_info('A', g5_di) == 0);
    TEST_ASSERT(g4media_rd16(g5_di + 0x00u) == 0x0005u); /* mock flags=0x25 -> masked 0x05 */
    TEST_ASSERT(g4media_rd16(g5_di + 0x02u) == 0x8300u);
    TEST_ASSERT(memcmp(g5_di + 0x16u, "SONY_SD_V29", 11u) == 0);
    TEST_ASSERT(g4media_rd32(g5_di + 0x58u) == 0x12345678u);
    TEST_ASSERT(g5_di[0x6cu] == 1u);
    TEST_ASSERT(g5_di[0x6du] == 'A');

    uint8_t g5_fs[G4MEDIA_FSYS_G5_FREE_SPACE_SIZE];
    memset(g5_fs, 0x55u, sizeof(g5_fs));
    TEST_ASSERT(g4media_c_fsys_get_free_space('A', g5_fs) == 0);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x00u) == 500000u);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x04u) == 400000u);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x08u) == 390000u);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x0cu) == 400000u);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x10u) == 0u);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x14u) == 0u);
    TEST_ASSERT(g4media_rd32(g5_fs + 0x18u) == 256u); /* spc */
    TEST_ASSERT(g4media_rd32(g5_fs + 0x1cu) == 512u); /* bps */
    TEST_ASSERT(g4media_rd32(g5_fs + 0x20u) == 0x20u);

    /* 未挂载时绝不造假，输出结构清零 */
    g_mock_sd_mounted = 0;
    memset(g5_fs, 0x77u, sizeof(g5_fs));
    TEST_ASSERT(g4media_c_fsys_get_free_space('A', g5_fs) != 0);
    for (size_t i = 0; i < G4MEDIA_FSYS_G5_FREE_SPACE_SIZE; i++) {
        TEST_ASSERT(g5_fs[i] == 0u);
    }
    printf("[PASS 11] v30 C-API Fsys_GetDriveInfo(0x7cB) 与 Fsys_GetFreeSpace(0x34B) 跨代对齐通过\n");

    /* 12. 缺失 6 符号语义检查 + GOT 批量安装清单 + mpr::Init/Load 包装 */
    g_mock_sd_inserted = 1;
    g_mock_sd_mounted  = 1;
    TEST_ASSERT(g4media_c_fsys_pg_enter('A') == 0);
    TEST_ASSERT(g4media_c_fsys_pg_exit('A') == 0);
    TEST_ASSERT(g4media_c_fsys_pg_start_wt('A') == 0);
    TEST_ASSERT(g4media_c_fsys_pg_stop_wt('A') == 0);
    TEST_ASSERT(g4media_c_fsys_lock("A:/DCIM", 1u) == 0);
    TEST_ASSERT(g4media_c_fsys_combine("A:/A.MP4", "A:/B.MP4") == 0);
    TEST_ASSERT(g4media_c_fsys_find_first("A:/PRIVATE/DATABASE/DATABASE.BIN", 0x80u, g5_di) == 2);
    TEST_ASSERT(g4media_c_fsys_stat("A:/DCIM", g5_fs) == 0);

    g_mock_sd_mounted = 0;
    TEST_ASSERT((uint32_t)g4media_c_fsys_pg_enter('A') == 0x80010002u);
    TEST_ASSERT((uint32_t)g4media_c_fsys_lock("A:/DCIM", 1u) == 0x80010002u);

    g_mock_got_rec_cnt = 0u;
    g4media_custom_got_hook_cb = mock_record_got_hook;
    g4media_orig_mpr_init = mock_real_mpr_init;
    g4media_orig_mpr_load = mock_real_mpr_load;
    g4media_orig_mpr_set_issue_event = mock_real_mpr_set_issue_event;
    g4media_install_c_fsys_got_hooks(0x10000000u, 0x20000000u, 0x30000000u);
    g4media_custom_got_hook_cb = NULL;
    /* libmp5 (6 + 15 + 1 SetIssueEvent + 1 GetMovieRecParam) + libOb5 (11) + appFw (11 + 5 mpr) = 50 GOT slots */
    TEST_ASSERT(g_mock_got_rec_cnt == 50u);

    uint8_t fake_load_param[0x30];
    memset(fake_load_param, 0, sizeof(fake_load_param));
    memcpy(fake_load_param + 0x08u, "/dev/mmca", 10u);
    fake_load_param[0x1du] = 'A';
    g4media_wr32(fake_load_param + 0x20u, 0x1000u);
    TEST_ASSERT(g4media_wrap_mpr_init(fake_load_param) == 0 && g_mock_mpr_init_calls == 1);
    TEST_ASSERT(g4media_wrap_mpr_load(fake_load_param) == 0 && g_mock_mpr_load_calls == 1);
    printf("[PASS 12] v31 缺失 6 符号语义、46 项 GOT 挂载清单与 mpr::Init/Load 探针全部通过\n");

    /* 13. v31 Open 错误码对齐 (0x80000030->0x80000051)、Chmod/Read/Write/WriteAndFlush 与 SetIssueEvent 探针 */
    g_mock_sd_inserted = 1;
    g_mock_sd_mounted  = 1;
    uint32_t open_fd = 0xdeadbeefu;
    TEST_ASSERT((uint32_t)g4media_c_fsys_open("A:/PRIVATE/DATABASE/DATABASE.BIN", &open_fd, 0x7u) == 0x80000051u);
    TEST_ASSERT(open_fd == 0u);
    TEST_ASSERT((uint32_t)g4media_c_fsys_open(NULL, &open_fd, 0x7u) == 0x80000030u);
    TEST_ASSERT(g4media_c_fsys_open("A:/DCIM/TEST.JPG", &open_fd, 0x1u) == 0 && open_fd == 0x101u);

    uint8_t io_buf[8] = {0};
    TEST_ASSERT(g4media_c_fsys_chmod("A:/DCIM/TEST.JPG", 0u) == 0);
    TEST_ASSERT(g4media_c_fsys_read(open_fd, io_buf, sizeof(io_buf)) == 8 && io_buf[0] == 0x22u);
    TEST_ASSERT(g4media_c_fsys_write(open_fd, io_buf, sizeof(io_buf)) == 8);
    TEST_ASSERT(g4media_c_fsys_write_and_flush(open_fd, io_buf, sizeof(io_buf)) == 8);

    g_mock_sd_mounted = 0;
    TEST_ASSERT((uint32_t)g4media_c_fsys_chmod("A:/DCIM/TEST.JPG", 0u) == 0x80010002u);
    TEST_ASSERT(g4media_c_fsys_read(open_fd, io_buf, sizeof(io_buf)) < 0);
    TEST_ASSERT(g4media_c_fsys_write(open_fd, io_buf, sizeof(io_buf)) < 0);
    TEST_ASSERT(g4media_c_fsys_write_and_flush(open_fd, io_buf, sizeof(io_buf)) < 0);

    uint8_t fake_evt[0x14];
    memset(fake_evt, 0, sizeof(fake_evt));
    g4media_wr32(fake_evt + 0x04u, 1u);
    g4media_wr32(fake_evt + 0x08u, 0u);
    g4media_wr32(fake_evt + 0x0cu, 0x1000u);
    fake_evt[0x10u] = 0u; fake_evt[0x11u] = 1u; fake_evt[0x12u] = 0u;
    TEST_ASSERT(g4media_wrap_mpr_set_issue_event(0x1002u, fake_evt, sizeof(fake_evt)) == 0);
    TEST_ASSERT(g_mock_mpr_evt_calls == 1 && g_mock_mpr_last_evt == 0x1002u);
    printf("[PASS 13] v31 Open 错误码转换、Chmod/Read/Write/WriteAndFlush 与 SetIssueEvent(0x1002) 通过\n");

    /* 14. v32 DMM unit_type=0x660 回退分配/释放 与 DcfNamer::GetRemainSlotFolders 空指针防崩护栏 */
    reset_bridge_state();
    g4media_orig_dmm_alloc_core     = mock_orig_dmm_alloc_null;
    g4media_orig_dmm_close_and_free = mock_orig_dmm_close_and_free;
    g4media_orig_dcf_load           = mock_orig_dcf_load;
    g4media_orig_dcf_remain_folders = mock_orig_dcf_remain;

    uint8_t out_unit[0x60];
    memset(out_unit, 0xaau, sizeof(out_unit));
    void *dmm_buf = g4media_hook_dmm_alloc_core(0x660u, 0u, 1u, 1u, out_unit, 1u, NULL);
    TEST_ASSERT(dmm_buf != NULL && g_mock_dmm_alloc_calls == 1);
    uint16_t synth_handle = g4media_rd16(out_unit + 0x04u);
    TEST_ASSERT(synth_handle == 0x7f00u);
    TEST_ASSERT(g4media_rd32(out_unit + 0x0cu) == 0x660u);
    TEST_ASSERT(g4media_rd32(out_unit + 0x10u) == 0x00113898u);
    TEST_ASSERT(g4media_rd32(out_unit + 0x50u) == (uint32_t)(uintptr_t)dmm_buf);
    TEST_ASSERT(((volatile uint8_t *)dmm_buf)[0] == 0u && ((volatile uint8_t *)dmm_buf)[0x113897u] == 0u);
    ((volatile uint8_t *)dmm_buf)[0x4e2u] = 0x5au;
    TEST_ASSERT(((volatile uint8_t *)dmm_buf)[0x4e2u] == 0x5au);

    /* 非 0x660 类型或非 cmd=1 失败不伪造分配 */
    TEST_ASSERT(g4media_hook_dmm_alloc_core(0x661u, 0u, 1u, 1u, out_unit, 1u, NULL) == NULL);

    /* 合成句柄走 close_and_free 自动 munmap，不透传给 Gen4 驱动；普通句柄正常透传 */
    TEST_ASSERT(g4media_hook_dmm_close_and_free(synth_handle) == 0);
    TEST_ASSERT(g_mock_dmm_close_calls == 0);
    TEST_ASSERT(g4media_dmm_slots[0].in_use == 0u);
    TEST_ASSERT(g4media_hook_dmm_close_and_free(0x1234u) == 0);
    TEST_ASSERT(g_mock_dmm_close_calls == 1 && g_mock_dmm_last_close_handle == 0x1234u);

    /* DcfNamer::GetRemainSlotFolders 空指针保护 */
    uint8_t *fake_mp5 = (uint8_t *)mmap(NULL, 0x290000u, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *fake_slots = (uint8_t *)mmap(NULL, G4MEDIA_DCF_SLOT_COUNT * G4MEDIA_DCF_SLOT_STRIDE,
                                          PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(fake_mp5 != MAP_FAILED && fake_slots != MAP_FAILED);
    *(uintptr_t *)(fake_mp5 + 0x002877a0u) = (uintptr_t)fake_slots;
    g4media_mp5_base = (uintptr_t)fake_mp5;

    fake_slots[0] = 1u; /* slot 0: loaded=1 但 files_ptr(0x6c)=NULL -> 应被清除 */
    g4media_wr32(fake_slots + 0x6cu, 0u);
    uint8_t *slot1 = fake_slots + G4MEDIA_DCF_SLOT_STRIDE;
    slot1[0] = 1u;      /* slot 1: loaded=1 且 files_ptr 非空 -> 应保持 */
    g4media_wr32(slot1 + 0x6cu, 0x12345678u);
    g4media_wr16(slot1 + 0x74u, 3u);

    TEST_ASSERT(g4media_hook_dcf_load(1u, 1u, NULL, 0u, 0u) == 0);
    TEST_ASSERT(g4media_hook_dcf_remain_folders(NULL, 0u, NULL) == 42u);
    TEST_ASSERT(g_mock_dcf_remain_calls == 1);
    TEST_ASSERT(fake_slots[0] == 0u);
    TEST_ASSERT(slot1[0] == 1u);

    munmap(fake_slots, G4MEDIA_DCF_SLOT_COUNT * G4MEDIA_DCF_SLOT_STRIDE);
    munmap(fake_mp5, 0x290000u);
    printf("[PASS 14] v32 DMM 0x660 回退分配/释放 与 DcfNamer 空指针护栏全部通过\n");

    /* 15. v33 MovieRemain / SetMovieRecParam / SetPlaybackParam / CalcMovieRemain / sidb::GetRemain 探针透传测试 */
    reset_bridge_state();
    g4media_orig_mpr_set_issue_event               = mock_real_mpr_set_issue_event;
    g4media_orig_mpr_get_movie_remain              = mock_orig_get_movie_remain;
    g4media_orig_mpr_set_movie_rec_param           = mock_orig_set_movie_rec_param;
    g4media_orig_mpr_set_playback_param            = mock_orig_set_playback_param;
    g4media_orig_mpr_get_movie_rec_status_internal = mock_orig_get_movie_rec_status_internal;
    g4media_orig_calc_movie_remain                 = mock_orig_calc_movie_remain;
    g4media_orig_sidb_get_remain                   = mock_orig_sidb_get_remain;

    uint8_t mov_in[G4MEDIA_MOVIE_REMAIN_IN_SIZE] = {0}, mov_out[24] = {0}, rec_p[G4MEDIA_MOVIE_REC_PARAM_SIZE] = {0}, pb_p[16] = {0}, evt4[16] = {0};
    g4media_wr32(mov_in, 4096u);
    TEST_ASSERT(g4media_wrap_mpr_get_movie_remain(mov_in, mov_out) == 0);
    TEST_ASSERT(g_mock_get_movie_remain_calls == 1 && g4media_rd32(mov_out + 0x04u) == 75u);
    TEST_ASSERT(g4media_wrap_mpr_set_movie_rec_param(rec_p) == 0 && g_mock_set_movie_rec_param_calls == 1);
    TEST_ASSERT(g4media_wrap_mpr_set_playback_param(pb_p) == 0 && g_mock_set_playback_param_calls == 1);
    TEST_ASSERT(g4media_hook_calc_movie_remain(0u, 0u, 0u, 0u) == 0 && g_mock_calc_movie_remain_calls == 1);
    uint32_t sidb_rem = 0u;
    TEST_ASSERT(g4media_hook_sidb_get_remain(4096u, 4u, &sidb_rem) == 0 && g_mock_sidb_get_remain_calls == 1 && sidb_rem == 1234u);
    TEST_ASSERT(g4media_wrap_mpr_set_issue_event(0x1004u, evt4, sizeof(evt4)) == 0 && g_mock_mpr_last_evt == 0x1004u);
    printf("[PASS 15] v33 MovieRemain / SetMovieRecParam / SetPlaybackParam / CalcMovieRemain / sidb::GetRemain 探针通过\n");

    /* 16. v34 MovieRecParam / GetMovieRecParam / GetMovieRemain 码率与音频参数规范化测试 */
    reset_bridge_state();
    g4media_orig_mpr_set_movie_rec_param = mock_orig_set_movie_rec_param;
    g4media_orig_mpr_get_movie_rec_param = mock_orig_get_movie_rec_param;
    g4media_orig_mpr_get_movie_remain    = mock_orig_get_movie_remain;

    TEST_ASSERT(g4media_video_bitrate_kbps(0u) == 0u);
    TEST_ASSERT(g4media_video_bitrate_kbps(1u) == 0u);
    TEST_ASSERT(g4media_video_bitrate_kbps(5u) == 0u);
    TEST_ASSERT(g4media_video_bitrate_kbps(9u) == 0u);
    TEST_ASSERT(g4media_video_bitrate_kbps(0x36u) == 0u);
    TEST_ASSERT(g4media_video_bitrate_kbps(0x0eu) == 50000u);
    TEST_ASSERT(g4media_video_bitrate_kbps(0x11u) == 600000u);
    TEST_ASSERT(g4media_video_bitrate_kbps(0x1au) == 9000u);

    /* (a) 合法参数应原样保留，一字节不改 */
    uint8_t valid_rec[G4MEDIA_MOVIE_REC_PARAM_SIZE];
    memset(valid_rec, 0, sizeof(valid_rec));
    g4media_wr32(valid_rec + 0x04u, 0x1000u);
    valid_rec[0x24u] = 1u; /* allowRecord=1, relay/simul/isolate/sub156=0 才是合法单卡参数 */
    g4media_wr32(valid_rec + 0x128u, 3u);
    g4media_wr32(valid_rec + 0x12cu, 0x11u);
    g4media_wr32(valid_rec + 0x130u, 2u);
    g4media_wr32(valid_rec + 0x13cu, 1u);
    g4media_wr32(valid_rec + 0x140u, 2u);
    valid_rec[0x156u] = 0u;
    g4media_wr32(valid_rec + 0x158u, 2u);
    g4media_wr32(valid_rec + 0x15cu, 0x1au);
    g4media_wr32(valid_rec + 0x160u, 6u);
    g4media_wr32(valid_rec + 0x16cu, 3u);
    g4media_wr32(valid_rec + 0x170u, 1u);
    TEST_ASSERT(g4media_wrap_mpr_set_movie_rec_param(valid_rec) == 0);
    TEST_ASSERT(memcmp(g_mock_last_movie_rec_param, valid_rec, sizeof(valid_rec)) == 0);

    /* (b) 全零主视频+开启 simulRec 但 sub_VQuality=0 场景 -> 必须规范化到有效表项 */
    uint8_t bad_rec[G4MEDIA_MOVIE_REC_PARAM_SIZE];
    memset(bad_rec, 0, sizeof(bad_rec));
    g4media_wr32(bad_rec + 0x04u, 0x1000u);
    bad_rec[0x0cu] = 1u;
    bad_rec[0x156u] = 1u;
    TEST_ASSERT(g4media_wrap_mpr_set_movie_rec_param(bad_rec) == 0);
    TEST_ASSERT(g4media_video_bitrate_kbps(g4media_rd32(g_mock_last_movie_rec_param + 0x12cu)) > 0u);
    TEST_ASSERT(g4media_is_valid_audio_param(g4media_rd32(g_mock_last_movie_rec_param + 0x13cu),
                                             g4media_rd32(g_mock_last_movie_rec_param + 0x140u)) == 1);
    TEST_ASSERT(g4media_video_bitrate_kbps(g4media_rd32(g_mock_last_movie_rec_param + 0x15cu)) > 0u);
    TEST_ASSERT(g4media_is_valid_audio_param(g4media_rd32(g_mock_last_movie_rec_param + 0x16cu),
                                             g4media_rd32(g_mock_last_movie_rec_param + 0x170u)) == 1);

    /* (c) GetMovieRecParam 返回 InitMovieRecParam 默认 0xff/5/0xff 时应就地修复 */
    memset(g_mock_seed_get_movie_rec_param, 0, sizeof(g_mock_seed_get_movie_rec_param));
    g4media_wr32(g_mock_seed_get_movie_rec_param + 0x128u, 0xcu);
    g4media_wr32(g_mock_seed_get_movie_rec_param + 0x12cu, 0xffu);
    g4media_wr32(g_mock_seed_get_movie_rec_param + 0x130u, 0xcu);
    g4media_wr32(g_mock_seed_get_movie_rec_param + 0x13cu, 5u);
    g4media_wr32(g_mock_seed_get_movie_rec_param + 0x140u, 0xffu);
    uint8_t got_rec[G4MEDIA_MOVIE_REC_PARAM_SIZE];
    memset(got_rec, 0, sizeof(got_rec));
    TEST_ASSERT(g4media_wrap_mpr_get_movie_rec_param(got_rec) == 0 && g_mock_get_movie_rec_param_calls == 1);
    TEST_ASSERT(g4media_rd32(got_rec + 0x128u) < 0xcu);
    TEST_ASSERT(g4media_video_bitrate_kbps(g4media_rd32(got_rec + 0x12cu)) > 0u);
    TEST_ASSERT(g4media_rd32(got_rec + 0x130u) < 0xcu);
    TEST_ASSERT(g4media_is_valid_audio_param(g4media_rd32(got_rec + 0x13cu), g4media_rd32(got_rec + 0x140u)) == 1);

    /* (d) GetMovieRemain 输入规范化 */
    uint8_t bad_min[G4MEDIA_MOVIE_REMAIN_IN_SIZE];
    memset(bad_min, 0, sizeof(bad_min));
    g4media_wr32(bad_min + 0x04u, 0x1000u);
    bad_min[0x20u] = 1u;
    TEST_ASSERT(g4media_wrap_mpr_get_movie_remain(bad_min, mov_out) == 0);
    TEST_ASSERT(g4media_video_bitrate_kbps(g4media_rd32(g_mock_last_movie_remain_in + 0x14u)) > 0u);
    TEST_ASSERT(g4media_is_valid_audio_param(g4media_rd32(g_mock_last_movie_remain_in + 0x18u),
                                             g4media_rd32(g_mock_last_movie_remain_in + 0x1cu)) == 1);
    TEST_ASSERT(g4media_video_bitrate_kbps(g4media_rd32(g_mock_last_movie_remain_in + 0x30u)) > 0u);
    printf("[PASS 16] v34 MovieRecParam / GetMovieRecParam / GetMovieRemain 规范化全部通过\n");

    /* 17. v35 GetStatus 真实盘符门槛校验：未挂载时绝不伪报 mounted=1，挂载分配 'A' 后正确补全 */
    g4media_app_base = (uintptr_t)fake_app;
    *(uint32_t *)(fake_app + G4MEDIA_OFF_MEDIA_CNT) = 2u;
    g4media_set_slot1_media_id(0x1000u);
    g4media_orig_get_status = NULL;
    g4media_g4_fsys.available = 1;
    g4media_g4_fsys.get_mount_drives = mock_g4_get_mount_drives;
    g4media_g4_fsys.get_drive_letter = mock_g4_get_drive_letter;
    g_mock_sd_inserted = 1;
    g_mock_sd_mounted = 0;
    g4media_get_status_out_t st_unmounted;
    memset(&st_unmounted, 0, sizeof(st_unmounted));
    st_unmounted.mounted = 1u;
    g4media_hook_get_status(&mid_sd, &st_unmounted);
    TEST_ASSERT(st_unmounted.mounted == 0u);

    g4media_orig_get_status = mock_orig_get_status_zero;
    g_mock_sd_mounted = 1;
    g4media_get_status_out_t st_mounted;
    g4media_hook_get_status(&mid_sd, &st_mounted);
    TEST_ASSERT(st_mounted.status == 0u && st_mounted.mounted == 1u && st_mounted.badblk == 0u);
    printf("[PASS 17] v35 GetStatus 真实盘符门槛校验通过\n");

    /* 18. v36 单卡槽 MovieRecParam 精确位宽置位(不踩踏相邻字节) 与 libmp5 按值传参结构体尺寸/对齐断言 */
    TEST_ASSERT(sizeof(g4media_mov_remain_in_val_t) == 0x3cu);
    TEST_ASSERT(sizeof(g4media_movie_rec_val_t) == 0x188u);
    TEST_ASSERT(_Alignof(g4media_movie_rec_val_t) == 8u);

    uint8_t v36_rec[G4MEDIA_MOVIE_REC_PARAM_SIZE];
    memset(v36_rec, 0, sizeof(v36_rec));
    v36_rec[0x00u] = 1u; /* relayRec */
    v36_rec[0x01u] = 0xa1u; v36_rec[0x02u] = 0xb2u; v36_rec[0x03u] = 0xc3u;
    g4media_wr32(v36_rec + 0x04u, 0x1000u);
    v36_rec[0x0cu] = 1u; /* simulRec */
    v36_rec[0x0du] = 0xd4u;
    v36_rec[0x24u] = 0u; /* allowRecord */
    v36_rec[0x25u] = 0xe5u;
    g4media_wr32(v36_rec + 0x28u, 2u); /* dual-slot mode */
    v36_rec[0x38u] = 1u; /* isolate */
    v36_rec[0x39u] = 0xf6u;
    v36_rec[0x154u] = 0x5au;
    v36_rec[0x155u] = 0x6bu;
    v36_rec[0x156u] = 1u; /* sub156 */
    v36_rec[0x157u] = 0x7cu;
    g4media_wr32(v36_rec + 0x128u, 1u);
    g4media_wr32(v36_rec + 0x12cu, 0x0eu);
    g4media_wr32(v36_rec + 0x130u, 0u);
    g4media_wr32(v36_rec + 0x13cu, 0u);
    g4media_wr32(v36_rec + 0x140u, 2u);

    memset(g_mock_last_movie_rec_param, 0, sizeof(g_mock_last_movie_rec_param));
    TEST_ASSERT(g4media_wrap_mpr_set_movie_rec_param(v36_rec) == 0);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x00u] == 0u);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x01u] == 0xa1u && g_mock_last_movie_rec_param[0x02u] == 0xb2u && g_mock_last_movie_rec_param[0x03u] == 0xc3u);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x0cu] == 0u && g_mock_last_movie_rec_param[0x0du] == 0xd4u);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x24u] == 1u && g_mock_last_movie_rec_param[0x25u] == 0xe5u);
    TEST_ASSERT(g4media_rd32(g_mock_last_movie_rec_param + 0x28u) == 0u);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x38u] == 0u && g_mock_last_movie_rec_param[0x39u] == 0xf6u);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x154u] == 0x5au && g_mock_last_movie_rec_param[0x155u] == 0x6bu);
    TEST_ASSERT(g_mock_last_movie_rec_param[0x156u] == 0u && g_mock_last_movie_rec_param[0x157u] == 0x7cu);
    TEST_ASSERT(g_mock_last_movie_remain_in[0x20u] == 0u);
    printf("[PASS 18] v36 单卡 MovieRecParam 位宽保护与 AAPCS 结构体布局校验通过\n");

    munmap(fake_app, map_sz);
    printf("=== 全部 18 项单元测试全部通过！===\n");
    return 0;
}
