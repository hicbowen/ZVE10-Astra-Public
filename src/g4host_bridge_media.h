/**
 * @file g4host_bridge_media.h
 * @brief ZV-E10 四代宿主移植五代 ASTRA 跨代桥接层 —— 模块 2：存储与联锁层桥接实现 (v34 录像 0min MovieRecParam 参数规范化与全链路诊断版)
 *
 * 根因与架构说明 (经实机日志、appFw.so 及四代 libObj.so/libInfraMediaDetect.so/libInfraFsys.so 二进制交叉实证)：
 * 1. 属性索引代际失配 (libObj.so @ 0x172760 vs libOb5.so @ 0x2a4180):
 *    - 五代新增 0x08=SLOT_1, 0x09=SLOT_2, 0x0a=SLOT_UTL_ONLY, 0x0b=SLOT_SSD；四代 libObj.so 在 0x08..0x0b 全空。
 *    - 四代 Slot1 物理 SD 卡 (0x1000) 使用 0x48=ADJ_SLOT_1 (以及 0x42=REMOVABLEMEDIA1, 0x45=REMOVABLE)，
 *      而 0x4000 为 /nondev/simulate (带 0x27=SIMULATE)。
 *    - 旧版 InitMedia (0x02b72ca0) 仅检查 flags[0x08]/flags[0x09]，导致真实 Slot1 (0x1000) 被判为 type=3 屏蔽，
 *      同时旧版将 G4MEDIA_G4_MEDIA_ID_SD 错误硬编码为 0x4000，把 /nondev/simulate 误当真实 SD 卡。
 * 2. 物理卡在位检测根因修复 (严防对空槽或 /nondev/simulate 造假):
 *    - libObj.so:GetMediaInfo (0x1000 -> 0x00cf016d) 仅查询静态配置表，无论是否插卡恒返回 err=0, valid=1，
 *      绝不能用作物理卡在位判据！
 *    - 真实硬件在位判据仅来自：(a) libInfraFsys.so:Fsys_GetDriveLetter(dev_name) != 0 (PrFILE2 已挂载)，或
 *      (b) 向四代 libInfraMediaDetect.so (0x00af816f) 发送同步 UIPC 0x11002 (GetInOutStatus) 查询 ThreadRM，
 *      其底层调用 mcmn_drv_checkmediaexist 返回 inserted==1 (且显式排除 media_type==2 SIMULATE / /nondev/)。
 * 3. StartInOut / ExecMount / Fsys / 联锁对齐：
 *    - 修复 InitMedia (0x02b72ca0) 将 flags[0x48]/[0x49] 识别为 Slot1/Slot2 并动态捕获真实 Slot1 media_id；
 *    - 修复 GetMediaInfo (0x02b72fc8) 跨代映射 flags[0x48]->flags[0x08]、flags[0x49]->flags[0x09]，绝不污染 SIMULATE；
 *    - 修复 GetStatus (0x02b73700) 0x11002->0x11003、Cmd_11009/Cmd_11008、Fsys_* 结构体翻译及 check_media_status 条件联锁。
 *
 * 规范约束：
 * - 纯头文件封装，所有内部符号均以 g4media_ 为前缀并加 static / static inline，零全局符号污染。
 * - 严禁对空卡槽或 /nondev/simulate 伪造卡在位；QEMU 下无 libInfraFsys.so 时安全透传。
 */

#ifndef G4HOST_BRIDGE_MEDIA_H
#define G4HOST_BRIDGE_MEDIA_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD 0x00004
#endif

/* ========================================================================= */
/* 1. 宿主基础工具前向声明                                                    */
/* ========================================================================= */
#ifndef G4HOST_TOOL_DECLS
#define G4HOST_TOOL_DECLS
static void logf_(const char *fmt, ...);
static void patch_thumb_jump(void *target, void *replacement, const char *name);
static void *make_thumb_trampoline_8(uintptr_t va, void *hook_fn, const char *name);
#endif

/* ========================================================================= */
/* 2. 偏移、签名与协议常量定义                                                */
/* ========================================================================= */

/* 五代 ASTRA appFw.so 媒体控制与联锁相关偏移 (4B 对齐 Thumb 入口) */
#define G4MEDIA_OFF_INFRA_INPUT_CB         0x02b72accu /* libOb5:InfraInput 媒体插拔事件回调 */
#define G4MEDIA_OFF_INIT_MEDIA             0x02b72ca0u /* MediaInit: 填充 g_media_tbl 并注册 InfraInputCb */
#define G4MEDIA_OFF_INIT_FLAG_SLOT1_INSN   0x02b72d90u /* ldrb.w r3, [r7, #0x68] (flags[0x08] -> 0xa8 flags[0x48]) */
#define G4MEDIA_OFF_INIT_FLAG_SLOT2_INSN   0x02b72d9au /* ldrb.w r3, [r7, #0x69] (flags[0x09] -> 0xa9 flags[0x49]) */
#define G4MEDIA_OFF_GET_MEDIA_INFO         0x02b72fc8u /* MediaCommon::GetMediaInfo (Cmd 0x1000) */
#define G4MEDIA_OFF_RPC_11000              0x02b730b8u /* MediaDetect::StartInOut (Cmd 0x11000) */
#define G4MEDIA_OFF_RPC_12001              0x02b73424u /* MediaDetect::StartTemp (Cmd 0x12001) */
#define G4MEDIA_OFF_RPC_12002              0x02b734d8u /* MediaDetect::StopTemp (Cmd 0x12002) */
#define G4MEDIA_OFF_MOUNT                  0x02b7358cu /* MediaMount::Mount (Cmd 0x21000) */
#define G4MEDIA_OFF_GET_STATUS             0x02b73700u /* MediaMount::GetStatus (五代 0x11002 -> 四代 0x11003) */
#define G4MEDIA_OFF_GET_STATUS_CMD_LIT     0x02b737e8u /* GetStatus 字面量池中的命令字 (0x11002) */
#define G4MEDIA_OFF_CMD_11009              0x02b73800u /* MediaMount::Cmd_11009 (exec_mount 前置校验) */
#define G4MEDIA_OFF_CMD_11008              0x02b738c8u /* MediaMount::Cmd_11008 (设备路径名查询) */
#define G4MEDIA_OFF_FSYS_MOUNT             0x02b7392cu /* Fsys::Mount 包装器 */
#define G4MEDIA_OFF_FSYS_GET_DRIVE_LETTER  0x02b73a2cu /* Fsys::GetDriveLetter 包装器 */
#define G4MEDIA_OFF_FSYS_GET_DRIVE_INFO    0x02b73a3cu /* Fsys::GetDriveInfo 包装器 */
#define G4MEDIA_OFF_FSYS_GET_DEVICE_INFO   0x02b73b00u /* Fsys::GetDeviceInfo 包装器 */
#define G4MEDIA_OFF_FSYS_GET_FREE_SPACE    0x02b73ce8u /* Fsys::GetFreeSpace 包装器 #1 (0x38B 输出) */
#define G4MEDIA_OFF_FSYS_GET_FREE_SPACE2   0x02b73e80u /* Fsys::GetFreeSpace 包装器 #2 (0x14B avail/total/status) */
#define G4MEDIA_OFF_OSAL_SND_SYNC          0x02bb60bcu /* appFw 同步 MWF 发送封装 (msg, sz, target, cb, wait) */
#define G4MEDIA_OFF_NOTIFY_MEDIA_STATUS    0x02af9e04u /* sequence_still_record::notify_initial_media_status */
#define G4MEDIA_OFF_CHECK_MEDIA_STATUS     0x02af95e8u /* sequence_still_record 内部媒体联锁检查器 */
#define G4MEDIA_OFF_ALLOW_REC_BNE          0x02b8af5eu /* mpr_SetMovieRecParam builder 中 allowRecord 分支 */

/* 五代 appFw.so 全局媒体条目表 (InitMedia @ 0x02b72ca0 填充, 0x02b728c8 检索) */
#define G4MEDIA_OFF_MEDIA_TBL              0x082b86e0u /* 媒体条目数组基址 (每项 0x24 字节) */
#define G4MEDIA_OFF_MEDIA_CNT              0x082b8920u /* 有效条目数量 (uint32_t) */
#define G4MEDIA_MAX_MEDIA_ENTRIES          16u
#define G4MEDIA_DEV_CACHE_CAP              4u

/* Gen4 libObj.so vs Gen5 libOb5.so 媒体属性标志位索引 (二进制交叉实证) */
#define G4MEDIA_ATTR_ALLMEDIAID            0x00u
#define G4MEDIA_ATTR_SLOT_1_G5             0x08u
#define G4MEDIA_ATTR_SLOT_2_G5             0x09u
#define G4MEDIA_ATTR_USE_FSYS              0x10u
#define G4MEDIA_ATTR_USE_MEDIAMOUNT        0x11u
#define G4MEDIA_ATTR_MOVIESTILL            0x20u
#define G4MEDIA_ATTR_PC_APP                0x23u
#define G4MEDIA_ATTR_SIMULATE              0x27u
#define G4MEDIA_ATTR_FIXED                 0x40u
#define G4MEDIA_ATTR_REMOVABLEMEDIA1       0x42u
#define G4MEDIA_ATTR_REMOVABLE             0x45u
#define G4MEDIA_ATTR_ADJ_SLOT_1_G4         0x48u
#define G4MEDIA_ATTR_ADJ_SLOT_2_G4         0x49u

/* 协议与错误码常量 */
#define G4MEDIA_TARGET_MEDIA_DETECT        0x00af816fu /* 四代 libInfraMediaDetect.so MWF 目标 ID */
#define G4MEDIA_CMD_GET_INOUT_STATUS       0x00011002u /* 四代 MediaDetect::GetInOutStatus (min_sz=0x18) */
#define G4MEDIA_CMD_GET_STATUS_G5          0x00011002u /* 五代 MediaMount::GetStatus */
#define G4MEDIA_CMD_GET_STATUS_G4          0x00011003u /* 四代 MediaMount::GetStatus */
#define G4MEDIA_G4_MEDIA_ID_SD_DEFAULT     0x00001000u /* 四代真实 Slot1 SD 卡默认 media_id (0x4000 为 /nondev/simulate) */
#define G4MEDIA_G4_MEDIA_ID_SIMULATE_DEF   0x00004000u /* /nondev/simulate 典型 media_id */
#define G4MEDIA_FALLBACK_DCF_HANDLE        0x40000002u
#define G4MEDIA_ERR_ALREADY_STARTED_G5     0x00000016u /* conv_detect(0x2 = ER_ALREADY_START) = 22 */
#define G4MEDIA_ERR_ALREADY_MOUNT_G5       0x00000024u /* conv(0xa = ER_ALREADY_MOUNT) */
#define G4MEDIA_ERR_UNSUPPORTED_G5         0x0000001bu /* conv(0x1) = 27 */
#define G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G4  0x80000021u /* conv_fsys_err -> 0x2d */
#define G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G5  0x0000002du

/* ========================================================================= */
/* 3. 跨代数据结构体定义                                                      */
/* ========================================================================= */

/** 五代 g_media_tbl 单项布局 (0x24 = 36 字节) */
typedef struct {
    uint32_t media_id;    /* +0x00 */
    uint32_t ev_attr;     /* +0x04 */
    uint32_t media_type;  /* +0x08 (3 为跳过/虚拟项; 0=slotA, 1=slotB) */
    uint32_t handle;      /* +0x0c */
    uint32_t pad10[2];    /* +0x10..+0x17 */
    uint32_t drv_id;      /* +0x18 */
    uint32_t pad1c;       /* +0x1c */
    uint8_t  mounted;     /* +0x20 */
    uint8_t  pad21[3];    /* +0x21..+0x23 */
} g4media_tbl_entry_t;

_Static_assert(sizeof(g4media_tbl_entry_t) == 0x24u, "g4media_tbl_entry_t must be 36 bytes");

/** 五代 GetMediaInfo (0x02b72fc8) 输入结构体 (8 字节) */
typedef struct {
    uint32_t media_id;     /* +0x00 */
    char    *out_dev_name; /* +0x04 (至少 21 字节缓冲区) */
} g4media_get_info_in_t;

/** 五代 GetMediaInfo (0x02b72fc8) 输出结构体 (0x8c 字节) */
typedef struct {
    uint8_t  valid;        /* +0x00 */
    uint8_t  pad1[3];      /* +0x01..+0x03 */
    uint32_t dev_type;     /* +0x04 */
    uint8_t  flags[0x80];  /* +0x08..+0x87 (其中 +0x19 对应 flags[0x11]) */
    uint32_t err;          /* +0x88 */
} g4media_get_info_out_t;

_Static_assert(sizeof(g4media_get_info_out_t) == 0x8cu, "g4media_get_info_out_t must be 0x8c bytes");

/** 五代 GetStatus (0x02b73700) 输出结构体 (0x0c 字节) */
typedef struct {
    uint32_t status;       /* +0x00 */
    uint8_t  mounted;      /* +0x04 */
    uint8_t  badblk;       /* +0x05 */
    uint8_t  wp;           /* +0x06 */
    uint8_t  ro;           /* +0x07 */
    uint32_t drv_id;       /* +0x08 */
} g4media_get_status_out_t;

_Static_assert(sizeof(g4media_get_status_out_t) == 0x0cu, "g4media_get_status_out_t must be 0x0c bytes");

/** 五代 Cmd_11009 (0x02b73800) 输出结构体 (0x14 字节) */
typedef struct {
    uint32_t status;       /* +0x00 (须为 0) */
    uint8_t  ok_flag;      /* +0x04 (须非 0) */
    uint8_t  pad5[3];      /* +0x05..+0x07 */
    uint32_t val8;         /* +0x08 (须 <= 0x63) */
    uint32_t valC;         /* +0x0c (须非 0) */
    uint32_t val10;        /* +0x10 */
} g4media_cmd11009_out_t;

_Static_assert(sizeof(g4media_cmd11009_out_t) == 0x14u, "g4media_cmd11009_out_t must be 0x14 bytes");

/** 五代 Cmd_11008 (0x02b738c8) 输入结构体 */
typedef struct {
    uint32_t media_id;     /* +0x00 */
    char    *out_name;     /* +0x04 (至少 21 字节缓冲区, out_name[20] 须为 0) */
} g4media_cmd11008_in_t;

/** 五代 Fsys_Mount (0x02b7392c) 输入/输出结构体 (实证: +0x00 为 const char *dev_name) */
typedef struct {
    const char *dev_name;  /* +0x00 (如 "/dev/mmca") */
    uint8_t     rw_flag;   /* +0x04 (0->0x100, 非0->0x300) */
    uint8_t     pad5[3];   /* +0x05..+0x07 */
} g4media_fsys_mount_in_t;

typedef struct {
    uint32_t status;       /* +0x00 */
    uint8_t  drv_letter;   /* +0x04 */
    uint8_t  pad5[3];      /* +0x05..+0x07 */
} g4media_fsys_mount_out_t;

/** 五代 Fsys_GetDriveLetter (0x02b73a2c) & Fsys_GetDeviceInfo (0x02b73b00) 输入结构体 */
typedef struct {
    const char *dev_name;  /* +0x00 */
} g4media_fsys_devname_in_t;

/** 五代 Fsys_GetDriveInfo (0x02b73a3c) 与 Fsys_GetDeviceInfo (0x02b73b00) 输出结构体 (0x54 字节) */
typedef struct {
    uint32_t status;            /* +0x00 */
    uint8_t  b4;                /* +0x04 */
    uint8_t  b5;                /* +0x05 */
    uint8_t  b6;                /* +0x06 */
    uint8_t  b7;                /* +0x07 */
    uint32_t media_type;        /* +0x08 */
    uint32_t volume_id;         /* +0x0c */
    char     volume_label[0x40];/* +0x10..+0x4f */
    uint8_t  fs_type_g5;        /* +0x50 (0x40=exFAT, 0x10=FAT, 0x14=0x8200) */
    uint8_t  pad51[3];          /* +0x51..+0x53 */
} g4media_fsys_info_out_t;

_Static_assert(sizeof(g4media_fsys_info_out_t) == 0x54u, "g4media_fsys_info_out_t must be 0x54 bytes");

/** 五代 Fsys_GetFreeSpace #1 (0x02b73ce8) 输出结构体 (0x38 字节) */
typedef struct {
    uint32_t status;
    uint32_t pad4;
    uint64_t bytes_08;
    uint64_t bytes_10;
    uint64_t bytes_18;
    uint64_t bytes_20;
    uint64_t bytes_28;
    uint64_t bytes_30;
} g4media_fsys_freespace_out_t;

_Static_assert(sizeof(g4media_fsys_freespace_out_t) == 0x38u, "g4media_fsys_freespace_out_t must be 0x38 bytes");

/** 五代 Fsys_GetFreeSpace #2 (0x02b73e80) 输出结构体 (严格 0x14 字节: 避免 uint64_t 尾对齐导致 0x18 踩栈) */
typedef struct {
    uint32_t avail_lo; /* +0x00 */
    uint32_t avail_hi; /* +0x04 */
    uint32_t total_lo; /* +0x08 */
    uint32_t total_hi; /* +0x0c */
    uint32_t status;   /* +0x10 */
} g4media_fsys_freespace2_out_t;

_Static_assert(sizeof(g4media_fsys_freespace2_out_t) == 0x14u, "g4media_fsys_freespace2_out_t must be 0x14 bytes");

/** 四代 libInfraFsys.so 导出符号函数表 (真实原型实证对齐) */
typedef uint32_t (*g4media_g4_get_mount_drives_fn_t)(void);
typedef uint8_t  (*g4media_g4_get_drive_letter_fn_t)(const char *dev_name);
typedef int      (*g4media_g4_fsys_mount_fn_t)(const char *dev_name, uint32_t mode, uint8_t *out_drv);
typedef int      (*g4media_g4_fsys_mount4_fn_t)(const char *dev_name, uint32_t mode, uint8_t *out_drv, void *opt);
typedef int      (*g4media_g4_fsys_unmount_fn_t)(uint8_t drv_letter, uint32_t opt);
typedef int      (*g4media_g4_fsys_drive_info_fn_t)(uint8_t drv_letter, void *g4_buf);
typedef int      (*g4media_g4_fsys_device_info_fn_t)(const char *dev_name, void *g4_buf);
typedef int      (*g4media_g4_fsys_free_fn_t)(uint8_t drv_letter, void *g4_buf);
typedef int      (*g4media_g4_fsys_find_first_fn_t)(const char *pattern, uint32_t attr, void *out_find_info);
typedef int      (*g4media_g4_fsys_find_next_fn_t)(void *find_info);
typedef int      (*g4media_g4_fsys_stat_fn_t)(const char *path, void *out_stat);
typedef int      (*g4media_g4_fsys_open_fn_t)(const char *path, uint32_t *out_fd, uint32_t mode);
typedef int      (*g4media_g4_fsys_close_fn_t)(uint32_t fd);
typedef int      (*g4media_g4_fsys_path_fn_t)(const char *path);
typedef int      (*g4media_g4_fsys_chmod_fn_t)(const char *path, uint32_t mode);
typedef int      (*g4media_g4_fsys_read_fn_t)(uint32_t fd, void *buf, uint32_t len);
typedef int      (*g4media_g4_fsys_write_fn_t)(uint32_t fd, const void *buf, uint32_t len);

typedef struct {
    int                               resolved;
    int                               available;
    g4media_g4_get_mount_drives_fn_t  get_mount_drives;
    g4media_g4_get_drive_letter_fn_t  get_drive_letter;
    g4media_g4_fsys_mount_fn_t        fsys_mount;
    g4media_g4_fsys_drive_info_fn_t   get_drive_info;
    g4media_g4_fsys_device_info_fn_t  get_device_info;
    g4media_g4_fsys_free_fn_t         get_free_space;
    g4media_g4_fsys_mount4_fn_t       fsys_mount4;
    g4media_g4_fsys_unmount_fn_t      fsys_unmount;
    g4media_g4_fsys_find_first_fn_t   find_first;
    g4media_g4_fsys_find_next_fn_t    find_next;
    g4media_g4_fsys_stat_fn_t         f_stat;
    g4media_g4_fsys_open_fn_t         f_open;
    g4media_g4_fsys_close_fn_t        f_close;
    g4media_g4_fsys_path_fn_t         f_mkdir;
    g4media_g4_fsys_path_fn_t         f_remove;
    g4media_g4_fsys_chmod_fn_t        f_chmod;
    g4media_g4_fsys_read_fn_t         f_read;
    g4media_g4_fsys_write_fn_t        f_write;
    g4media_g4_fsys_write_fn_t        f_write_and_flush;
} g4media_fsys_api_t;

typedef struct {
    uint32_t media_id;
    uint8_t  drv_letter;
    char     dev_name[32];
} g4media_dev_cache_entry_t;

/** 四代 libInfraMediaDetect.so 0x11002 (GetInOutStatus) 同步 UIPC 消息 (0x30 = 48 字节) */
typedef struct {
    uint32_t cmd;          /* +0x00: 0x00011002 */
    uint16_t ver;          /* +0x04: 1 */
    uint16_t payload_sz;   /* +0x06: 0x18 */
    uint32_t media_id;     /* +0x08 */
    uint32_t err_code;     /* +0x0c */
    uint32_t pad10[2];     /* +0x10..+0x17 */
    uint8_t  hold_flag;    /* +0x18 (out[0]) */
    uint8_t  inserted;     /* +0x19 (out[1]: 1=物理卡在位, 0=空卡槽) */
    uint8_t  media_type;   /* +0x1a (out[2]: 2=MS, 3=SD, 4=SSD) */
    uint8_t  ev_attr;      /* +0x1b (out[3]) */
    uint16_t device_id;    /* +0x1c (out[4..5]: 0xd100=/dev/mmca, 0xd110=/dev/mmcaa) */
    uint8_t  tail[18];     /* +0x1e..+0x2f */
} g4media_inout_status_msg_t;

_Static_assert(sizeof(g4media_inout_status_msg_t) == 0x30u, "g4media_inout_status_msg_t must be 0x30 bytes");

/* 原函数跳板原型 */
typedef void (*g4media_infra_input_cb_t)(int ch, void *ev_ptr);
typedef int  (*g4media_query_inout_fn_t)(uint32_t media_id, uint8_t *out_inserted, uint16_t *out_dev_id);
typedef int  (*g4media_osal_snd_sync_fn_t)(void *msg_buf, uint32_t msg_size, uint32_t target_id, void *cb, uint32_t wait_reply);
typedef void (*g4media_init_media_fn_t)(void);
typedef void (*g4media_get_media_info_fn_t)(g4media_get_info_in_t *in, g4media_get_info_out_t *out);
typedef int  (*g4media_rpc_fn_t)(void *param_in, uint32_t *status_out);
typedef void (*g4media_mount_fn_t)(uint32_t *media_id_in, uint32_t *status_out);
typedef void (*g4media_get_status_fn_t)(uint32_t *media_id_in, g4media_get_status_out_t *out);
typedef void (*g4media_cmd11009_fn_t)(uint32_t *media_id_in, g4media_cmd11009_out_t *out);
typedef void (*g4media_cmd11008_fn_t)(g4media_cmd11008_in_t *in, uint32_t *status_out);
typedef void (*g4media_fsys_mount_fn_t)(g4media_fsys_mount_in_t *in, g4media_fsys_mount_out_t *out);
typedef void (*g4media_fsys_get_drv_letter_fn_t)(g4media_fsys_devname_in_t *in, uint8_t *out_drv);
typedef void (*g4media_fsys_drive_info_fn_t)(uint8_t *drv_letter_ptr, g4media_fsys_info_out_t *out);
typedef void (*g4media_fsys_device_info_fn_t)(g4media_fsys_devname_in_t *in, g4media_fsys_info_out_t *out);
typedef void (*g4media_fsys_freespace_fn_t)(uint8_t *drv_letter_ptr, g4media_fsys_freespace_out_t *out);
typedef void (*g4media_fsys_freespace2_fn_t)(uint8_t *drv_letter_ptr, g4media_fsys_freespace2_out_t *out);
typedef void (*g4media_notify_media_status_fn_t)(void *self, uint32_t slot1, uint32_t slot2);

/* ========================================================================= */
/* 4. 模块内部状态与全局缓存                                                  */
/* ========================================================================= */

static uintptr_t                         g4media_app_base                 = 0;
static uintptr_t                         g4media_mpr_base                 = 0;
static volatile uint32_t                 g4media_bridge_initialized       = 0;
static volatile uint32_t                 g4media_injected_mask            = 0;
static volatile uint32_t                 g4media_slot1_media_id           = G4MEDIA_G4_MEDIA_ID_SD_DEFAULT;
static volatile uint32_t                 g4media_simulate_media_id        = 0u;
static g4media_fsys_api_t                g4media_g4_fsys                  = {0};
static g4media_infra_input_cb_t          g4media_custom_input_cb          = NULL;
static g4media_query_inout_fn_t          g4media_custom_query_inout       = NULL;
static g4media_dev_cache_entry_t         g4media_dev_cache[G4MEDIA_DEV_CACHE_CAP] = {{0}};

static g4media_init_media_fn_t           g4media_orig_init_media          = NULL;
static g4media_get_media_info_fn_t       g4media_orig_get_media_info      = NULL;
static g4media_rpc_fn_t                  g4media_orig_rpc_11000           = NULL;
static g4media_rpc_fn_t                  g4media_orig_rpc_12001           = NULL;
static g4media_rpc_fn_t                  g4media_orig_rpc_12002           = NULL;
static g4media_mount_fn_t                g4media_orig_mount               = NULL;
static g4media_get_status_fn_t           g4media_orig_get_status          = NULL;
static g4media_cmd11009_fn_t             g4media_orig_cmd_11009           = NULL;
static g4media_cmd11008_fn_t             g4media_orig_cmd_11008           = NULL;
static g4media_fsys_mount_fn_t           g4media_orig_fsys_mount          = NULL;
static g4media_fsys_get_drv_letter_fn_t  g4media_orig_fsys_get_drv_letter = NULL;
static g4media_fsys_drive_info_fn_t      g4media_orig_fsys_get_drive_info = NULL;
static g4media_fsys_device_info_fn_t     g4media_orig_fsys_get_device_info= NULL;
static g4media_fsys_freespace_fn_t       g4media_orig_fsys_get_free_space = NULL;
static g4media_fsys_freespace2_fn_t      g4media_orig_fsys_get_free_space2= NULL;
static g4media_notify_media_status_fn_t  g4media_orig_notify_media_status = NULL;

static const char * const g4media_sd_cand_devs[] = {
    "/dev/mmca",
    "/dev/mmcaa",
    "/dev/mmca1",
    "/dev/mmcab",
    "/dev/msa",
    "/dev/msb"
};
#define G4MEDIA_SD_CAND_COUNT (sizeof(g4media_sd_cand_devs) / sizeof(g4media_sd_cand_devs[0]))

/* ========================================================================= */
/* 5. 内存读写、设备路径缓存与四代 libInfraFsys.so 惰性解析辅助                */
/* ========================================================================= */

static inline int g4media_patch_thumb16(uintptr_t va, uint16_t new_insn, const char *name)
{
    uintptr_t addr = va & ~(uintptr_t)1u;
    uintptr_t page = addr & ~(uintptr_t)4095u;
    if (mprotect((void *)page, 4096u * 2u, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        *(volatile uint16_t *)addr = new_insn;
        __builtin___clear_cache((char *)addr, (char *)addr + 4);
        logf_("G4_MEDIA: patch 16-bit Thumb @ %p (%s) -> 0x%04x 成功", (void *)addr, name, (unsigned)new_insn);
        return 0;
    }
    logf_("G4_MEDIA_WARN: mprotect 失败 @ %p (%s) errno=%d", (void *)addr, name, errno);
    return -1;
}

static inline int g4media_patch_u32(uintptr_t va, uint32_t new_val, const char *name)
{
    uintptr_t addr = va & ~(uintptr_t)3u;
    uintptr_t page = addr & ~(uintptr_t)4095u;
    if (mprotect((void *)page, 4096u * 2u, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        *(volatile uint32_t *)addr = new_val;
        __builtin___clear_cache((char *)addr, (char *)addr + 4);
        logf_("G4_MEDIA: patch u32 @ %p (%s) -> 0x%08x 成功", (void *)addr, name, new_val);
        return 0;
    }
    logf_("G4_MEDIA_WARN: patch u32 mprotect 失败 @ %p (%s) errno=%d", (void *)addr, name, errno);
    return -1;
}

static inline void *g4media_install_tramp8(uintptr_t va, const uint8_t sig[8], void *hook_fn, const char *name)
{
    if (memcmp((const void *)va, sig, 8u) != 0) {
        const uint8_t *b = (const uint8_t *)va;
        logf_("G4_MEDIA_WARN: %s @ %p 签名前言不匹配 (%02x %02x %02x %02x %02x %02x %02x %02x)，跳过挂钩",
              name, (void *)va, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
        return NULL;
    }
    void *tramp = make_thumb_trampoline_8(va, hook_fn, name);
    if (tramp) {
        logf_("G4_MEDIA: %s @ %p 跳板安装成功 (tramp=%p)", name, (void *)va, tramp);
    } else {
        logf_("G4_MEDIA_WARN: %s @ %p make_thumb_trampoline_8 返回 NULL", name, (void *)va);
    }
    return tramp;
}

/**
 * @brief 检查指针值是否可能是有效用户态字符串指针 (严防将小整数 media_id 误当指针解引用崩溃)
 */
static inline int g4media_is_plausible_cstr(const char *s)
{
    uintptr_t p = (uintptr_t)s;
    if (p < 0x10000u) {
        return 0;
    }
    return s[0] != '\0';
}

static inline void g4media_copy_str(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0u) {
        return;
    }
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t n = 0u;
    while (n + 1u < cap && src[n] != '\0') {
        n++;
    }
    if (n > 0u && dst != src) {
        memmove(dst, src, n);
    }
    dst[n] = '\0';
}

static inline int g4media_is_slot1_dev_name_eligible(const char *dev_name)
{
    if (!dev_name || dev_name[0] == '\0') {
        return 1;
    }
    if (strncmp(dev_name, "/nondev/", 8) == 0 ||
        strncmp(dev_name, "/dev/mmcb", 9) == 0 ||
        strncmp(dev_name, "/dev/mmcc", 9) == 0 ||
        strncmp(dev_name, "/dev/nflash", 11) == 0 ||
        strncmp(dev_name, "/dev/sata", 9) == 0 ||
        strncmp(dev_name, "/dev/sd", 7) == 0 ||
        strncmp(dev_name, "/dev/sr", 7) == 0) {
        return 0;
    }
    return (strncmp(dev_name, "/dev/mmca", 9) == 0 ||
            strcmp(dev_name, "/dev/ms") == 0 ||
            strncmp(dev_name, "/dev/msa", 8) == 0 ||
            strncmp(dev_name, "/dev/msb", 8) == 0);
}

static inline void g4media_cache_clear(uint32_t media_id)
{
    if (media_id == 0u) {
        return;
    }
    for (uint32_t i = 0u; i < G4MEDIA_DEV_CACHE_CAP; i++) {
        if (g4media_dev_cache[i].media_id == media_id) {
            memset(&g4media_dev_cache[i], 0, sizeof(g4media_dev_cache[i]));
        }
    }
}

static inline void g4media_cache_store(uint32_t media_id, const char *dev_name, uint8_t drv_letter)
{
    if (media_id == 0u) {
        return;
    }
    int slot = -1;
    for (uint32_t i = 0u; i < G4MEDIA_DEV_CACHE_CAP; i++) {
        if (g4media_dev_cache[i].media_id == media_id) {
            slot = (int)i;
            break;
        }
        if (slot < 0 && g4media_dev_cache[i].media_id == 0u) {
            slot = (int)i;
        }
    }
    if (slot < 0) {
        slot = 0;
    }
    g4media_dev_cache[slot].media_id = media_id;
    if (drv_letter != 0u) {
        g4media_dev_cache[slot].drv_letter = drv_letter;
    }
    if (g4media_is_plausible_cstr(dev_name) && dev_name != g4media_dev_cache[slot].dev_name) {
        /* 避免静态默认 "/dev/ms" 覆盖已探明的物理 "/dev/mmca*" 节点 */
        if (strcmp(dev_name, "/dev/ms") == 0 &&
            strncmp(g4media_dev_cache[slot].dev_name, "/dev/mmc", 8) == 0) {
            return;
        }
        g4media_copy_str(g4media_dev_cache[slot].dev_name,
                         sizeof(g4media_dev_cache[slot].dev_name), dev_name);
    }
}

static inline const g4media_dev_cache_entry_t *g4media_cache_lookup(uint32_t media_id)
{
    if (media_id == 0u) {
        return NULL;
    }
    for (uint32_t i = 0u; i < G4MEDIA_DEV_CACHE_CAP; i++) {
        if (g4media_dev_cache[i].media_id == media_id) {
            return &g4media_dev_cache[i];
        }
    }
    return NULL;
}

/**
 * @brief 惰性解析宿主中已驻留的四代 libInfraFsys.so 导出函数 (QEMU 下不加载并安全置 available=0)
 */
static inline const g4media_fsys_api_t *g4media_resolve_g4_fsys(void)
{
    if (g4media_g4_fsys.resolved) {
        return &g4media_g4_fsys;
    }

    void *h = dlopen("libInfraFsys.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!h) {
        void *probe_sym = dlsym(RTLD_DEFAULT, "Fsys_GetDriveLetter");
        if (probe_sym) {
            Dl_info dli;
            memset(&dli, 0, sizeof(dli));
            if (dladdr(probe_sym, &dli) && dli.dli_fname && strstr(dli.dli_fname, "libInfraFsys")) {
                h = RTLD_DEFAULT;
            }
        }
    }

    if (h) {
        g4media_g4_fsys.get_mount_drives = (g4media_g4_get_mount_drives_fn_t)dlsym(h, "Fsys_GetMountDrives");
        g4media_g4_fsys.get_drive_letter = (g4media_g4_get_drive_letter_fn_t)dlsym(h, "Fsys_GetDriveLetter");
        g4media_g4_fsys.fsys_mount       = (g4media_g4_fsys_mount_fn_t)dlsym(h, "Fsys_Mount");
        g4media_g4_fsys.fsys_mount4      = (g4media_g4_fsys_mount4_fn_t)dlsym(h, "Fsys_Mount");
        g4media_g4_fsys.fsys_unmount     = (g4media_g4_fsys_unmount_fn_t)dlsym(h, "Fsys_Unmount");
        g4media_g4_fsys.get_drive_info   = (g4media_g4_fsys_drive_info_fn_t)dlsym(h, "Fsys_GetDriveInfo");
        g4media_g4_fsys.get_device_info  = (g4media_g4_fsys_device_info_fn_t)dlsym(h, "Fsys_GetDeviceInfo");
        g4media_g4_fsys.get_free_space   = (g4media_g4_fsys_free_fn_t)dlsym(h, "Fsys_GetFreeSpace");
        g4media_g4_fsys.find_first       = (g4media_g4_fsys_find_first_fn_t)dlsym(h, "Fsys_FindFirst");
        g4media_g4_fsys.find_next        = (g4media_g4_fsys_find_next_fn_t)dlsym(h, "Fsys_FindNext");
        g4media_g4_fsys.f_stat           = (g4media_g4_fsys_stat_fn_t)dlsym(h, "Fsys_Stat");
        g4media_g4_fsys.f_open           = (g4media_g4_fsys_open_fn_t)dlsym(h, "Fsys_Open");
        g4media_g4_fsys.f_close          = (g4media_g4_fsys_close_fn_t)dlsym(h, "Fsys_Close");
        g4media_g4_fsys.f_mkdir          = (g4media_g4_fsys_path_fn_t)dlsym(h, "Fsys_Mkdir");
        g4media_g4_fsys.f_remove         = (g4media_g4_fsys_path_fn_t)dlsym(h, "Fsys_Remove");
        g4media_g4_fsys.f_chmod          = (g4media_g4_fsys_chmod_fn_t)dlsym(h, "Fsys_Chmod");
        g4media_g4_fsys.f_read           = (g4media_g4_fsys_read_fn_t)dlsym(h, "Fsys_Read");
        g4media_g4_fsys.f_write          = (g4media_g4_fsys_write_fn_t)dlsym(h, "Fsys_Write");
        g4media_g4_fsys.f_write_and_flush = (g4media_g4_fsys_write_fn_t)dlsym(h, "Fsys_WriteAndFlush");
        if (g4media_g4_fsys.get_drive_letter || g4media_g4_fsys.get_mount_drives) {
            g4media_g4_fsys.available = 1;
            logf_("G4_MEDIA: 解析四代 libInfraFsys.so 成功 (Drives=%p Letter=%p Mount=%p DriveInfo=%p DevInfo=%p Free=%p Find=%p Stat=%p Open=%p)",
                  (void *)g4media_g4_fsys.get_mount_drives,
                  (void *)g4media_g4_fsys.get_drive_letter,
                  (void *)g4media_g4_fsys.fsys_mount,
                  (void *)g4media_g4_fsys.get_drive_info,
                  (void *)g4media_g4_fsys.get_device_info,
                  (void *)g4media_g4_fsys.get_free_space,
                  (void *)g4media_g4_fsys.find_first,
                  (void *)g4media_g4_fsys.f_stat,
                  (void *)g4media_g4_fsys.f_open);
        }
    }
    g4media_g4_fsys.resolved = 1;
    return &g4media_g4_fsys;
}

static inline uint32_t g4media_get_slot1_media_id(void)
{
    uint32_t id = g4media_slot1_media_id;
    return (id != 0u) ? id : G4MEDIA_G4_MEDIA_ID_SD_DEFAULT;
}

static inline void g4media_set_slot1_media_id(uint32_t media_id)
{
    if (media_id != 0u && media_id != g4media_simulate_media_id) {
        g4media_slot1_media_id = media_id;
    }
}

static inline uint32_t g4media_get_simulate_media_id(void)
{
    return g4media_simulate_media_id;
}

static inline void g4media_set_simulate_media_id(uint32_t media_id)
{
    if (media_id != 0u) {
        g4media_simulate_media_id = media_id;
    }
}

static inline int g4media_is_simulate_media(uint32_t media_id)
{
    if (media_id == 0u) {
        return 0;
    }
    if (g4media_simulate_media_id != 0u && media_id == g4media_simulate_media_id) {
        return 1;
    }
    if (g4media_app_base) {
        uint32_t cnt = *(const volatile uint32_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_CNT);
        if (cnt > 0u && cnt <= G4MEDIA_MAX_MEDIA_ENTRIES) {
            const g4media_tbl_entry_t *entries =
                (const g4media_tbl_entry_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_TBL);
            for (uint32_t i = 0u; i < cnt; i++) {
                if (entries[i].media_id == media_id) {
                    return (entries[i].media_type == 2u) ? 1 : 0;
                }
            }
        }
    }
    return 0;
}

static inline int g4media_is_allowed_slot1_media(uint32_t media_id)
{
    if (media_id == 0u || g4media_is_simulate_media(media_id)) {
        return 0;
    }
    if (g4media_app_base) {
        uint32_t cnt = *(const volatile uint32_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_CNT);
        if (cnt > 0u && cnt <= G4MEDIA_MAX_MEDIA_ENTRIES) {
            const g4media_tbl_entry_t *entries =
                (const g4media_tbl_entry_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_TBL);
            for (uint32_t i = 0u; i < cnt; i++) {
                if (entries[i].media_id == media_id) {
                    return (entries[i].media_type == 0u) ? 1 : 0;
                }
            }
        }
    }
    return (media_id == g4media_get_slot1_media_id()) ? 1 : 0;
}

static inline const char *g4media_dev_id_to_path(uint16_t dev_id)
{
    switch (dev_id) {
    case 0xd100u: return "/dev/mmca";
    case 0xd110u: return "/dev/mmcaa";
    case 0xd120u: return "/dev/mmcab";
    case 0xd200u: return "/dev/mmcb";
    case 0xd210u: return "/dev/mmcba";
    case 0xd010u: return "/dev/msa";
    case 0xd020u: return "/dev/msb";
    default:      return NULL;
    }
}

/**
 * @brief 向四代 libInfraMediaDetect.so (0x00af816f) 发送同步 0x11002 (GetInOutStatus) 查询物理卡真实在位状态
 *
 * 返回 0 表示 MWF/UIPC 通信成功，out_inserted (1=在位, 0=空槽) 与 out_dev_id (0xd100 等) 有效；
 * 返回负值表示无法查询（如 QEMU 环境或非真机）。
 */
static inline int g4media_query_inout_status_g4(uint32_t media_id,
                                                uint8_t *out_inserted,
                                                uint16_t *out_dev_id)
{
    if (out_inserted) *out_inserted = 0u;
    if (out_dev_id)   *out_dev_id   = 0u;
    if (!g4media_is_allowed_slot1_media(media_id)) {
        return -1;
    }
    if (g4media_custom_query_inout) {
        return g4media_custom_query_inout(media_id, out_inserted, out_dev_id);
    }

    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !g4media_app_base) {
        return -2;
    }

    uintptr_t fn_va = g4media_app_base + G4MEDIA_OFF_OSAL_SND_SYNC;
    static const uint8_t sig_snd_sync[8] = { 0x2du, 0xe9u, 0xf0u, 0x47u, 0x84u, 0xb0u, 0x88u, 0x46u };
    if (memcmp((const void *)fn_va, sig_snd_sync, sizeof(sig_snd_sync)) != 0) {
        return -3;
    }

    g4media_inout_status_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.cmd        = G4MEDIA_CMD_GET_INOUT_STATUS; /* 0x00011002 */
    msg.ver        = 1u;
    msg.payload_sz = 0x18u;
    msg.media_id   = media_id;

    g4media_osal_snd_sync_fn_t snd_sync = (g4media_osal_snd_sync_fn_t)(fn_va | 1u);
    int rc = snd_sync(&msg, (uint32_t)sizeof(msg), G4MEDIA_TARGET_MEDIA_DETECT, NULL, 1u);
    if (rc != 0 || msg.err_code != 0u) {
        logf_("G4_MEDIA: GetInOutStatus(0x11002, id=0x%x) 失败 rc=%d err=0x%x",
              media_id, rc, msg.err_code);
        return -4;
    }

    if (out_inserted) *out_inserted = msg.inserted ? 1u : 0u;
    if (out_dev_id)   *out_dev_id   = msg.device_id;
    return 0;
}

/**
 * @brief 通过四代 Fsys_GetDriveLetter(const char *dev_name) 真实探测指定 media_id 是否已挂载并拿到真实盘符/设备名
 *
 * 严禁将 uint32_t media_id 直接传入 Fsys_GetDriveLetter(const char *)！
 * 仅查询合法 Slot1 的已缓存 dev_name 或合法静态 SD 设备字符串；对空槽及 /nondev/simulate 绝不造假。
 */
static inline int g4media_probe_real_sd(uint32_t media_id,
                                        char *out_dev_name,
                                        size_t out_dev_cap,
                                        uint8_t *out_drv_letter)
{
    if (out_drv_letter) {
        *out_drv_letter = 0u;
    }
    if (out_dev_name && out_dev_cap > 0u) {
        out_dev_name[0] = '\0';
    }
    if (!g4media_is_allowed_slot1_media(media_id)) {
        return 0;
    }

    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !api->get_drive_letter) {
        return 0;
    }
    if (api->get_mount_drives && api->get_mount_drives() == 0u) {
        return 0;
    }

    const g4media_dev_cache_entry_t *cached = g4media_cache_lookup(media_id);
    if (cached && cached->dev_name[0] != '\0' && strncmp(cached->dev_name, "/nondev/", 8) != 0) {
        uint8_t drv = api->get_drive_letter(cached->dev_name);
        if (drv != 0u) {
            g4media_cache_store(media_id, cached->dev_name, drv);
            if (out_drv_letter) *out_drv_letter = drv;
            if (out_dev_name && out_dev_cap > 0u) {
                g4media_copy_str(out_dev_name, out_dev_cap, cached->dev_name);
            }
            return 1;
        }
    }

    if (media_id == g4media_get_slot1_media_id()) {
        for (size_t i = 0u; i < G4MEDIA_SD_CAND_COUNT; i++) {
            const char *cand = g4media_sd_cand_devs[i];
            uint8_t drv = api->get_drive_letter(cand);
            if (drv != 0u) {
                g4media_cache_store(media_id, cand, drv);
                if (out_drv_letter) *out_drv_letter = drv;
                if (out_dev_name && out_dev_cap > 0u) {
                    g4media_copy_str(out_dev_name, out_dev_cap, cand);
                }
                return 1;
            }
        }
    }
    return 0;
}

/**
 * @brief 将四代 PrFILE2 文件系统类型字 (0x8300 exFAT / 0x800x FAT 等) 转换为五代 ConvFsType (0x02b72900) 输出
 */
static inline uint8_t g4media_translate_fs_type(uint16_t fs_g4)
{
    if (fs_g4 == 0x8300u || fs_g4 == 0x8101u || fs_g4 == 0x3fffu ||
        (fs_g4 >= 0x8500u && fs_g4 <= 0x8602u)) {
        return 0x40u; /* exFAT */
    }
    if (fs_g4 == 0x8200u) {
        return 0x14u;
    }
    if (fs_g4 == 0u) {
        return 0u;
    }
    return 0x10u; /* FAT16 / FAT32 */
}

/**
 * @brief 简化版四代 Fsys 错误码转换 (对齐 appFw.so @ 0x02b726fc: 0 -> 0, 0x80000021 -> 0x2d, 其余非 0 -> 0x29)
 */
static inline uint32_t g4media_conv_fsys_err(int g4_err)
{
    if (g4_err == 0) {
        return 0u;
    }
    if ((uint32_t)g4_err == G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G4) {
        return G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G5; /* 0x2d */
    }
    return 0x29u;
}

/**
 * @brief 启动及运行期存储栈诊断（仅做合法字符串指针查询与只读观测，杜绝小整数指针崩溃和 errno=30 噪音）
 */
static void g4media_diagnose_storage_state(const char *tag)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available) {
        logf_("G4_MEDIA_DIAG[%s]: libInfraFsys.so 未加载 (QEMU 或非真机环境)", tag);
        return;
    }
    uint32_t slot1_id = g4media_get_slot1_media_id();
    uint32_t drives_mask = api->get_mount_drives ? api->get_mount_drives() : 0u;
    uint8_t drv_mmca  = api->get_drive_letter ? api->get_drive_letter("/dev/mmca")  : 0u;
    uint8_t drv_mmcaa = api->get_drive_letter ? api->get_drive_letter("/dev/mmcaa") : 0u;
    uint8_t drv_mmcb  = api->get_drive_letter ? api->get_drive_letter("/dev/mmcb")  : 0u;
    if (drv_mmca != 0u) {
        g4media_cache_store(slot1_id, "/dev/mmca", drv_mmca);
    } else if (drv_mmcaa != 0u) {
        g4media_cache_store(slot1_id, "/dev/mmcaa", drv_mmcaa);
    }
    logf_("G4_MEDIA_DIAG[%s]: slot1=0x%x sim=0x%x PrFILE2 drives_mask=0x%x, drv(/dev/mmca)=0x%02x('%c'), drv(/dev/mmcaa)=0x%02x('%c'), drv(/dev/mmcb)=0x%02x",
          tag, slot1_id, g4media_get_simulate_media_id(), drives_mask,
          (unsigned)drv_mmca,  (drv_mmca  >= 0x20u && drv_mmca  < 0x7fu) ? (int)drv_mmca  : '.',
          (unsigned)drv_mmcaa, (drv_mmcaa >= 0x20u && drv_mmcaa < 0x7fu) ? (int)drv_mmcaa : '.',
          (unsigned)drv_mmcb);
}

/**
 * @brief 探测四代是否已挂载或底层物理卡确实在位 (v29 零造假版)
 *
 * 严禁使用 GetMediaInfo (0x1000 -> 0x00cf016d) 判在位 (其仅查静态配置表，空槽与 simulate 恒返 valid=1)！
 * 仅在真机宿主存在 libInfraFsys.so 且 media_id 为合法 Slot1 (非 SIMULATE/非空 Slot2) 时探测：
 *  1) 优先查 Fsys_GetDriveLetter(dev_name) != 0 (PrFILE2 已挂载)；
 *  2) 若尚未挂载，向四代 libInfraMediaDetect.so (0x00af816f) 发送同步 0x11002 (GetInOutStatus)，
 *     查询 ThreadRM 底层 mcmn_drv_checkmediaexist 返回的 inserted 字段 (1=物理卡在位, 0=空槽)。
 * 在 QEMU (!api->available)、物理空槽 (inserted==0) 或 /nondev/simulate 下严格返回 0。
 */
static inline int g4media_probe_phys_card_present_in_g4(uint32_t media_id,
                                                      char *out_dev_name,
                                                      size_t out_dev_cap,
                                                      uint8_t *out_drv_letter)
{
    if (out_drv_letter) {
        *out_drv_letter = 0u;
    }
    if (out_dev_name && out_dev_cap > 0u) {
        out_dev_name[0] = '\0';
    }
    if (!g4media_is_allowed_slot1_media(media_id)) {
        return 0;
    }
    if (g4media_probe_real_sd(media_id, out_dev_name, out_dev_cap, out_drv_letter)) {
        return 1;
    }
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available) {
        return 0;
    }

    uint8_t inserted = 0u;
    uint16_t dev_id = 0u;
    if (g4media_query_inout_status_g4(media_id, &inserted, &dev_id) == 0 && inserted != 0u) {
        const char *mapped = g4media_dev_id_to_path(dev_id);
        const char *chosen = NULL;
        if (mapped && mapped[0] != '\0') {
            chosen = mapped;
        } else {
            const g4media_dev_cache_entry_t *c = g4media_cache_lookup(media_id);
            if (c && c->dev_name[0] != '\0' && strncmp(c->dev_name, "/nondev/", 8) != 0) {
                chosen = c->dev_name;
            } else {
                chosen = "/dev/mmca";
            }
        }
        g4media_cache_store(media_id, chosen, 0u);
        if (out_dev_name && out_dev_cap > 0u) {
            g4media_copy_str(out_dev_name, out_dev_cap, chosen);
        }
        logf_("G4_MEDIA: GetInOutStatus(0x11002, id=0x%x) 确认物理卡在位 (inserted=1 dev_id=0x%04x -> '%s')",
              media_id, (unsigned)dev_id, chosen);
        return 1;
    }
    return 0;
}

/**
 * @brief 获取某个在位 media_id 的最佳四代设备名 (用于 Cmd_11008 / Fsys_Mount / Fsys_GetDeviceInfo)
 */
static inline const char *g4media_pick_dev_name_for_media(uint32_t media_id, char *buf, size_t cap)
{
    if (!buf || cap == 0u) {
        return "";
    }
    buf[0] = '\0';
    if (!g4media_is_allowed_slot1_media(media_id)) {
        return "";
    }
    if (g4media_probe_phys_card_present_in_g4(media_id, buf, cap, NULL) && buf[0] != '\0') {
        return buf;
    }
    const g4media_dev_cache_entry_t *c = g4media_cache_lookup(media_id);
    if (c && c->dev_name[0] != '\0' && strncmp(c->dev_name, "/nondev/", 8) != 0) {
        g4media_copy_str(buf, cap, c->dev_name);
        return buf;
    }
    if (media_id == g4media_get_slot1_media_id()) {
        g4media_copy_str(buf, cap, "/dev/mmca");
        return buf;
    }
    return "";
}

/**
 * @brief 主动检索五代 g_media_tbl 并投递缺失的 MEDIA_IN 事件至 appFw+0x02b72acc，唤醒 sequence_media_mount
 */
static void g4media_inject_media_in_if_ready(uint32_t media_id)
{
    if (!g4media_app_base || !g4media_is_allowed_slot1_media(media_id)) {
        return;
    }
    uint8_t drv = 0u;
    char dev_name[32];
    memset(dev_name, 0, sizeof(dev_name));
    if (!g4media_probe_phys_card_present_in_g4(media_id, dev_name, sizeof(dev_name), &drv)) {
        logf_("G4_MEDIA: StartInOut(0x%x) 四代未检测到有效盘符或物理卡在位，绝不投递假 MEDIA_IN", media_id);
        return;
    }

    uintptr_t cnt_va = g4media_app_base + G4MEDIA_OFF_MEDIA_CNT;
    uintptr_t tbl_va = g4media_app_base + G4MEDIA_OFF_MEDIA_TBL;
    uint32_t cnt = *(const volatile uint32_t *)cnt_va;
    if (cnt == 0u || cnt > G4MEDIA_MAX_MEDIA_ENTRIES) {
        logf_("G4_MEDIA_WARN: g_media_cnt=%u 异常 (超出 [1..%u])，跳过 MEDIA_IN 注入",
              cnt, G4MEDIA_MAX_MEDIA_ENTRIES);
        return;
    }

    const g4media_tbl_entry_t *entries = (const g4media_tbl_entry_t *)tbl_va;
    int found_idx = -1;
    for (uint32_t i = 0u; i < cnt; i++) {
        logf_("G4_MEDIA_TBL[%u]: id=0x%x attr=0x%x type=%u drv_id=%u mounted=%u",
              i, entries[i].media_id, entries[i].ev_attr, entries[i].media_type,
              entries[i].drv_id, (unsigned)entries[i].mounted);
        if (entries[i].media_id == media_id && entries[i].media_type == 0u) {
            found_idx = (int)i;
        }
    }

    if (found_idx < 0) {
        logf_("G4_MEDIA_WARN: g_media_tbl 中未找到有效 Slot1 media_id=0x%x，无法注入 MEDIA_IN",
              media_id);
        return;
    }

    uint32_t bit = 1u << (uint32_t)found_idx;
    if (__sync_fetch_and_or(&g4media_injected_mask, bit) & bit) {
        logf_("G4_MEDIA: media_id=0x%x (logical=%d) 本轮已投递过 MEDIA_IN，跳过重复注入",
              media_id, found_idx + 1);
        return;
    }

    uintptr_t cb_va = g4media_app_base + G4MEDIA_OFF_INFRA_INPUT_CB;
    static const uint8_t sig_in_cb[8] = { 0xb0u, 0xb5u, 0x0cu, 0x46u, 0x0du, 0x68u, 0x00u, 0xafu };
    if (memcmp((const void *)cb_va, sig_in_cb, sizeof(sig_in_cb)) != 0) {
        logf_("G4_MEDIA_WARN: InfraInputCb @ %p 签名不匹配，无法安全投递 MEDIA_IN", (void *)cb_va);
        return;
    }

    g4media_infra_input_cb_t cb_fn = g4media_custom_input_cb
        ? g4media_custom_input_cb
        : (g4media_infra_input_cb_t)(cb_va | 1u);
    uint32_t ev[4] = { (uint32_t)(found_idx + 1), 0u, 1u, 0x7fffffffu };
    logf_("G4_MEDIA: 真实 SD 卡 (media_id=0x%x, dev='%s', drv=0x%02x'%c') 触发五代 MEDIA_IN -> cb(logical=%u, st=1)",
          media_id, dev_name, (unsigned)drv, (drv >= 0x20u && drv < 0x7fu) ? (int)drv : '.', ev[0]);
    cb_fn(0, ev);
}

/* ========================================================================= */
/* 6. Hook 函数实现                                                           */
/* ========================================================================= */

/** 0. InitMedia (0x02b72ca0) — 跨代修正 Gen4 flags[0x48]/[0x49] -> Slot1/Slot2 分类并捕获真实 media_id */
static void g4media_hook_init_media(void)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int is_g4_host = (api->available != 0) || (dlopen("libObj.so", RTLD_NOLOAD | RTLD_LAZY) != NULL);

    if (g4media_app_base && is_g4_host) {
        uintptr_t insn1 = g4media_app_base + G4MEDIA_OFF_INIT_FLAG_SLOT1_INSN;
        uintptr_t insn2 = g4media_app_base + G4MEDIA_OFF_INIT_FLAG_SLOT2_INSN;
        /* ldrb.w r3, [r7, #0x68] = 97 f8 68 30 -> 改为 #0xa8 (flags[0x48] ADJ_SLOT_1) */
        if (*(const volatile uint16_t *)insn1 == 0xf897u &&
            *(const volatile uint16_t *)(insn1 + 2u) == 0x3068u) {
            g4media_patch_thumb16(insn1 + 2u, 0x30a8u, "InitMedia:flags[0x08]->flags[0x48]");
        }
        /* ldrb.w r3, [r7, #0x69] = 97 f8 69 30 -> 改为 #0xa9 (flags[0x49] ADJ_SLOT_2) */
        if (*(const volatile uint16_t *)insn2 == 0xf897u &&
            *(const volatile uint16_t *)(insn2 + 2u) == 0x3069u) {
            g4media_patch_thumb16(insn2 + 2u, 0x30a9u, "InitMedia:flags[0x09]->flags[0x49]");
        }
    }

    if (g4media_orig_init_media) {
        g4media_orig_init_media();
    }

    if (!g4media_app_base) {
        return;
    }

    uint32_t cnt = *(const volatile uint32_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_CNT);
    if (cnt == 0u || cnt > G4MEDIA_MAX_MEDIA_ENTRIES) {
        logf_("G4_MEDIA_WARN: InitMedia 完成但 g_media_cnt=%u 异常", cnt);
        return;
    }

    g4media_tbl_entry_t *entries = (g4media_tbl_entry_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_TBL);
    uint32_t primary_slot1_id = 0u;
    uint32_t fallback_slot1_id = 0u;
    for (uint32_t i = 0u; i < cnt; i++) {
        char dev_buf[32];
        memset(dev_buf, 0, sizeof(dev_buf));
        g4media_get_info_out_t info;
        memset(&info, 0, sizeof(info));

        if (g4media_orig_get_media_info) {
            g4media_get_info_in_t req = { entries[i].media_id, dev_buf };
            g4media_orig_get_media_info(&req, &info);
        }

        if (info.err == 0u && info.valid != 0u) {
            if (info.flags[G4MEDIA_ATTR_SIMULATE] != 0u || strncmp(dev_buf, "/nondev/", 8) == 0) {
                if (info.flags[G4MEDIA_ATTR_SIMULATE] != 0u || strcmp(dev_buf, "/nondev/simulate") == 0) {
                    g4media_set_simulate_media_id(entries[i].media_id);
                }
                if (entries[i].media_type == 0u || entries[i].media_type == 1u) {
                    entries[i].media_type = 2u; /* 严禁 /nondev/ 节点混为卡槽 */
                }
            } else if (info.flags[G4MEDIA_ATTR_FIXED] == 0u &&
                       info.flags[G4MEDIA_ATTR_PC_APP] == 0u &&
                       (info.flags[G4MEDIA_ATTR_SLOT_1_G5] != 0u ||
                        info.flags[G4MEDIA_ATTR_ADJ_SLOT_1_G4] != 0u ||
                        info.flags[G4MEDIA_ATTR_REMOVABLEMEDIA1] != 0u)) {
                if (entries[i].media_type == 3u) {
                    entries[i].media_type = 0u;
                }
                if (entries[i].media_type == 0u) {
                    if (info.flags[G4MEDIA_ATTR_SLOT_1_G5] != 0u ||
                        info.flags[G4MEDIA_ATTR_ADJ_SLOT_1_G4] != 0u) {
                        if (primary_slot1_id == 0u) {
                            primary_slot1_id = entries[i].media_id;
                        }
                    } else if (fallback_slot1_id == 0u) {
                        fallback_slot1_id = entries[i].media_id;
                    }
                    if (dev_buf[0] != '\0') {
                        g4media_cache_store(entries[i].media_id, dev_buf, 0u);
                    }
                }
            } else if (entries[i].media_type == 0u) {
                if (fallback_slot1_id == 0u) {
                    fallback_slot1_id = entries[i].media_id;
                }
                if (dev_buf[0] != '\0') {
                    g4media_cache_store(entries[i].media_id, dev_buf, 0u);
                }
            }
        } else if (entries[i].media_type == 0u && fallback_slot1_id == 0u) {
            fallback_slot1_id = entries[i].media_id;
        }

        logf_("G4_MEDIA_INIT[%u]: id=0x%x ev_attr=0x%x type=%u handle=0x%x dev='%s'",
              i, entries[i].media_id, entries[i].ev_attr, entries[i].media_type,
              entries[i].handle, dev_buf);
    }
    if (primary_slot1_id != 0u) {
        g4media_set_slot1_media_id(primary_slot1_id);
    } else if (fallback_slot1_id != 0u) {
        g4media_set_slot1_media_id(fallback_slot1_id);
    }
    logf_("G4_MEDIA: InitMedia 校准完毕 -> slot1_id=0x%x simulate_id=0x%x",
          g4media_get_slot1_media_id(), g4media_get_simulate_media_id());
}

/** 1. StartInOut (0x02b730b8, Cmd 0x11000) */
static int g4media_hook_rpc_11000(void *param_in, uint32_t *status_out)
{
    uint32_t slot_val = param_in ? *(const volatile uint32_t *)param_in : 0u;
    logf_("G4_MEDIA: StartInOut(0x11000) 进入: slot_val=0x%x", slot_val);
    g4media_diagnose_storage_state("StartInOut");

    int rc = 0;
    if (g4media_orig_rpc_11000) {
        rc = g4media_orig_rpc_11000(param_in, status_out);
        logf_("G4_MEDIA: StartInOut 原函数返回: rc=%d, status_out=%u",
              rc, status_out ? *status_out : 0xffffffffu);
    } else if (status_out) {
        *status_out = 0u;
    }

    int phys_present = g4media_probe_phys_card_present_in_g4(slot_val, NULL, 0u, NULL);
    if (status_out && *status_out != 0u) {
        if (phys_present) {
            logf_("G4_MEDIA: StartInOut(0x%x) 原返回 status=%u，四代真实有卡，旁路置 status=0",
                  slot_val, *status_out);
            *status_out = 0u;
        } else if (*status_out == G4MEDIA_ERR_ALREADY_STARTED_G5 &&
                   g4media_is_allowed_slot1_media(slot_val)) {
            /* 四代 ThreadRM 已提前 StartInOut(0x1000) 导致返回 ER_ALREADY_START(2->22)，空槽也须置 0 防 FATAL 断言，但绝不投递 MEDIA_IN */
            logf_("G4_MEDIA: StartInOut(0x%x) 四代已启动监听 (status=22) 且当前空槽，置 status=0 但绝不注 MEDIA_IN",
                  slot_val);
            *status_out = 0u;
        }
    }

    if (phys_present) {
        g4media_inject_media_in_if_ready(slot_val);
    } else if (g4media_is_allowed_slot1_media(slot_val)) {
        /* 物理空槽或热拔出后：清理该 Slot 的注入去重位与旧盘符缓存，保证再次插卡可重新上报 */
        if (g4media_app_base) {
            uint32_t cnt = *(const volatile uint32_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_CNT);
            if (cnt > 0u && cnt <= G4MEDIA_MAX_MEDIA_ENTRIES) {
                const g4media_tbl_entry_t *entries =
                    (const g4media_tbl_entry_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_TBL);
                for (uint32_t i = 0u; i < cnt; i++) {
                    if (entries[i].media_id == slot_val) {
                        __sync_and_and_fetch(&g4media_injected_mask, ~(1u << i));
                    }
                }
            }
        }
        g4media_cache_clear(slot_val);
    }
    return rc;
}

/** 2. StartTemp (0x02b73424, Cmd 0x12001) */
static int g4media_hook_rpc_12001(void *param_in, uint32_t *status_out)
{
    uint32_t slot_val = param_in ? *(const volatile uint32_t *)param_in : 0u;
    int rc = 0;
    if (g4media_orig_rpc_12001) {
        rc = g4media_orig_rpc_12001(param_in, status_out);
    } else if (status_out) {
        *status_out = 0u;
    }
    logf_("G4_MEDIA: StartTemp(0x12001, slot=0x%x) -> rc=%d, status=%u",
          slot_val, rc, status_out ? *status_out : 0xffffffffu);
    if (status_out && *status_out != 0u &&
        g4media_probe_phys_card_present_in_g4(slot_val, NULL, 0u, NULL)) {
        *status_out = 0u;
    }
    return rc;
}

/** 3. StopTemp (0x02b734d8, Cmd 0x12002) */
static int g4media_hook_rpc_12002(void *param_in, uint32_t *status_out)
{
    uint32_t slot_val = param_in ? *(const volatile uint32_t *)param_in : 0u;
    int rc = 0;
    if (g4media_orig_rpc_12002) {
        rc = g4media_orig_rpc_12002(param_in, status_out);
    } else if (status_out) {
        *status_out = 0u;
    }
    logf_("G4_MEDIA: StopTemp(0x12002, slot=0x%x) -> rc=%d, status=%u",
          slot_val, rc, status_out ? *status_out : 0xffffffffu);
    if (status_out && *status_out != 0u &&
        g4media_probe_phys_card_present_in_g4(slot_val, NULL, 0u, NULL)) {
        *status_out = 0u;
    }
    return rc;
}

/** 4. GetMediaInfo (0x02b72fc8) — 输入 { media_id, out_dev_name } */
static void g4media_hook_get_media_info(g4media_get_info_in_t *in, g4media_get_info_out_t *out)
{
    uint32_t media_id = in ? in->media_id : 0u;
    char safe_dev_buf[32];
    memset(safe_dev_buf, 0, sizeof(safe_dev_buf));

    g4media_get_info_in_t local_in;
    local_in.media_id = media_id;
    local_in.out_dev_name = (in && in->out_dev_name) ? in->out_dev_name : safe_dev_buf;
    if (local_in.out_dev_name) {
        local_in.out_dev_name[0] = '\0';
    }

    if (g4media_orig_get_media_info) {
        g4media_orig_get_media_info(&local_in, out);
    }
    if (!out) {
        return;
    }

    const char *got_name = local_in.out_dev_name ? local_in.out_dev_name : "";
    int is_sim = (out->flags[G4MEDIA_ATTR_SIMULATE] != 0u ||
                  strncmp(got_name, "/nondev/", 8) == 0 ||
                  g4media_is_simulate_media(media_id));
    if (is_sim) {
        if (out->flags[G4MEDIA_ATTR_SIMULATE] != 0u || strcmp(got_name, "/nondev/simulate") == 0) {
            g4media_set_simulate_media_id(media_id);
        }
        /* 严禁对 SIMULATE 或 /nondev/ 设备翻译 SLOT_1 或缓存成 SD 设备 */
        out->flags[G4MEDIA_ATTR_SLOT_1_G5] = 0u;
        out->flags[G4MEDIA_ATTR_SLOT_2_G5] = 0u;
        logf_("G4_MEDIA: GetMediaInfo(0x%x, SIMULATE) 原返回: err=%u valid=%u dev='%s' f27=%u",
              media_id, out->err, (unsigned)out->valid, got_name, (unsigned)out->flags[G4MEDIA_ATTR_SIMULATE]);
        return;
    }

    if (out->err == 0u && out->valid != 0u && got_name[0] != '\0') {
        g4media_cache_store(media_id, got_name, 0u);
    }

    /* 跨代静态属性位翻译：Gen4 ADJ_SLOT_1(0x48)/ADJ_SLOT_2(0x49) -> Gen5 SLOT_1(0x08)/SLOT_2(0x09) */
    if (out->err == 0u && out->valid != 0u && out->flags[G4MEDIA_ATTR_FIXED] == 0u) {
        if (out->flags[G4MEDIA_ATTR_ADJ_SLOT_1_G4] != 0u && out->flags[G4MEDIA_ATTR_SLOT_1_G5] == 0u) {
            out->flags[G4MEDIA_ATTR_SLOT_1_G5] = 1u;
        }
        if (out->flags[G4MEDIA_ATTR_ADJ_SLOT_2_G4] != 0u && out->flags[G4MEDIA_ATTR_SLOT_2_G5] == 0u) {
            out->flags[G4MEDIA_ATTR_SLOT_2_G5] = 1u;
        }
        if (out->flags[G4MEDIA_ATTR_SLOT_1_G5] != 0u && out->flags[G4MEDIA_ATTR_PC_APP] == 0u) {
            g4media_set_slot1_media_id(media_id);
        }
    }

    logf_("G4_MEDIA: GetMediaInfo(0x%x) 原返回: err=%u valid=%u dev='%s' dev_type=%u f08=%u f48=%u f11(0x19)=%u",
          media_id, out->err, (unsigned)out->valid, got_name, out->dev_type,
          (unsigned)out->flags[G4MEDIA_ATTR_SLOT_1_G5],
          (unsigned)out->flags[G4MEDIA_ATTR_ADJ_SLOT_1_G4],
          (unsigned)out->flags[G4MEDIA_ATTR_USE_MEDIAMOUNT]);

    /* 若四代真实物理卡在位 (Fsys 已挂或 GetInOutStatus 在位)，确保 exec_mount 所需字段及真实设备名就绪 */
    char phys_dev[32];
    if (g4media_probe_phys_card_present_in_g4(media_id, phys_dev, sizeof(phys_dev), NULL)) {
        out->err = 0u;
        out->valid = 1u;
        if (out->dev_type == 0u) {
            out->dev_type = 2u; /* SD */
        }
        out->flags[G4MEDIA_ATTR_USE_MEDIAMOUNT] = 1u; /* offset +0x19 in struct */
        out->flags[G4MEDIA_ATTR_SLOT_1_G5] = 1u;
        if (phys_dev[0] != '\0') {
            if (in && in->out_dev_name && strcmp(in->out_dev_name, phys_dev) != 0) {
                g4media_copy_str(in->out_dev_name, 21u, phys_dev);
            }
            g4media_cache_store(media_id, phys_dev, 0u);
        }
    } else if (out->err == 0u && out->valid != 0u && g4media_is_allowed_slot1_media(media_id)) {
        if (out->dev_type == 0u) {
            out->dev_type = 2u;
        }
        if (out->flags[G4MEDIA_ATTR_USE_MEDIAMOUNT] == 0u) {
            out->flags[G4MEDIA_ATTR_USE_MEDIAMOUNT] = 1u;
        }
    }
}

/** 5. Mount (0x02b7358c) */
static void g4media_hook_mount(uint32_t *media_id_in, uint32_t *status_out)
{
    uint32_t media_id = media_id_in ? *media_id_in : 0u;
    if (g4media_orig_mount) {
        g4media_orig_mount(media_id_in, status_out);
    } else if (status_out) {
        *status_out = 0u;
    }
    uint32_t st = status_out ? *status_out : 0u;
    uint8_t drv = 0u;
    int phys_ok = g4media_probe_phys_card_present_in_g4(media_id, NULL, 0u, &drv);
    logf_("G4_MEDIA: Mount(0x%x) 原返回 status=%u (phys_ok=%d, drv=0x%02x)",
          media_id, st, phys_ok, (unsigned)drv);

    if (phys_ok) {
        if (g4media_app_base) {
            uint32_t cnt = *(const volatile uint32_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_CNT);
            if (cnt > 0u && cnt <= G4MEDIA_MAX_MEDIA_ENTRIES) {
                g4media_tbl_entry_t *entries = (g4media_tbl_entry_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_TBL);
                for (uint32_t i = 0u; i < cnt; i++) {
                    if (entries[i].media_id == media_id) {
                        entries[i].mounted = 1u;
                        break;
                    }
                }
            }
        }
        if (status_out && st != 0u) {
            *status_out = 0u;
            logf_("G4_MEDIA: Mount(0x%x) 真卡在位/已挂载，将 status=%u 归一为 0", media_id, st);
        }
    }
}

/** 6. GetStatus (0x02b73700) — 已将命令字字面量从 0x11002 修补为 0x11003 */
static void g4media_hook_get_status(uint32_t *media_id_in, g4media_get_status_out_t *out)
{
    uint32_t media_id = media_id_in ? *media_id_in : 0u;
    if (g4media_orig_get_status) {
        g4media_orig_get_status(media_id_in, out);
    }
    if (!out) {
        return;
    }
    logf_("G4_MEDIA: GetStatus(0x%x, 0x11003) 原返回: status=%u mounted=%u bad=%u wp=%u ro=%u drv=%u",
          media_id, out->status, (unsigned)out->mounted, (unsigned)out->badblk,
          (unsigned)out->wp, (unsigned)out->ro, out->drv_id);

    uint8_t real_drv = 0u;
    if (g4media_probe_real_sd(media_id, NULL, 0u, &real_drv) && real_drv >= (uint8_t)'A' && real_drv <= (uint8_t)'Z') {
        if (out->status != 0u || out->mounted == 0u) {
            out->status = 0u;
            out->mounted = 1u;
            out->badblk = 0u;
            logf_("G4_MEDIA: GetStatus(0x%x) 四代 PrFILE2 真实挂载在线(drv='%c' 0x%02x)，补全 status=0 mounted=1",
                  media_id, (char)real_drv, (unsigned)real_drv);
        }
        if (out->drv_id == 0u && g4media_app_base) {
            uint32_t cnt = *(const volatile uint32_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_CNT);
            if (cnt > 0u && cnt <= G4MEDIA_MAX_MEDIA_ENTRIES) {
                const g4media_tbl_entry_t *entries = (const g4media_tbl_entry_t *)(g4media_app_base + G4MEDIA_OFF_MEDIA_TBL);
                for (uint32_t i = 0u; i < cnt; i++) {
                    if (entries[i].media_id == media_id && entries[i].drv_id != 0u) {
                        out->drv_id = entries[i].drv_id;
                        break;
                    }
                }
            }
        }
    } else if (out->mounted != 0u) {
        /* Fsys_Mount 尚未完成分配真实盘符时，禁止提前报 mounted=1，避免上层拿无效盘符调 GetFreeSpace(0x80000040) 与重复挂载 */
        logf_("G4_MEDIA: GetStatus(0x%x) 真实盘符未就绪(real_drv=0x%02x)，保持 mounted=0 (原 status=%u mounted=%u)",
              media_id, (unsigned)real_drv, out->status, (unsigned)out->mounted);
        out->mounted = 0u;
    }
}

/** 7. Cmd_11009 (0x02b73800) — exec_mount 调用 Fsys_Mount 前的 MediaMount 预检 */
static void g4media_hook_cmd_11009(uint32_t *media_id_in, g4media_cmd11009_out_t *out)
{
    uint32_t media_id = media_id_in ? *media_id_in : 0u;
    uint8_t drv = 0u;
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();

    if (!api->available) {
        if (g4media_orig_cmd_11009) {
            g4media_orig_cmd_11009(media_id_in, out);
        } else if (out) {
            memset(out, 0, sizeof(*out));
        }
        return;
    }

    if (out) {
        memset(out, 0, sizeof(*out));
    }
    if (g4media_probe_phys_card_present_in_g4(media_id, NULL, 0u, &drv)) {
        if (out) {
            out->status  = 0u;
            out->ok_flag = 1u;
            out->val8    = 0u; /* <= 0x63 */
            out->valC    = 1u; /* != 0 */
            out->val10   = 0u; /* valC >= val10 -> OK */
        }
        logf_("G4_MEDIA: Cmd_11009(0x%x) 真卡在线 (drv=0x%02x)，跨代应答 status=0 ok=1",
              media_id, (unsigned)drv);
        return;
    }

    /* 未检测到真卡：透传原函数返回错误，绝不造假 */
    if (g4media_orig_cmd_11009) {
        g4media_orig_cmd_11009(media_id_in, out);
    } else if (out) {
        out->status = G4MEDIA_ERR_UNSUPPORTED_G5;
    }
    logf_("G4_MEDIA: Cmd_11009(0x%x) 无真卡，保持 status=%u",
          media_id, out ? out->status : 0xffffffffu);
}

/** 8. Cmd_11008 (0x02b738c8) — MediaMount 设备路径名查询 (输出 "/dev/mmca" 等设备名, 绝非 "A:\\") */
static void g4media_hook_cmd_11008(g4media_cmd11008_in_t *in, uint32_t *status_out)
{
    uint32_t media_id = in ? in->media_id : 0u;
    if (g4media_orig_cmd_11008) {
        g4media_orig_cmd_11008(in, status_out);
    } else if (status_out) {
        *status_out = 0u;
    }

    uint32_t st = status_out ? *status_out : 0u;
    char dev_buf[32];
    if (st == 0u && in && in->out_name && in->out_name[0] != '\0') {
        if (!g4media_is_simulate_media(media_id) && strncmp(in->out_name, "/nondev/", 8) != 0) {
            if (strcmp(in->out_name, "/dev/ms") == 0 &&
                g4media_probe_phys_card_present_in_g4(media_id, dev_buf, sizeof(dev_buf), NULL) &&
                dev_buf[0] != '\0' && strcmp(dev_buf, "/dev/ms") != 0) {
                memset(in->out_name, 0, 21u);
                g4media_copy_str(in->out_name, 20u, dev_buf);
            }
            g4media_cache_store(media_id, in->out_name, 0u);
        }
        return;
    }

    if (st != 0u && g4media_probe_phys_card_present_in_g4(media_id, dev_buf, sizeof(dev_buf), NULL)) {
        const char *picked = (dev_buf[0] != '\0') ? dev_buf : g4media_pick_dev_name_for_media(media_id, dev_buf, sizeof(dev_buf));
        if (picked[0] != '\0') {
            if (in && in->out_name) {
                /* 严格满足 0x02b729b4 检查 (strlen <= 19, 第 20 字节为 0 避免 0x02bc3174 断言) */
                memset(in->out_name, 0, 21u);
                g4media_copy_str(in->out_name, 20u, picked);
            }
            if (status_out) {
                *status_out = 0u;
            }
            logf_("G4_MEDIA: Cmd_11008(0x%x) 跨代适配 (原 status=%u -> 0, dev_name='%s')",
                  media_id, st, (in && in->out_name) ? in->out_name : "");
        }
    } else if (st != 0u && in && in->out_name) {
        memset(in->out_name, 0, 21u);
    }
}

/** 9. Fsys_Mount (0x02b7392c) — 输入 { const char *dev_name, uint8_t rw_flag } */
static void g4media_hook_fsys_mount(g4media_fsys_mount_in_t *in, g4media_fsys_mount_out_t *out)
{
    const char *dev_name = (in && g4media_is_plausible_cstr(in->dev_name)) ? in->dev_name : "";
    uint8_t rw_flag = in ? in->rw_flag : 0u;

    if (g4media_orig_fsys_mount) {
        g4media_orig_fsys_mount(in, out);
    } else if (out) {
        memset(out, 0, sizeof(*out));
    }
    if (!out) {
        return;
    }
    logf_("G4_MEDIA: Fsys_Mount(dev='%s', rw=%u) 原返回: status=%u drv_letter=0x%02x('%c')",
          dev_name, (unsigned)rw_flag, out->status, (unsigned)out->drv_letter,
          (out->drv_letter >= 0x20u && out->drv_letter < 0x7fu) ? (int)out->drv_letter : '.');

    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available) {
        return;
    }

    uint32_t slot1_id = g4media_get_slot1_media_id();

    /* 情况 A: 四代已挂载 (0x80000021 -> 0x2d) 或原函数未写回 drv_letter，用 Fsys_GetDriveLetter(dev_name) 补全 */
    if (out->drv_letter == 0u && dev_name[0] != '\0' && api->get_drive_letter) {
        uint8_t drv = api->get_drive_letter(dev_name);
        if (drv != 0u) {
            out->status = 0u;
            out->drv_letter = drv;
            if (g4media_is_slot1_dev_name_eligible(dev_name)) {
                g4media_cache_store(slot1_id, dev_name, drv);
            }
            logf_("G4_MEDIA: Fsys_Mount('%s') 已挂载，补全 drv=0x%02x('%c') status=0",
                  dev_name, (unsigned)drv, (drv >= 0x20u && drv < 0x7fu) ? (int)drv : '.');
            return;
        }
    }

    /* 情况 B: 仅当输入设备名属于 Slot1 域（严禁劫持 /nondev/ 或 Slot2 /dev/mmcb*）且物理卡在线时，自适应试探 Slot1 节点 */
    if ((out->status != 0u || out->drv_letter == 0u) &&
        g4media_is_slot1_dev_name_eligible(dev_name) &&
        g4media_probe_phys_card_present_in_g4(slot1_id, NULL, 0u, NULL)) {
        uint32_t mode = rw_flag ? 0x300u : 0x100u;
        for (size_t i = 0u; i < G4MEDIA_SD_CAND_COUNT; i++) {
            const char *cand = g4media_sd_cand_devs[i];
            uint8_t drv = api->get_drive_letter ? api->get_drive_letter(cand) : 0u;
            if (drv != 0u) {
                out->status = 0u;
                out->drv_letter = drv;
                g4media_cache_store(slot1_id, cand, drv);
                logf_("G4_MEDIA: Fsys_Mount 自适应命中已挂载 '%s' -> drv=0x%02x('%c')",
                      cand, (unsigned)drv, (drv >= 0x20u && drv < 0x7fu) ? (int)drv : '.');
                return;
            }
            if (api->fsys_mount) {
                uint8_t m_drv = 0u;
                int m_rc = api->fsys_mount(cand, mode, &m_drv);
                if ((m_rc == 0 || (uint32_t)m_rc == G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G4) &&
                    (m_drv != 0u || (api->get_drive_letter && (m_drv = api->get_drive_letter(cand)) != 0u))) {
                    out->status = 0u;
                    out->drv_letter = m_drv;
                    g4media_cache_store(slot1_id, cand, m_drv);
                    logf_("G4_MEDIA: Fsys_Mount 自适应挂载 '%s' (rc=0x%x) -> drv=0x%02x('%c')",
                          cand, (unsigned)m_rc, (unsigned)m_drv,
                          (m_drv >= 0x20u && m_drv < 0x7fu) ? (int)m_drv : '.');
                    return;
                }
            }
        }
    }
}

/** 9b. Fsys_GetDriveLetter (0x02b73a2c) — 输入 { const char *dev_name } */
static void g4media_hook_fsys_get_drive_letter(g4media_fsys_devname_in_t *in, uint8_t *out_drv)
{
    if (g4media_orig_fsys_get_drv_letter) {
        g4media_orig_fsys_get_drv_letter(in, out_drv);
    } else if (out_drv) {
        *out_drv = 0u;
    }

    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !out_drv || *out_drv != 0u) {
        return;
    }
    const char *dev_name = (in && g4media_is_plausible_cstr(in->dev_name)) ? in->dev_name : NULL;
    if (dev_name && api->get_drive_letter) {
        *out_drv = api->get_drive_letter(dev_name);
    }
    if (*out_drv == 0u && g4media_is_slot1_dev_name_eligible(dev_name)) {
        const g4media_dev_cache_entry_t *c = g4media_cache_lookup(g4media_get_slot1_media_id());
        if (c && c->dev_name[0] != '\0' && api->get_drive_letter) {
            *out_drv = api->get_drive_letter(c->dev_name);
        }
    }
}

/** 10 & 11. 公共四代->五代 Fsys_GetDriveInfo / Fsys_GetDeviceInfo 结构体翻译器 */
static inline void g4media_translate_g4_fsys_buf(int is_device_info,
                                                 const char *label_tag,
                                                 int g4_rc,
                                                 const uint8_t *g4_buf,
                                                 g4media_fsys_info_out_t *out)
{
    out->status = g4media_conv_fsys_err(g4_rc);
    if (g4_rc == 0) {
        uint16_t raw_flags  = (uint16_t)g4_buf[0] | ((uint16_t)g4_buf[1] << 8);
        uint16_t raw_fstype = (uint16_t)g4_buf[2] | ((uint16_t)g4_buf[3] << 8);
        uint32_t raw_vol_id = (uint32_t)g4_buf[0x24] |
                              ((uint32_t)g4_buf[0x25] << 8) |
                              ((uint32_t)g4_buf[0x26] << 16) |
                              ((uint32_t)g4_buf[0x27] << 24);

        /* 依据 appFw.so @ 0x02b73a58..0x02b73a74 及 0x02b73b1c..0x02b73b38 */
        out->b4 = (uint8_t)(raw_flags & 1u);
        out->b5 = (uint8_t)((raw_flags >> 1) & 1u);
        out->b6 = (uint8_t)((raw_flags >> 2) & 1u);
        out->b7 = (uint8_t)((raw_flags >> 5) & 1u);
        out->media_type = 1u; /* SD */
        out->volume_id  = raw_vol_id;
        memcpy(out->volume_label, g4_buf + 0x0au, 0x18u);
        out->volume_label[0x18] = '\0';
        out->fs_type_g5 = g4media_translate_fs_type(raw_fstype);
        logf_("G4_MEDIA: %s(%s) -> g4_rc=0 flags=0x%04x g4_fs=0x%04x->0x%02x label='%s' vol=0x%x",
              is_device_info ? "Fsys_GetDeviceInfo" : "Fsys_GetDriveInfo",
              label_tag, (unsigned)raw_flags, (unsigned)raw_fstype,
              (unsigned)out->fs_type_g5, out->volume_label, out->volume_id);
    } else {
        logf_("G4_MEDIA: %s(%s) -> g4_rc=0x%x (status=%u)",
              is_device_info ? "Fsys_GetDeviceInfo" : "Fsys_GetDriveInfo",
              label_tag, (unsigned)g4_rc, out->status);
    }
}

static void g4media_hook_fsys_get_drive_info(uint8_t *drv_letter_ptr, g4media_fsys_info_out_t *out)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !api->get_drive_info) {
        if (g4media_orig_fsys_get_drive_info) {
            g4media_orig_fsys_get_drive_info(drv_letter_ptr, out);
        } else if (out) {
            memset(out, 0, sizeof(*out));
        }
        return;
    }
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));

    uint8_t drv = drv_letter_ptr ? *drv_letter_ptr : 0u;
    uint8_t g4_buf[256];
    memset(g4_buf, 0, sizeof(g4_buf));
    int g4_rc = api->get_drive_info(drv, g4_buf);

    char tag[16];
    snprintf(tag, sizeof(tag), "drv=0x%02x", (unsigned)drv);
    g4media_translate_g4_fsys_buf(0, tag, g4_rc, g4_buf, out);
}

static void g4media_hook_fsys_get_device_info(g4media_fsys_devname_in_t *in, g4media_fsys_info_out_t *out)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !api->get_device_info) {
        if (g4media_orig_fsys_get_device_info) {
            g4media_orig_fsys_get_device_info(in, out);
        } else if (out) {
            memset(out, 0, sizeof(*out));
        }
        return;
    }
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));

    const char *dev_name = (in && g4media_is_plausible_cstr(in->dev_name)) ? in->dev_name : NULL;
    uint8_t g4_buf[256];
    memset(g4_buf, 0, sizeof(g4_buf));
    int g4_rc = -1;

    if (dev_name) {
        g4_rc = api->get_device_info(dev_name, g4_buf);
    }
    if (g4_rc != 0 && g4media_is_slot1_dev_name_eligible(dev_name)) {
        const g4media_dev_cache_entry_t *c = g4media_cache_lookup(g4media_get_slot1_media_id());
        if (c && c->dev_name[0] != '\0' && (!dev_name || strcmp(c->dev_name, dev_name) != 0)) {
            memset(g4_buf, 0, sizeof(g4_buf));
            int rc2 = api->get_device_info(c->dev_name, g4_buf);
            if (rc2 == 0) {
                g4_rc = 0;
                dev_name = c->dev_name;
            }
        }
    }

    g4media_translate_g4_fsys_buf(1, dev_name ? dev_name : "<null>", g4_rc, g4_buf, out);
}

/** 12. Fsys_GetFreeSpace 公共四代->五代字节数查询翻译器 */
static inline void g4media_query_g4_free_space(uint8_t drv_letter,
                                               uint32_t *out_status,
                                               uint64_t *out_total_bytes,
                                               uint64_t *out_avail_bytes,
                                               uint64_t *out_free_blk_bytes)
{
    *out_status = 0x29u;
    *out_total_bytes = 0u;
    *out_avail_bytes = 0u;
    *out_free_blk_bytes = 0u;

    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->get_free_space) {
        return;
    }

    /* 四代 libInfraFsys.so:Fsys_GetFreeSpace (0x1b6a9) 输出布局:
     * +0x00 totalCluster, +0x04 freeCluster, +0x08 freeBlockCluster,
     * +0x0c bytePerSector, +0x10 sectorPerCluster, +0x14 flags */
    uint8_t g4_buf[64];
    memset(g4_buf, 0, sizeof(g4_buf));
    int g4_rc = api->get_free_space(drv_letter, g4_buf);
    *out_status = g4media_conv_fsys_err(g4_rc);

    if (g4_rc == 0) {
        uint32_t total_clst    = (uint32_t)g4_buf[0x00] | ((uint32_t)g4_buf[0x01] << 8) | ((uint32_t)g4_buf[0x02] << 16) | ((uint32_t)g4_buf[0x03] << 24);
        uint32_t free_clst     = (uint32_t)g4_buf[0x04] | ((uint32_t)g4_buf[0x05] << 8) | ((uint32_t)g4_buf[0x06] << 16) | ((uint32_t)g4_buf[0x07] << 24);
        uint32_t free_blk_clst = (uint32_t)g4_buf[0x08] | ((uint32_t)g4_buf[0x09] << 8) | ((uint32_t)g4_buf[0x0a] << 16) | ((uint32_t)g4_buf[0x0b] << 24);
        uint32_t bytes_per_sec = (uint32_t)g4_buf[0x0c] | ((uint32_t)g4_buf[0x0d] << 8) | ((uint32_t)g4_buf[0x0e] << 16) | ((uint32_t)g4_buf[0x0f] << 24);
        uint32_t sec_per_clst  = (uint32_t)g4_buf[0x10] | ((uint32_t)g4_buf[0x11] << 8) | ((uint32_t)g4_buf[0x12] << 16) | ((uint32_t)g4_buf[0x13] << 24);
        uint64_t bytes_per_clst = (uint64_t)bytes_per_sec * (uint64_t)sec_per_clst;

        *out_total_bytes    = (uint64_t)total_clst * bytes_per_clst;
        *out_avail_bytes    = (uint64_t)free_clst * bytes_per_clst;
        *out_free_blk_bytes = (uint64_t)free_blk_clst * bytes_per_clst;
    }
}

/** 12a. Fsys_GetFreeSpace #1 (0x02b73ce8, 0x38B 输出) */
static void g4media_hook_fsys_get_free_space(uint8_t *drv_letter_ptr, g4media_fsys_freespace_out_t *out)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !api->get_free_space) {
        if (g4media_orig_fsys_get_free_space) {
            g4media_orig_fsys_get_free_space(drv_letter_ptr, out);
        } else if (out) {
            memset(out, 0, sizeof(*out));
        }
        return;
    }

    uint8_t drv = drv_letter_ptr ? *drv_letter_ptr : 0u;
    if (!out) {
        return;
    }
    memset(out, 0, sizeof(*out));
    g4media_query_g4_free_space(drv, &out->status, &out->bytes_08, &out->bytes_10, &out->bytes_18);

    static uint32_t log_cnt = 0u;
    if (log_cnt < 12u || out->status != 0u) {
        log_cnt++;
        logf_("G4_MEDIA: Fsys_GetFreeSpace#1(drv=0x%02x) -> status=%u total=%llu avail=%llu blk=%llu",
              (unsigned)drv, out->status,
              (unsigned long long)out->bytes_08,
              (unsigned long long)out->bytes_10,
              (unsigned long long)out->bytes_18);
    }
}

/** 12b. Fsys_GetFreeSpace #2 (0x02b73e80, 0x14B avail/total/status 输出) */
static void g4media_hook_fsys_get_free_space2(uint8_t *drv_letter_ptr, g4media_fsys_freespace2_out_t *out)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !api->get_free_space) {
        if (g4media_orig_fsys_get_free_space2) {
            g4media_orig_fsys_get_free_space2(drv_letter_ptr, out);
        } else if (out) {
            memset(out, 0, sizeof(*out));
        }
        return;
    }

    uint8_t drv = drv_letter_ptr ? *drv_letter_ptr : 0u;
    if (!out) {
        return;
    }
    uint64_t total_bytes = 0u;
    uint64_t avail_bytes = 0u;
    uint64_t dummy_blk = 0u;
    uint32_t st = 0x29u;
    memset(out, 0, sizeof(*out));
    g4media_query_g4_free_space(drv, &st, &total_bytes, &avail_bytes, &dummy_blk);

    out->avail_lo = (uint32_t)(avail_bytes & 0xffffffffu);
    out->avail_hi = (uint32_t)((avail_bytes >> 32) & 0xffffffffu);
    out->total_lo = (uint32_t)(total_bytes & 0xffffffffu);
    out->total_hi = (uint32_t)((total_bytes >> 32) & 0xffffffffu);
    out->status   = st;

    static uint32_t log_cnt2 = 0u;
    if (log_cnt2 < 12u || st != 0u) {
        log_cnt2++;
        logf_("G4_MEDIA: Fsys_GetFreeSpace#2(drv=0x%02x) -> status=%u total=%llu avail=%llu",
              (unsigned)drv, st,
              (unsigned long long)total_bytes,
              (unsigned long long)avail_bytes);
    }
}

/** 13. notify_initial_media_status (0x02af9e04) — 仅依据四代真实探测，绝不假冒空槽 */
static void g4media_hook_notify_media_status(void *self, uint32_t slot1, uint32_t slot2)
{
    logf_("G4_MEDIA: notify_initial_media_status 触发 (原始通知: slot1=0x%x, slot2=0x%x)", slot1, slot2);

    uint8_t drv = 0u;
    if (slot1 == 0u && g4media_probe_phys_card_present_in_g4(g4media_get_slot1_media_id(), NULL, 0u, &drv)) {
        slot1 = 1u;
        if (self) {
            *(volatile uint8_t *)((uintptr_t)self + 0x32du) = 1u; /* slot1_writable_flag */
            *(volatile uint8_t *)((uintptr_t)self + 0x32fu) = 1u; /* is_media_status_valid */
        }
        logf_("G4_MEDIA: 四代确认 Slot1 真卡在线 (drv=0x%02x)，同步 slot1=0x1, writable=1, valid=1",
              (unsigned)drv);
    } else if (slot1 == 0u) {
        logf_("G4_MEDIA: 未检测到物理 SD 卡 (slot1=0x%x 保持不变)", slot1);
    }

    if (g4media_orig_notify_media_status) {
        g4media_orig_notify_media_status(self, slot1, slot2);
    }
}

/** 14. 媒体联锁检查器 (0x02af95e8) 条件钩子 — 严防空槽伪造在位，仅真卡缺失通知时兜底 */
static int g4media_hook_check_media_status(void *p_self)
{
    if (!p_self) {
        return 0;
    }
    uint8_t *self = *(uint8_t *const *)p_self;
    if (!self) {
        return 0;
    }

    uint8_t  valid = *(const volatile uint8_t *)(self + 0x32fu);
    uint32_t slot1 = *(const volatile uint32_t *)(self + 0x330u);
    uint8_t  w1    = *(const volatile uint8_t *)(self + 0x32du);
    uint32_t slot2 = *(const volatile uint32_t *)(self + 0x334u);
    uint8_t  w2    = *(const volatile uint8_t *)(self + 0x32eu);

    int orig_res = 1;
    if (valid == 0u) {
        orig_res = 0;
    } else if ((slot1 - 1u) <= 1u && w1 == 0u) {
        orig_res = 0;
    } else if ((slot2 - 1u) <= 1u) {
        orig_res = (int)w2;
    }

    if (orig_res == 0 && valid == 0u) {
        uint8_t drv = 0u;
        if (g4media_probe_phys_card_present_in_g4(g4media_get_slot1_media_id(), NULL, 0u, &drv)) {
            *(volatile uint8_t *)(self + 0x32fu) = 1u;
            if (*(const volatile uint32_t *)(self + 0x330u) == 0u) {
                *(volatile uint32_t *)(self + 0x330u) = 1u;
            }
            if (*(const volatile uint8_t *)(self + 0x32du) == 0u) {
                *(volatile uint8_t *)(self + 0x32du) = 1u;
            }
            logf_("G4_MEDIA: check_media_status valid=0 但真卡在线 (drv=0x%02x)，补齐联锁返回 1",
                  (unsigned)drv);
            return 1;
        }
    }

    return orig_res;
}

/* ========================================================================= */
/* 7. 主初始化入口                                                            */
/* ========================================================================= */

static inline void init_bridge_media(uintptr_t app_base, uintptr_t mpr_base)
{
    if (!app_base) {
        logf_("G4_MEDIA_WARN: app_base 为空，取消初始化");
        return;
    }

    if (__sync_lock_test_and_set(&g4media_bridge_initialized, 1u)) {
        logf_("G4_MEDIA: 媒体桥接层已初始化，跳过重复装载");
        return;
    }

    g4media_app_base = app_base;
    g4media_mpr_base = mpr_base;
    (void)g4media_mpr_base;

    logf_("G4_MEDIA: 初始化存储与联锁桥接层 (v33 MovieRemain 与 Playback 全链路诊断版, app_base=%p, mpr_base=%p)...",
          (void *)app_base, (void *)mpr_base);

    g4media_diagnose_storage_state("init");

    static const uint8_t sig_init_media[8] = {0x2du, 0xe9u, 0xf0u, 0x43u, 0xdfu, 0xb0u, 0x02u, 0xafu};
    static const uint8_t sig_get_info[8]   = {0xf0u, 0xb5u, 0xbfu, 0xb0u, 0x06u, 0x46u, 0x02u, 0xafu};
    static const uint8_t sig_rpc_11000[8]  = {0x2du, 0xe9u, 0xf0u, 0x43u, 0x8du, 0xb0u, 0x05u, 0x46u};
    static const uint8_t sig_rpc_12001[8]  = {0x2du, 0xe9u, 0xf0u, 0x43u, 0x8du, 0xb0u, 0x05u, 0x46u};
    static const uint8_t sig_rpc_12002[8]  = {0x2du, 0xe9u, 0xf0u, 0x43u, 0x8du, 0xb0u, 0x05u, 0x46u};
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

    g4media_orig_init_media = (g4media_init_media_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_INIT_MEDIA, sig_init_media, (void *)g4media_hook_init_media, "appFw:InitMedia");

    g4media_orig_get_media_info = (g4media_get_media_info_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_GET_MEDIA_INFO, sig_get_info, (void *)g4media_hook_get_media_info, "appFw:GetMediaInfo");

    g4media_orig_rpc_11000 = (g4media_rpc_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_RPC_11000, sig_rpc_11000, (void *)g4media_hook_rpc_11000, "appFw:StartInOut_0x11000");

    g4media_orig_rpc_12001 = (g4media_rpc_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_RPC_12001, sig_rpc_12001, (void *)g4media_hook_rpc_12001, "appFw:StartTemp_0x12001");

    g4media_orig_rpc_12002 = (g4media_rpc_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_RPC_12002, sig_rpc_12002, (void *)g4media_hook_rpc_12002, "appFw:StopTemp_0x12002");

    g4media_orig_mount = (g4media_mount_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_MOUNT, sig_mount, (void *)g4media_hook_mount, "appFw:Mount_0x21000");

    /* 修补 GetStatus 命令字: 五代 0x11002 -> 四代 GetStatus 0x11003 */
    uintptr_t status_lit_va = app_base + G4MEDIA_OFF_GET_STATUS_CMD_LIT;
    if (*(const volatile uint32_t *)status_lit_va == G4MEDIA_CMD_GET_STATUS_G5) {
        g4media_patch_u32(status_lit_va, G4MEDIA_CMD_GET_STATUS_G4, "appFw:GetStatus_cmd_0x11003");
    } else {
        logf_("G4_MEDIA_WARN: GetStatus lit @ %p = 0x%08x (非 0x11002)，跳过改写",
              (void *)status_lit_va, *(const volatile uint32_t *)status_lit_va);
    }
    g4media_orig_get_status = (g4media_get_status_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_GET_STATUS, sig_status, (void *)g4media_hook_get_status, "appFw:GetStatus_0x11003");

    g4media_orig_cmd_11009 = (g4media_cmd11009_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_CMD_11009, sig_11009, (void *)g4media_hook_cmd_11009, "appFw:Cmd_11009");

    g4media_orig_cmd_11008 = (g4media_cmd11008_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_CMD_11008, sig_11008, (void *)g4media_hook_cmd_11008, "appFw:Cmd_11008");

    g4media_orig_fsys_mount = (g4media_fsys_mount_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_FSYS_MOUNT, sig_fs_mount, (void *)g4media_hook_fsys_mount, "appFw:Fsys_Mount");

    g4media_orig_fsys_get_drv_letter = (g4media_fsys_get_drv_letter_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_FSYS_GET_DRIVE_LETTER, sig_fs_letter, (void *)g4media_hook_fsys_get_drive_letter, "appFw:Fsys_GetDriveLetter");

    g4media_orig_fsys_get_drive_info = (g4media_fsys_drive_info_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_FSYS_GET_DRIVE_INFO, sig_fs_drv, (void *)g4media_hook_fsys_get_drive_info, "appFw:Fsys_GetDriveInfo");

    g4media_orig_fsys_get_device_info = (g4media_fsys_device_info_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_FSYS_GET_DEVICE_INFO, sig_fs_dev, (void *)g4media_hook_fsys_get_device_info, "appFw:Fsys_GetDeviceInfo");

    g4media_orig_fsys_get_free_space = (g4media_fsys_freespace_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_FSYS_GET_FREE_SPACE, sig_fs_free, (void *)g4media_hook_fsys_get_free_space, "appFw:Fsys_GetFreeSpace");

    g4media_orig_fsys_get_free_space2 = (g4media_fsys_freespace2_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_FSYS_GET_FREE_SPACE2, sig_fs_free2, (void *)g4media_hook_fsys_get_free_space2, "appFw:Fsys_GetFreeSpace2");

    g4media_orig_notify_media_status = (g4media_notify_media_status_fn_t)g4media_install_tramp8(
        app_base + G4MEDIA_OFF_NOTIFY_MEDIA_STATUS, sig_notify, (void *)g4media_hook_notify_media_status, "appFw:notify_initial_media_status");

    /* 媒体联锁条件钩子 */
    uintptr_t check_media_va = app_base + G4MEDIA_OFF_CHECK_MEDIA_STATUS;
    static const uint8_t sig_check_media_status[8] = {0x03u, 0x68u, 0x80u, 0xb5u, 0x00u, 0xafu, 0x93u, 0xf8u};
    if (memcmp((const void *)check_media_va, sig_check_media_status, sizeof(sig_check_media_status)) == 0) {
        patch_thumb_jump((void *)check_media_va, (void *)g4media_hook_check_media_status, "appFw:check_media_status");
        logf_("G4_MEDIA: sequence_still_record 媒体联锁条件钩子 @ %p 安装成功", (void *)check_media_va);
    } else {
        logf_("G4_MEDIA_WARN: check_media_status @ %p 签名不匹配，安全跳过", (void *)check_media_va);
    }

    /* v36 撤回 0x02b8af5e 强行改 NOP 补丁，避免误走双卡分支污染 simulRec/isolate/w28，交由 mpr::SetMovieRecParam 精确置位单卡参数 */
    logf_("G4_MEDIA: 存储与联锁桥接层全部 Hook 装载完成 (已撤回 0x02b8af5e 双卡分支补丁)");
}

/* ========================================================================= */
/* 8. v32 C-API Fsys_* 跨代结构体/错误码翻译与 GOT/DMM 全链路桥接层            */
/* ========================================================================= */

#define G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE   0x7cu
#define G4MEDIA_FSYS_G5_FREE_SPACE_SIZE   0x34u
#define G4MEDIA_DMM_DCF_UNIT_TYPE         0x660u
#define G4MEDIA_DMM_DCF_SIZE              0x00113898u
#define G4MEDIA_DMM_DCF_MMAP_SIZE         0x00114000u
#define G4MEDIA_DMM_HANDLE_BASE           0x7f00u
#define G4MEDIA_DMM_MAX_SLOTS             16u
#define G4MEDIA_DCF_SLOT_COUNT            4u
#define G4MEDIA_DCF_SLOT_STRIDE           0x54e0u
#define G4MEDIA_MOVIE_REC_PARAM_SIZE      0x188u
#define G4MEDIA_MOVIE_REMAIN_IN_SIZE      0x3cu
#define G4MEDIA_DEF_MAIN_VQUALITY         0x0eu /* 50000 kbps */
#define G4MEDIA_DEF_SUB_VQUALITY          0x1au /* 9000 kbps proxy */

typedef int      (*g4media_mpr_init_fn_t)(const void *init_in_param);
typedef int      (*g4media_mpr_load_fn_t)(const void *load_in_param);
typedef int      (*g4media_mpr_set_issue_event_fn_t)(uint32_t evt_id, const void *param, uint32_t size);
typedef int      (*g4media_mpr_get_movie_remain_fn_t)(const void *in_param, void *out_param);
typedef int      (*g4media_mpr_set_movie_rec_param_fn_t)(const void *param);
typedef int      (*g4media_mpr_get_movie_rec_param_fn_t)(void *out_param);
typedef int      (*g4media_mpr_set_playback_param_fn_t)(const void *param);
typedef int      (*g4media_mpr_get_movie_rec_status_internal_fn_t)(void *out_param);
typedef int      (*g4media_calc_movie_remain_fn_t)(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3);
typedef int      (*g4media_sidb_get_remain_fn_t)(uint32_t slot_id, uint32_t content_type, uint32_t *out_remain);
typedef struct { uint32_t w[15]; } g4media_mov_remain_in_val_t;
typedef struct __attribute__((aligned(8))) { uint64_t q[49]; } g4media_movie_rec_val_t;
typedef int      (*g4media_calc_recordable_time_fn_t)(g4media_mov_remain_in_val_t in_val, uint32_t *out_rem);
typedef int      (*g4media_rate_check_fn_t)(uint32_t drv_char, g4media_movie_rec_val_t rec_val, uint8_t *out_flag, uint32_t *out_inh);
typedef void *   (*g4media_dmm_alloc_core_fn_t)(uint32_t unit_type, uint32_t a1, uint32_t cmd, uint32_t a3, void *out_unit, uint32_t flag, void *p_munmap);
typedef int      (*g4media_dmm_close_and_free_fn_t)(uint32_t unit_handle);
typedef int      (*g4media_dcf_load_fn_t)(uint32_t slot_idx, uint32_t enable, const void *dir_str, uint32_t r3, uint32_t sp0);
typedef uint32_t (*g4media_dcf_remain_folders_fn_t)(const void *slot_mask_arr, uint32_t mode, void *out_arr);
typedef void     (*g4media_got_hook_cb_t)(uintptr_t mod_base, uintptr_t got_off, void *new_fn, const char *label);

typedef struct {
    void     *addr;
    size_t    size;
    uint16_t  handle;
    uint32_t  unit_type;
    uint8_t   in_use;
} g4media_dmm_slot_t;

static g4media_mpr_init_fn_t                         g4media_orig_mpr_init                        = NULL;
static g4media_mpr_load_fn_t                         g4media_orig_mpr_load                        = NULL;
static g4media_mpr_set_issue_event_fn_t              g4media_orig_mpr_set_issue_event             = NULL;
static g4media_mpr_get_movie_remain_fn_t             g4media_orig_mpr_get_movie_remain            = NULL;
static g4media_mpr_set_movie_rec_param_fn_t          g4media_orig_mpr_set_movie_rec_param         = NULL;
static g4media_mpr_get_movie_rec_param_fn_t          g4media_orig_mpr_get_movie_rec_param         = NULL;
static g4media_mpr_set_playback_param_fn_t           g4media_orig_mpr_set_playback_param          = NULL;
static g4media_mpr_get_movie_rec_status_internal_fn_t g4media_orig_mpr_get_movie_rec_status_internal = NULL;
static g4media_calc_movie_remain_fn_t                g4media_orig_calc_movie_remain               = NULL;
static g4media_sidb_get_remain_fn_t                  g4media_orig_sidb_get_remain                 = NULL;
static g4media_calc_recordable_time_fn_t             g4media_orig_calc_recordable_time            = NULL;
static g4media_rate_check_fn_t                       g4media_orig_rate_check                      = NULL;
static g4media_dmm_alloc_core_fn_t                   g4media_orig_dmm_alloc_core                  = NULL;
static g4media_dmm_close_and_free_fn_t               g4media_orig_dmm_close_and_free              = NULL;
static g4media_dcf_load_fn_t                         g4media_orig_dcf_load                        = NULL;
static g4media_dcf_remain_folders_fn_t               g4media_orig_dcf_remain_folders              = NULL;
static g4media_got_hook_cb_t                         g4media_custom_got_hook_cb                   = NULL;
static uintptr_t                                     g4media_mp5_base                             = 0u;
static volatile uint32_t                             g4media_cfys_log_budget                      = 256u;
static volatile uint32_t                             g4media_movie_diag_budget                    = 96u;
static volatile uint32_t                             g4media_drive_raw_logged                   = 0u;
static g4media_dmm_slot_t                            g4media_dmm_slots[G4MEDIA_DMM_MAX_SLOTS];
static volatile uint32_t                             g4media_dmm_lock                             = 0u;

static inline uint16_t g4media_rd16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t g4media_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void g4media_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static inline void g4media_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static inline uint8_t g4media_upper_drv(uint8_t drv)
{
    if (drv >= 'a' && drv <= 'z') {
        return (uint8_t)(drv - ('a' - 'A'));
    }
    return drv;
}

static inline int g4media_cfys_take_log_slot(int force)
{
    if (force) {
        return 1;
    }
    for (;;) {
        uint32_t cur = __atomic_load_n(&g4media_cfys_log_budget, __ATOMIC_RELAXED);
        if (cur == 0u) {
            return 0;
        }
        if (__sync_bool_compare_and_swap(&g4media_cfys_log_budget, cur, cur - 1u)) {
            return 1;
        }
    }
}

static inline int g4media_is_drive_mounted_in_g4(uint8_t drv_letter)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->available || !api->get_mount_drives) {
        return 0;
    }
    uint8_t up = g4media_upper_drv(drv_letter);
    if (up < 'A' || up > 'Z') {
        return 0;
    }
    uint32_t mask = api->get_mount_drives();
    return ((mask & (1u << (unsigned)(up - 'A'))) != 0u) ? 1 : 0;
}

/**
 * @brief 将四代 Fsys_GetDriveInfo / Fsys_GetDeviceInfo (0x38 B) 精准翻译为五代 ABI (0x7c B)
 *
 * 已通过 Gen4 libInfraFsys.so (0x17250/0x18ac0/0x18c44) 与
 * Gen5 libInfraFsys_g5.so (0x1fe70/0x1fd40) + libmpr_g5.so::_Load (0x000c942c..0x000c9492) 交叉实证。
 */
static inline void g4media_translate_drive_info_g4_to_g5(uint8_t drv_letter, const uint8_t *g4_buf, void *g5_out_void)
{
    if (!g5_out_void) {
        return;
    }
    uint8_t *g5 = (uint8_t *)g5_out_void;
    memset(g5, 0, G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE);
    if (!g4_buf) {
        return;
    }

    uint16_t flags    = g4media_rd16(g4_buf + 0x00u);
    uint16_t g5_flags = (uint16_t)(flags & 0x07u); /* 仅保留 bit0..2 只读/WP/Err；屏蔽 G4 内部卷属性 0x10..0x80 (避免 0xf0 触发 mpr::_Load 假只读锁) */
    uint16_t dev_type = g4media_rd16(g4_buf + 0x02u);
    uint32_t unit_sz  = g4media_rd32(g4_buf + 0x04u);
    uint16_t mclass   = g4media_rd16(g4_buf + 0x08u);
    uint32_t vol_id   = g4media_rd32(g4_buf + 0x24u);
    uint16_t fs_type  = g4media_rd16(g4_buf + 0x28u);

    g4media_wr16(g5 + 0x00u, g5_flags);
    g4media_wr16(g5 + 0x02u, dev_type);
    g4media_wr32(g5 + 0x04u, unit_sz);
    g4media_wr16(g5 + 0x14u, mclass);
    memcpy(g5 + 0x16u, g4_buf + 0x0au, 24u);
    g4media_wr32(g5 + 0x58u, vol_id);
    g4media_wr16(g5 + 0x5cu, fs_type);
    g5[0x6cu] = (g5_flags != 0u) ? 1u : 0u;
    g5[0x6du] = g4media_upper_drv(drv_letter);
}

/**
 * @brief 将四代 Fsys_GetFreeSpace (0x24 B) 精准翻译为五代 ABI (0x34 B)
 *
 * 四代 (PrFILE_getdev @ 0x000237e1): +0x00 total, +0x04 free, +0x08 blk, +0x0c bps, +0x10 spc, +0x14 flags
 * 五代 (PrFILE_getdev @ 0x0002e70d / _Load @ 0x000c9502):
 *   +0x00 total, +0x04 free, +0x08 blk, +0x0c free_lo, +0x10 free_hi(0), +0x14 mode(0),
 *   +0x18 spc, +0x1c bps, +0x20 flags
 */
static inline void g4media_translate_free_space_g4_to_g5(const uint8_t *g4_buf, void *g5_out_void)
{
    if (!g5_out_void) {
        return;
    }
    uint8_t *g5 = (uint8_t *)g5_out_void;
    memset(g5, 0, G4MEDIA_FSYS_G5_FREE_SPACE_SIZE);
    if (!g4_buf) {
        return;
    }

    uint32_t total_clst = g4media_rd32(g4_buf + 0x00u);
    uint32_t free_clst  = g4media_rd32(g4_buf + 0x04u);
    uint32_t blk_clst   = g4media_rd32(g4_buf + 0x08u);
    uint32_t bps        = g4media_rd32(g4_buf + 0x0cu);
    uint32_t spc        = g4media_rd32(g4_buf + 0x10u);
    uint32_t flags      = g4media_rd32(g4_buf + 0x14u);

    g4media_wr32(g5 + 0x00u, total_clst);
    g4media_wr32(g5 + 0x04u, free_clst);
    g4media_wr32(g5 + 0x08u, blk_clst);
    g4media_wr32(g5 + 0x0cu, free_clst);
    g4media_wr32(g5 + 0x18u, spc);
    g4media_wr32(g5 + 0x1cu, bps);
    g4media_wr32(g5 + 0x20u, flags);
}

static int g4media_c_fsys_get_drive_info(uint8_t drv_letter, void *out_g5)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->get_drive_info) {
        if (out_g5) memset(out_g5, 0, G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE);
        return (int)0x80010002u;
    }

    uint8_t g4_buf[64];
    memset(g4_buf, 0, sizeof(g4_buf));
    int rc = api->get_drive_info(drv_letter, g4_buf);
    if (rc == 0) {
        g4media_translate_drive_info_g4_to_g5(drv_letter, g4_buf, out_g5);
    } else if (out_g5) {
        memset(out_g5, 0, G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE);
    }

    if (g4media_cfys_take_log_slot(rc != 0)) {
        const uint8_t *g5 = (const uint8_t *)out_g5;
        uint16_t raw_flags = (rc == 0) ? g4media_rd16(g4_buf + 0x00u) : 0u;
        uint32_t unit_sz   = (rc == 0) ? g4media_rd32(g4_buf + 0x04u) : 0u;
        uint16_t mclass    = (rc == 0) ? g4media_rd16(g4_buf + 0x08u) : 0u;
        logf_("G4_MEDIA_CFYS: GetDriveInfo(drv='%c'/0x%02x) -> rc=0x%x raw_flags=0x%04x g5_flags=0x%04x dev=0x%04x fs=0x%04x unit=0x%x mclass=0x%04x vol=0x%08x ro=%u",
              (drv_letter >= 0x20u && drv_letter < 0x7fu) ? (int)drv_letter : '.',
              (unsigned)drv_letter, (unsigned)rc,
              (unsigned)raw_flags,
              g5 ? (unsigned)g4media_rd16(g5 + 0x00u) : 0u,
              g5 ? (unsigned)g4media_rd16(g5 + 0x02u) : 0u,
              g5 ? (unsigned)g4media_rd16(g5 + 0x5cu) : 0u,
              (unsigned)unit_sz, (unsigned)mclass,
              g5 ? (unsigned)g4media_rd32(g5 + 0x58u) : 0u,
              g5 ? (unsigned)g5[0x6cu] : 0u);
    }
    if (rc == 0 && g4media_upper_drv(drv_letter) == 'A' &&
        !__sync_lock_test_and_set(&g4media_drive_raw_logged, 1u)) {
        logf_("G4_MEDIA_DRV_RAW: w0..7=[%08x %08x %08x %08x %08x %08x %08x %08x] w8..13=[%08x %08x %08x %08x %08x %08x]",
              g4media_rd32(g4_buf + 0x00u), g4media_rd32(g4_buf + 0x04u), g4media_rd32(g4_buf + 0x08u), g4media_rd32(g4_buf + 0x0cu),
              g4media_rd32(g4_buf + 0x10u), g4media_rd32(g4_buf + 0x14u), g4media_rd32(g4_buf + 0x18u), g4media_rd32(g4_buf + 0x1cu),
              g4media_rd32(g4_buf + 0x20u), g4media_rd32(g4_buf + 0x24u), g4media_rd32(g4_buf + 0x28u), g4media_rd32(g4_buf + 0x2cu),
              g4media_rd32(g4_buf + 0x30u), g4media_rd32(g4_buf + 0x34u));
    }
    return rc;
}

static int g4media_c_fsys_get_device_info(const char *dev_name, void *out_g5)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->get_device_info) {
        if (out_g5) memset(out_g5, 0, G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE);
        return (int)0x80010002u;
    }

    uint8_t g4_buf[64];
    memset(g4_buf, 0, sizeof(g4_buf));
    int rc = api->get_device_info(dev_name, g4_buf);
    if (rc == 0) {
        uint8_t drv = (g4media_is_plausible_cstr(dev_name) && api->get_drive_letter)
                          ? api->get_drive_letter(dev_name) : 0u;
        g4media_translate_drive_info_g4_to_g5(drv, g4_buf, out_g5);
    } else if (out_g5) {
        memset(out_g5, 0, G4MEDIA_FSYS_G5_DRIVE_INFO_SIZE);
    }

    if (g4media_cfys_take_log_slot(rc != 0)) {
        logf_("G4_MEDIA_CFYS: GetDeviceInfo('%s') -> rc=0x%x",
              g4media_is_plausible_cstr(dev_name) ? dev_name : "", (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_get_free_space(uint8_t drv_letter, void *out_g5)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (!api->get_free_space) {
        if (out_g5) memset(out_g5, 0, G4MEDIA_FSYS_G5_FREE_SPACE_SIZE);
        return (int)0x80010002u;
    }

    uint8_t g4_buf[64];
    memset(g4_buf, 0, sizeof(g4_buf));
    int rc = api->get_free_space(drv_letter, g4_buf);
    if (rc == 0) {
        g4media_translate_free_space_g4_to_g5(g4_buf, out_g5);
    } else if (out_g5) {
        memset(out_g5, 0, G4MEDIA_FSYS_G5_FREE_SPACE_SIZE);
    }

    if (g4media_cfys_take_log_slot(rc != 0)) {
        const uint8_t *g5 = (const uint8_t *)out_g5;
        logf_("G4_MEDIA_CFYS: GetFreeSpace(drv='%c'/0x%02x) -> rc=0x%x total=%u free=%u spc=%u bps=%u",
              (drv_letter >= 0x20u && drv_letter < 0x7fu) ? (int)drv_letter : '.',
              (unsigned)drv_letter, (unsigned)rc,
              g5 ? g4media_rd32(g5 + 0x00u) : 0u,
              g5 ? g4media_rd32(g5 + 0x04u) : 0u,
              g5 ? g4media_rd32(g5 + 0x18u) : 0u,
              g5 ? g4media_rd32(g5 + 0x1cu) : 0u);
    }
    return rc;
}

static int g4media_c_fsys_mount(const char *dev_name, uint32_t mode, uint8_t *out_drv, void *opt)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = (int)0x80010002u;
    if (api->fsys_mount4) {
        rc = api->fsys_mount4(dev_name, mode, out_drv, opt);
    } else if (api->fsys_mount) {
        rc = api->fsys_mount(dev_name, mode, out_drv);
    }
    if ((rc == 0 || (uint32_t)rc == G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G4) &&
        out_drv && *out_drv == 0u && g4media_is_plausible_cstr(dev_name) && api->get_drive_letter) {
        *out_drv = api->get_drive_letter(dev_name);
    }
    if (g4media_cfys_take_log_slot(rc != 0 && (uint32_t)rc != G4MEDIA_FSYS_ERR_ALREADY_MOUNT_G4)) {
        logf_("G4_MEDIA_CFYS: Mount('%s', mode=0x%x) -> rc=0x%x drv=0x%02x",
              g4media_is_plausible_cstr(dev_name) ? dev_name : "", mode, (unsigned)rc,
              out_drv ? (unsigned)*out_drv : 0u);
    }
    return rc;
}

static int g4media_c_fsys_unmount(uint8_t drv_letter, uint32_t opt)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->fsys_unmount ? api->fsys_unmount(drv_letter, opt) : (int)0x80010002u;
    logf_("G4_MEDIA_CFYS: Unmount(drv='%c'/0x%02x, opt=0x%x) -> rc=0x%x",
          (drv_letter >= 0x20u && drv_letter < 0x7fu) ? (int)drv_letter : '.',
          (unsigned)drv_letter, opt, (unsigned)rc);
    return rc;
}

static int g4media_c_fsys_find_first(const char *pattern, uint32_t attr, void *out_find_info)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->find_first ? api->find_first(pattern, attr, out_find_info) : (int)0x80010002u;
    if (g4media_cfys_take_log_slot(rc != 0 && rc != 2)) {
        logf_("G4_MEDIA_CFYS: FindFirst('%s', attr=0x%x) -> rc=0x%x",
              g4media_is_plausible_cstr(pattern) ? pattern : "", attr, (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_find_next(void *find_info)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->find_next ? api->find_next(find_info) : (int)0x80010002u;
    if (rc != 0 && rc != 2 && g4media_cfys_take_log_slot(1)) {
        logf_("G4_MEDIA_CFYS: FindNext(%p) -> rc=0x%x", find_info, (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_stat(const char *path, void *out_stat)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_stat ? api->f_stat(path, out_stat) : (int)0x80010002u;
    if (g4media_cfys_take_log_slot(rc != 0 && rc != 2)) {
        logf_("G4_MEDIA_CFYS: Stat('%s') -> rc=0x%x",
              g4media_is_plausible_cstr(path) ? path : "", (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_open(const char *path, uint32_t *out_fd, uint32_t mode)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_open ? api->f_open(path, out_fd, mode) : (int)0x80010002u;
    int mapped_rc = rc;
    /* 四代缺父目录创建/打开失败返回 0x80000030，而五代 sidb/mpr 判定对应五代错误码 0x80000051 */
    if ((uint32_t)rc == 0x80000030u && path != NULL && out_fd != NULL) {
        mapped_rc = (int)0x80000051u;
    }
    if (g4media_cfys_take_log_slot((mapped_rc != 0 && mapped_rc != 2) ||
                                   (g4media_is_plausible_cstr(path) && strstr(path, "DATABASE") != NULL))) {
        logf_("G4_MEDIA_CFYS: Open('%s', mode=0x%x) -> rc=0x%x%s fd=0x%x",
              g4media_is_plausible_cstr(path) ? path : "", mode, (unsigned)mapped_rc,
              (mapped_rc != rc) ? " (mapped from 0x80000030)" : "",
              out_fd ? *out_fd : 0u);
    }
    return mapped_rc;
}

static int g4media_c_fsys_close(uint32_t fd)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    return api->f_close ? api->f_close(fd) : (int)0x80010002u;
}

static int g4media_c_fsys_mkdir(const char *path)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_mkdir ? api->f_mkdir(path) : (int)0x80010002u;
    if (g4media_cfys_take_log_slot(rc != 0)) {
        logf_("G4_MEDIA_CFYS: Mkdir('%s') -> rc=0x%x",
              g4media_is_plausible_cstr(path) ? path : "", (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_remove(const char *path)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_remove ? api->f_remove(path) : (int)0x80010002u;
    if (g4media_cfys_take_log_slot(rc != 0)) {
        logf_("G4_MEDIA_CFYS: Remove('%s') -> rc=0x%x",
              g4media_is_plausible_cstr(path) ? path : "", (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_chmod(const char *path, uint32_t mode)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_chmod ? api->f_chmod(path, mode) : (int)0x80010002u;
    if (g4media_cfys_take_log_slot(rc != 0)) {
        logf_("G4_MEDIA_CFYS: Chmod('%s', mode=0x%x) -> rc=0x%x",
              g4media_is_plausible_cstr(path) ? path : "", mode, (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_read(uint32_t fd, void *buf, uint32_t len)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_read ? api->f_read(fd, buf, len) : (int)0x80010002u;
    if (rc < 0 && g4media_cfys_take_log_slot(1)) {
        logf_("G4_MEDIA_CFYS: Read(fd=0x%x, len=%u) -> rc=0x%x", fd, len, (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_write(uint32_t fd, const void *buf, uint32_t len)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_write ? api->f_write(fd, buf, len) : (int)0x80010002u;
    if (rc < 0 && g4media_cfys_take_log_slot(1)) {
        logf_("G4_MEDIA_CFYS: Write(fd=0x%x, len=%u) -> rc=0x%x", fd, len, (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_write_and_flush(uint32_t fd, const void *buf, uint32_t len)
{
    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    int rc = api->f_write_and_flush ? api->f_write_and_flush(fd, buf, len) : (int)0x80010002u;
    if (rc < 0 && g4media_cfys_take_log_slot(1)) {
        logf_("G4_MEDIA_CFYS: WriteAndFlush(fd=0x%x, len=%u) -> rc=0x%x", fd, len, (unsigned)rc);
    }
    return rc;
}

/* 四代 libInfraFsys.so 缺失的 6 个五代 Fsys_* 符号适配器 */
static int g4media_c_fsys_lock(const char *path, uint32_t mode)
{
    if (!g4media_is_plausible_cstr(path)) {
        return (int)0x80000030u;
    }
    if (path[1] == ':' && !g4media_is_drive_mounted_in_g4((uint8_t)path[0])) {
        return (int)0x80010002u;
    }
    if (g4media_cfys_take_log_slot(0)) {
        logf_("G4_MEDIA_CFYS: Fsys_Lock('%s', mode=0x%x) -> 0", path, mode);
    }
    return 0;
}

static int g4media_c_fsys_combine(const char *dst_path, const char *src_path)
{
    if (!g4media_is_plausible_cstr(dst_path) || !g4media_is_plausible_cstr(src_path)) {
        return (int)0x80000030u;
    }
    if (dst_path[1] == ':' && !g4media_is_drive_mounted_in_g4((uint8_t)dst_path[0])) {
        return (int)0x80010002u;
    }
    logf_("G4_MEDIA_CFYS: Fsys_Combine('%s', '%s') -> 0 (compat)", dst_path, src_path);
    return 0;
}

static int g4media_c_fsys_pg_op(uint8_t drv_letter, const char *op_name)
{
    int mounted = g4media_is_drive_mounted_in_g4(drv_letter);
    int rc = mounted ? 0 : (int)0x80010002u;
    if (g4media_cfys_take_log_slot(rc != 0)) {
        logf_("G4_MEDIA_CFYS: %s(drv='%c'/0x%02x) -> rc=0x%x",
              op_name, (drv_letter >= 0x20u && drv_letter < 0x7fu) ? (int)drv_letter : '.',
              (unsigned)drv_letter, (unsigned)rc);
    }
    return rc;
}

static int g4media_c_fsys_pg_enter(uint8_t drv_letter)          { return g4media_c_fsys_pg_op(drv_letter, "Fsys_PGEnter"); }
static int g4media_c_fsys_pg_exit(uint8_t drv_letter)           { return g4media_c_fsys_pg_op(drv_letter, "Fsys_PGExit"); }
static int g4media_c_fsys_pg_start_wt(uint8_t drv_letter)       { return g4media_c_fsys_pg_op(drv_letter, "Fsys_PGStartWriteThru"); }
static int g4media_c_fsys_pg_stop_wt(uint8_t drv_letter)        { return g4media_c_fsys_pg_op(drv_letter, "Fsys_PGStopWriteThru"); }

static int g4media_wrap_mpr_init(const void *init_in_param)
{
    int rc = -1;
    if (g4media_orig_mpr_init) {
        rc = g4media_orig_mpr_init(init_in_param);
    }
    logf_("G4_MEDIA_MPR: mpr::Init(param=%p) -> rc=%d", init_in_param, rc);
    return rc;
}

static int g4media_wrap_mpr_load(const void *load_in_param)
{
    const uint8_t *p = (const uint8_t *)load_in_param;
    uint8_t drv = p ? p[0x1du] : 0u;
    uint32_t slot = p ? g4media_rd32(p + 0x20u) : 0u;
    const char *dev = p ? (const char *)(p + 0x08u) : "";
    logf_("G4_MEDIA_MPR: mpr::Load ENTER(slot=%u drv='%c'/0x%02x dev='%s')",
          slot, (drv >= 0x20u && drv < 0x7fu) ? (int)drv : '.', (unsigned)drv,
          (dev[0] >= 0x20 && dev[0] < 0x7f) ? dev : "");
    int rc = -1;
    if (g4media_orig_mpr_load) {
        rc = g4media_orig_mpr_load(load_in_param);
    }
    logf_("G4_MEDIA_MPR: mpr::Load EXIT(slot=%u) -> rc=%d", slot, rc);
    return rc;
}

static inline int g4media_take_movie_diag_slot(void)
{
    for (;;) {
        uint32_t cur = __atomic_load_n(&g4media_movie_diag_budget, __ATOMIC_RELAXED);
        if (cur == 0u) {
            return 0;
        }
        if (__sync_bool_compare_and_swap(&g4media_movie_diag_budget, cur, cur - 1u)) {
            return 1;
        }
    }
}

static inline void g4media_log_movie_rec_status(const char *tag, int extra_rc)
{
    if (!g4media_orig_mpr_get_movie_rec_status_internal) {
        return;
    }
    uint8_t st[0x90];
    memset(st, 0, sizeof(st));
    int rc = g4media_orig_mpr_get_movie_rec_status_internal(st);
    logf_("G4_MEDIA_MOV[%s]: extra=%d st_rc=%d rem0=%u inh0=0x%08x rem1=%u inh1=0x%08x b48=%u w4c=0x%08x",
          tag, extra_rc, rc,
          g4media_rd32(st + 0x10u), g4media_rd32(st + 0x50u),
          g4media_rd32(st + 0x20u), g4media_rd32(st + 0x60u),
          (unsigned)st[0x48u], g4media_rd32(st + 0x4cu));
}

static int g4media_wrap_mpr_set_issue_event(uint32_t evt_id, const void *param, uint32_t size)
{
    if (evt_id == 0x1002u && param != NULL && size >= 0x14u) {
        const uint8_t *ep = (const uint8_t *)param;
        logf_("G4_MEDIA_MPR: SetIssueEvent(0x1002 LoadFinished): r04=0x%x ev_err=0x%x slot=%u err_flag=%u rep_dcf=%u rep_m4=%u",
              g4media_rd32(ep + 0x04u), g4media_rd32(ep + 0x08u), g4media_rd32(ep + 0x0cu),
              (unsigned)ep[0x10u], (unsigned)ep[0x11u], (unsigned)ep[0x12u]);
    } else if (evt_id == 0x1004u) {
        const uint8_t *ep = (const uint8_t *)param;
        if (ep != NULL && size >= 0x10u) {
            logf_("G4_MEDIA_MOV: SetIssueEvent(0x1004): w0..3=[0x%x 0x%x 0x%x 0x%x]",
                  g4media_rd32(ep + 0x00u), g4media_rd32(ep + 0x04u),
                  g4media_rd32(ep + 0x08u), g4media_rd32(ep + 0x0cu));
        }
        g4media_log_movie_rec_status("evt1004", 0);
    } else if (g4media_cfys_take_log_slot(0)) {
        logf_("G4_MEDIA_MPR: SetIssueEvent(evt=0x%x, param=%p, size=0x%x)", evt_id, param, size);
    }
    return g4media_orig_mpr_set_issue_event ? g4media_orig_mpr_set_issue_event(evt_id, param, size) : -1;
}

/* libmp5.so @ 0x25408c mpr::pconv::GetVideoBitrate 查表 (kbps; 0=无效) */
static inline uint32_t g4media_video_bitrate_kbps(uint32_t vq)
{
    static const uint32_t k_vbitrate_kbps[54] = {
             0u,      0u,  12000u,      0u,      0u,      0u,  16000u,  21000u,
         25000u,      0u,  60000u,  90000u, 100000u, 150000u,  50000u, 240000u,
        300000u, 600000u,  35000u, 500000u, 250000u,  80000u, 200000u, 220000u,
        440000u,  25000u,   9000u,   3000u,   6000u,   2000u,   1000u,  40000u,
         20000u,  38000u,  70000u,  75000u, 125000u, 140000u, 260000u, 400000u,
        520000u,  30000u,  13000u,  42000u,  45000u,  84000u, 280000u,  89000u,
         93000u, 111000u, 185000u, 222000u, 384000u, 480000u
    };
    return (vq < (sizeof(k_vbitrate_kbps) / sizeof(k_vbitrate_kbps[0]))) ? k_vbitrate_kbps[vq] : 0u;
}

/* libmp5.so @ 0x110f54 MovieRemain::GetAudioBitrate 有效区间校验 */
static inline int g4media_is_valid_audio_param(uint32_t comb, uint32_t ch)
{
    return (comb <= 4u && ch >= 1u && ch <= 4u) ? 1 : 0;
}

static inline uint32_t g4media_sanitize_stream_fields(uint8_t *p_st, uint8_t *p_vq, uint8_t *p_fps,
                                                      uint8_t *p_ac, uint8_t *p_ach,
                                                      uint32_t def_vq, uint32_t def_fps,
                                                      uint32_t def_ac, uint32_t def_ach,
                                                      uint32_t bit_shift)
{
    uint32_t mask = 0u;
    if (p_st && g4media_rd32(p_st) >= 0xcu) {
        g4media_wr32(p_st, 1u);
        mask |= (1u << bit_shift);
    }
    if (p_vq && g4media_video_bitrate_kbps(g4media_rd32(p_vq)) == 0u) {
        g4media_wr32(p_vq, def_vq);
        mask |= (2u << bit_shift);
    }
    if (p_fps && g4media_rd32(p_fps) >= 0xcu) {
        g4media_wr32(p_fps, def_fps);
        mask |= (4u << bit_shift);
    }
    if (p_ac && p_ach) {
        uint32_t ac = g4media_rd32(p_ac);
        uint32_t ach = g4media_rd32(p_ach);
        if (!g4media_is_valid_audio_param(ac, ach)) {
            if (ac > 4u) {
                g4media_wr32(p_ac, def_ac);
                mask |= (8u << bit_shift);
            }
            if (ach < 1u || ach > 4u) {
                g4media_wr32(p_ach, def_ach);
                mask |= (16u << bit_shift);
            }
        }
    }
    return mask;
}

static inline void g4media_sanitize_movie_rec_param(uint8_t *p, size_t len, uint32_t *out_fixed_mask)
{
    uint32_t mask = 0u;
    if (p != NULL && len >= G4MEDIA_MOVIE_REC_PARAM_SIZE) {
        /* 严格按原厂字段位宽修正单卡槽属性: +0x00=relay(1B), +0x0c=simul(1B), +0x24=allow(1B), +0x28=mode(4B), +0x38=isolate(1B), +0x156=sub_en(1B) */
        if (p[0x00u] != 0u) {
            p[0x00u] = 0u;
            mask |= (1u << 16);
        }
        if (p[0x0cu] != 0u) {
            p[0x0cu] = 0u;
            mask |= (1u << 17);
        }
        if (p[0x24u] != 1u) {
            p[0x24u] = 1u;
            mask |= (1u << 18);
        }
        if (g4media_rd32(p + 0x28u) != 0u) {
            g4media_wr32(p + 0x28u, 0u);
            mask |= (1u << 19);
        }
        if (p[0x38u] != 0u) {
            p[0x38u] = 0u;
            mask |= (1u << 20);
        }
        mask |= g4media_sanitize_stream_fields(
            p + 0x128u, p + 0x12cu, p + 0x130u, p + 0x13cu, p + 0x140u,
            G4MEDIA_DEF_MAIN_VQUALITY, 0u, 0u, 2u, 0u);
        if (p[0x156u] != 0u) {
            mask |= g4media_sanitize_stream_fields(
                p + 0x158u, p + 0x15cu, p + 0x160u, p + 0x16cu, p + 0x170u,
                G4MEDIA_DEF_SUB_VQUALITY, 6u, 3u, 1u, 5u);
            p[0x156u] = 0u; /* 严格 1 字节写清，绝不踩踏 +0x158 */
            mask |= (1u << 21);
        }
    }
    if (out_fixed_mask) {
        *out_fixed_mask = mask;
    }
}

static inline void g4media_sanitize_movie_remain_in(uint8_t *p, size_t len, uint32_t *out_fixed_mask)
{
    uint32_t mask = 0u;
    if (p != NULL && len >= G4MEDIA_MOVIE_REMAIN_IN_SIZE) {
        mask |= g4media_sanitize_stream_fields(
            p + 0x0cu, p + 0x14u, p + 0x10u, p + 0x18u, p + 0x1cu,
            G4MEDIA_DEF_MAIN_VQUALITY, 0u, 0u, 2u, 0u);
        if (p[0x20u] != 0u) {
            mask |= g4media_sanitize_stream_fields(
                p + 0x28u, p + 0x30u, p + 0x2cu, p + 0x34u, p + 0x38u,
                G4MEDIA_DEF_SUB_VQUALITY, 6u, 3u, 1u, 5u);
            p[0x20u] = 0u; /* 单卡机关闭双路同时录子流，避免 CalcRecordableTime 因 sub 返回 3 */
            mask |= (1u << 21);
        }
    }
    if (out_fixed_mask) {
        *out_fixed_mask = mask;
    }
}

static int g4media_wrap_mpr_get_movie_remain(const void *in_param, void *out_param)
{
    uint8_t fixed_in[G4MEDIA_MOVIE_REMAIN_IN_SIZE];
    const void *call_in = in_param;
    uint32_t fixed_mask = 0u;
    if (in_param != NULL) {
        memcpy(fixed_in, in_param, sizeof(fixed_in));
        g4media_sanitize_movie_remain_in(fixed_in, sizeof(fixed_in), &fixed_mask);
        if (fixed_mask != 0u) {
            call_in = fixed_in;
        }
    }
    int rc = g4media_orig_mpr_get_movie_remain ? g4media_orig_mpr_get_movie_remain(call_in, out_param) : -1;
    if (g4media_take_movie_diag_slot() || fixed_mask != 0u || (out_param && g4media_rd32((const uint8_t *)out_param + 0x04u) == 0u && rc != 0)) {
        const uint8_t *ip = (const uint8_t *)call_in;
        const uint8_t *op = (const uint8_t *)out_param;
        logf_("G4_MEDIA_MOV: GetMovieRemain(in0=%u in4=%u in8=%u vq=0x%x sim=%u sub_vq=0x%x fixed=0x%x) -> rc=%d out=[st=0x%x rem=%u w8=0x%x wc=0x%x w10=0x%x w14=0x%x]",
              ip ? g4media_rd32(ip + 0x00u) : 0u,
              ip ? g4media_rd32(ip + 0x04u) : 0u,
              ip ? g4media_rd32(ip + 0x08u) : 0u,
              ip ? g4media_rd32(ip + 0x14u) : 0u,
              ip ? (unsigned)ip[0x20u] : 0u,
              ip ? g4media_rd32(ip + 0x30u) : 0u,
              fixed_mask, rc,
              op ? g4media_rd32(op + 0x00u) : 0u,
              op ? g4media_rd32(op + 0x04u) : 0u,
              op ? g4media_rd32(op + 0x08u) : 0u,
              op ? g4media_rd32(op + 0x0cu) : 0u,
              op ? g4media_rd32(op + 0x10u) : 0u,
              op ? g4media_rd32(op + 0x14u) : 0u);
    }
    return rc;
}

static int g4media_wrap_mpr_set_movie_rec_param(const void *param)
{
    uint8_t fixed[G4MEDIA_MOVIE_REC_PARAM_SIZE];
    const void *call_param = param;
    uint32_t fixed_mask = 0u;
    uint32_t raw_relay = 0u, raw_iso = 0u, raw_allow = 0u, raw_sim = 0u, raw_sub156 = 0u;
    uint32_t raw_mvq = 0u, raw_mac = 0u, raw_mach = 0u, raw_svq = 0u;
    if (param != NULL) {
        memcpy(fixed, param, sizeof(fixed));
        raw_relay  = (uint32_t)fixed[0x00u];
        raw_sim    = (uint32_t)fixed[0x0cu];
        raw_allow  = (uint32_t)fixed[0x24u];
        raw_iso    = (uint32_t)fixed[0x38u];
        raw_sub156 = (uint32_t)fixed[0x156u];
        raw_mvq    = g4media_rd32(fixed + 0x12cu);
        raw_mac    = g4media_rd32(fixed + 0x13cu);
        raw_mach   = g4media_rd32(fixed + 0x140u);
        raw_svq    = g4media_rd32(fixed + 0x15cu);
        g4media_sanitize_movie_rec_param(fixed, sizeof(fixed), &fixed_mask);
        if (fixed_mask != 0u) {
            call_param = fixed;
        }
    }
    int rc = g4media_orig_mpr_set_movie_rec_param ? g4media_orig_mpr_set_movie_rec_param(call_param) : -1;
    if (g4media_take_movie_diag_slot() || fixed_mask != 0u) {
        const uint8_t *p = (const uint8_t *)call_param;
        logf_("G4_MEDIA_MOV: SetMovieRecParam(slot=0x%x raw=[relay=%u iso=%u allow=%u sim=%u sub156=%u vq=0x%x ac=%u ach=%u svq=0x%x] fix=[relay=%u iso=%u allow=%u sim=%u w28=%u sub156=%u st=%u vq=0x%x fps=%u ac=%u ach=%u] mask=0x%x) -> rc=%d",
              p ? g4media_rd32(p + 0x04u) : 0u,
              raw_relay, raw_iso, raw_allow, raw_sim, raw_sub156, raw_mvq, raw_mac, raw_mach, raw_svq,
              p ? (unsigned)p[0x00u] : 0u, p ? (unsigned)p[0x38u] : 0u,
              p ? (unsigned)p[0x24u] : 0u, p ? (unsigned)p[0x0cu] : 0u,
              p ? g4media_rd32(p + 0x28u) : 0u, p ? (unsigned)p[0x156u] : 0u,
              p ? g4media_rd32(p + 0x128u) : 0u, p ? g4media_rd32(p + 0x12cu) : 0u,
              p ? g4media_rd32(p + 0x130u) : 0u, p ? g4media_rd32(p + 0x13cu) : 0u,
              p ? g4media_rd32(p + 0x140u) : 0u,
              fixed_mask, rc);
        g4media_log_movie_rec_status("SetMovieRecParam", rc);
    }
    return rc;
}

static int g4media_wrap_mpr_get_movie_rec_param(void *out_param)
{
    int rc = g4media_orig_mpr_get_movie_rec_param ? g4media_orig_mpr_get_movie_rec_param(out_param) : -1;
    if (rc == 0 && out_param != NULL) {
        uint32_t fixed_mask = 0u;
        uint8_t *p = (uint8_t *)out_param;
        g4media_sanitize_movie_rec_param(p, G4MEDIA_MOVIE_REC_PARAM_SIZE, &fixed_mask);
        if (fixed_mask != 0u && g4media_take_movie_diag_slot()) {
            logf_("G4_MEDIA_MOV: GetMovieRecParam sanitized(mask=0x%x relay=%u iso=%u allow=%u sim=%u sub156=%u vq=0x%x ac=%u ach=%u)",
                  fixed_mask, (unsigned)p[0x00u], (unsigned)p[0x38u], (unsigned)p[0x24u],
                  (unsigned)p[0x0cu], (unsigned)p[0x156u],
                  g4media_rd32(p + 0x12cu), g4media_rd32(p + 0x13cu), g4media_rd32(p + 0x140u));
        }
    }
    return rc;
}

static int g4media_wrap_mpr_set_playback_param(const void *param)
{
    int rc = g4media_orig_mpr_set_playback_param ? g4media_orig_mpr_set_playback_param(param) : -1;
    const uint8_t *p = (const uint8_t *)param;
    logf_("G4_MEDIA_PB: SetPlaybackParam(p0..3=[0x%x 0x%x 0x%x 0x%x]) -> rc=%d",
          p ? g4media_rd32(p + 0x00u) : 0u, p ? g4media_rd32(p + 0x04u) : 0u,
          p ? g4media_rd32(p + 0x08u) : 0u, p ? g4media_rd32(p + 0x0cu) : 0u, rc);
    return rc;
}

static int g4media_hook_calc_movie_remain(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3)
{
    int rc = g4media_orig_calc_movie_remain ? g4media_orig_calc_movie_remain(a0, a1, a2, a3) : -1;
    if (g4media_take_movie_diag_slot() || rc != 0) {
        g4media_log_movie_rec_status("CalcMovieRemain", rc);
    }
    return rc;
}

static int g4media_hook_calc_recordable_time(g4media_mov_remain_in_val_t in_val, uint32_t *out_rem)
{
    int rc = g4media_orig_calc_recordable_time ? g4media_orig_calc_recordable_time(in_val, out_rem) : -1;
    if (g4media_take_movie_diag_slot() || rc != 0) {
        const uint8_t *ip = (const uint8_t *)in_val.w;
        logf_("G4_MEDIA_MOV[CalcRecordableTime]: rc=%d out_rem=%u vq=0x%x ac=%u ach=%u sim=%u",
              rc, out_rem ? *out_rem : 0u,
              g4media_rd32(ip + 0x14u), g4media_rd32(ip + 0x18u), g4media_rd32(ip + 0x1cu),
              (unsigned)ip[0x20u]);
    }
    return rc;
}

static int g4media_hook_rate_check(uint32_t drv_char, g4media_movie_rec_val_t rec_val,
                                   uint8_t *out_flag, uint32_t *out_inh)
{
    int rc = g4media_orig_rate_check ? g4media_orig_rate_check(drv_char, rec_val, out_flag, out_inh) : -1;
    if (g4media_take_movie_diag_slot() || rc != 0 || (out_inh && (*out_inh & 0x400u) != 0u)) {
        const uint8_t *rp = (const uint8_t *)rec_val.q;
        uint8_t ch = (uint8_t)(drv_char & 0xffu);
        logf_("G4_MEDIA_MOV[RateCheck]: drv='%c'(0x%02x) rc=%d flag=%u out_inh=0x%08x relay=%u iso=%u allow=%u sim=%u sub156=%u",
              (ch >= 0x20u && ch < 0x7fu) ? (int)ch : '.', (unsigned)ch,
              rc, out_flag ? (unsigned)*out_flag : 0u, out_inh ? *out_inh : 0u,
              (unsigned)rp[0x00u], (unsigned)rp[0x38u], (unsigned)rp[0x24u],
              (unsigned)rp[0x0cu], (unsigned)rp[0x156u]);
    }
    return rc;
}

static int g4media_hook_sidb_get_remain(uint32_t slot_id, uint32_t content_type, uint32_t *out_remain)
{
    int rc = g4media_orig_sidb_get_remain ? g4media_orig_sidb_get_remain(slot_id, content_type, out_remain) : -1;
    if (g4media_take_movie_diag_slot() || rc != 0) {
        logf_("G4_MEDIA_SIDB: sidb::GetRemain(slot=%u type=%u) -> rc=0x%x remain=%u",
              slot_id, content_type, (unsigned)rc, out_remain ? *out_remain : 0u);
    }
    return rc;
}

static inline void g4media_apply_got_slot(uintptr_t mod_base, uintptr_t got_off, void *new_fn, const char *label)
{
    if (!mod_base || !new_fn) {
        return;
    }
    if (g4media_custom_got_hook_cb) {
        g4media_custom_got_hook_cb(mod_base, got_off, new_fn, label);
        return;
    }
    uintptr_t slot = mod_base + got_off;
    uintptr_t page = slot & ~(uintptr_t)4095u;
    if (mprotect((void *)page, 4096u, PROT_READ | PROT_WRITE) != 0) {
        logf_("G4_MEDIA_WARN: mprotect GOT %s (0x%lx) 失败 errno=%d", label, (unsigned long)slot, errno);
        return;
    }
    *(void **)slot = new_fn;
}

typedef struct {
    uintptr_t   got_off;
    void       *hook_fn;
    const char *label;
} g4media_got_entry_t;

static inline void g4media_install_got_table(uintptr_t mod_base, const g4media_got_entry_t *tbl, size_t count)
{
    if (!mod_base || !tbl) {
        return;
    }
    for (size_t i = 0u; i < count; i++) {
        g4media_apply_got_slot(mod_base, tbl[i].got_off, tbl[i].hook_fn, tbl[i].label);
    }
}

static inline uint8_t *g4media_get_dcf_slots_base(void)
{
    if (!g4media_mp5_base) {
        return NULL;
    }
    uintptr_t table_ptr = *(const volatile uintptr_t *)(g4media_mp5_base + 0x002877a0u);
    if (!table_ptr) {
        table_ptr = g4media_mp5_base + 0x00b09280u;
    }
    return (uint8_t *)table_ptr;
}

static void *g4media_hook_dmm_alloc_core(uint32_t unit_type, uint32_t a1, uint32_t cmd, uint32_t a3,
                                         void *out_unit, uint32_t flag, void *p_munmap)
{
    void *orig_rc = g4media_orig_dmm_alloc_core
        ? g4media_orig_dmm_alloc_core(unit_type, a1, cmd, a3, out_unit, flag, p_munmap)
        : NULL;
    if (orig_rc != NULL) {
        return orig_rc;
    }

    if (cmd == 1u && unit_type == G4MEDIA_DMM_DCF_UNIT_TYPE && out_unit != NULL) {
        void *buf = mmap(NULL, G4MEDIA_DMM_DCF_MMAP_SIZE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buf == MAP_FAILED) {
            logf_("G4_MEDIA_DMM_ERR: fallback mmap(0x%x) 失败 errno=%d",
                  (unsigned)G4MEDIA_DMM_DCF_MMAP_SIZE, errno);
            return NULL;
        }

        uint16_t handle = 0u;
        while (__sync_lock_test_and_set(&g4media_dmm_lock, 1u)) {}
        for (size_t i = 0u; i < G4MEDIA_DMM_MAX_SLOTS; i++) {
            if (!g4media_dmm_slots[i].in_use) {
                handle = (uint16_t)(G4MEDIA_DMM_HANDLE_BASE + i);
                g4media_dmm_slots[i].addr      = buf;
                g4media_dmm_slots[i].size      = G4MEDIA_DMM_DCF_MMAP_SIZE;
                g4media_dmm_slots[i].handle    = handle;
                g4media_dmm_slots[i].unit_type = unit_type;
                g4media_dmm_slots[i].in_use    = 1u;
                break;
            }
        }
        __sync_lock_release(&g4media_dmm_lock);

        if (handle == 0u) {
            munmap(buf, G4MEDIA_DMM_DCF_MMAP_SIZE);
            logf_("G4_MEDIA_DMM_ERR: 合成句柄表已满 (max=%u)，回退分配失败", (unsigned)G4MEDIA_DMM_MAX_SLOTS);
            return NULL;
        }

        uint8_t *uo = (uint8_t *)out_unit;
        memset(uo, 0, 0x60u);
        g4media_wr16(uo + 0x04u, handle);
        g4media_wr32(uo + 0x0cu, unit_type);
        g4media_wr32(uo + 0x10u, G4MEDIA_DMM_DCF_SIZE);
        g4media_wr32(uo + 0x14u, (uint32_t)(uintptr_t)buf);
        g4media_wr32(uo + 0x50u, (uint32_t)(uintptr_t)buf);

        logf_("G4_MEDIA_DMM: fallback mmap for unit_type=0x%x -> handle=0x%04x buf=%p size=0x%x",
              unit_type, (unsigned)handle, buf, (unsigned)G4MEDIA_DMM_DCF_MMAP_SIZE);
        return buf;
    }

    if (cmd == 1u && g4media_cfys_take_log_slot(0)) {
        logf_("G4_MEDIA_DMM_WARN: dmm_alloc_core(unit_type=0x%x, cmd=%u, out=%p) -> NULL",
              unit_type, cmd, out_unit);
    }
    return NULL;
}

static int g4media_hook_dmm_close_and_free(uint32_t unit_handle)
{
    uint16_t h = (uint16_t)(unit_handle & 0xffffu);
    if (h >= G4MEDIA_DMM_HANDLE_BASE && h < G4MEDIA_DMM_HANDLE_BASE + G4MEDIA_DMM_MAX_SLOTS) {
        size_t idx = (size_t)(h - G4MEDIA_DMM_HANDLE_BASE);
        void *addr = NULL;
        size_t sz  = 0u;
        uint32_t utype = 0u;
        while (__sync_lock_test_and_set(&g4media_dmm_lock, 1u)) {}
        if (g4media_dmm_slots[idx].in_use && g4media_dmm_slots[idx].handle == h) {
            addr  = g4media_dmm_slots[idx].addr;
            sz    = g4media_dmm_slots[idx].size;
            utype = g4media_dmm_slots[idx].unit_type;
            g4media_dmm_slots[idx].in_use    = 0u;
            g4media_dmm_slots[idx].addr      = NULL;
            g4media_dmm_slots[idx].size      = 0u;
            g4media_dmm_slots[idx].handle    = 0u;
            g4media_dmm_slots[idx].unit_type = 0u;
        }
        __sync_lock_release(&g4media_dmm_lock);

        if (addr != NULL && sz > 0u) {
            munmap(addr, sz);
            logf_("G4_MEDIA_DMM: close_and_free handle=0x%04x unit_type=0x%x -> munmap(%p, 0x%x)",
                  (unsigned)h, utype, addr, (unsigned)sz);
            return 0;
        }
    }
    return g4media_orig_dmm_close_and_free ? g4media_orig_dmm_close_and_free(unit_handle) : 0;
}

static int g4media_hook_dcf_load(uint32_t slot_idx, uint32_t enable, const void *dir_str, uint32_t r3, uint32_t sp0)
{
    int rc = g4media_orig_dcf_load ? g4media_orig_dcf_load(slot_idx, enable, dir_str, r3, sp0) : -1;
    uint8_t *slots = g4media_get_dcf_slots_base();
    if (slots != NULL && slot_idx < G4MEDIA_DCF_SLOT_COUNT) {
        const uint8_t *s = slots + (size_t)slot_idx * G4MEDIA_DCF_SLOT_STRIDE;
        logf_("G4_MEDIA_DCF: DcfNamer::Load(slot=%u en=%u) -> rc=%d loaded=%u handle=0x%04x virt=0x%08x files=0x%08x folders=%u",
              slot_idx, enable, rc, (unsigned)s[0], (unsigned)g4media_rd16(s + 0x0cu),
              g4media_rd32(s + 0x58u), g4media_rd32(s + 0x6cu), (unsigned)g4media_rd16(s + 0x74u));
    } else {
        logf_("G4_MEDIA_DCF: DcfNamer::Load(slot=%u en=%u) -> rc=%d", slot_idx, enable, rc);
    }
    return rc;
}

static uint32_t g4media_hook_dcf_remain_folders(const void *slot_mask_arr, uint32_t mode, void *out_arr)
{
    uint8_t *slots = g4media_get_dcf_slots_base();
    if (slots != NULL) {
        for (uint32_t i = 0u; i < G4MEDIA_DCF_SLOT_COUNT; i++) {
            uint8_t *s = slots + (size_t)i * G4MEDIA_DCF_SLOT_STRIDE;
            if (s[0] != 0u && g4media_rd32(s + 0x6cu) == 0u) {
                logf_("G4_MEDIA_DCF_WARN: slot=%u loaded_flag=%u 但 files_ptr=NULL，清除失效标志防崩",
                      i, (unsigned)s[0]);
                s[0] = 0u;
            }
        }
    }
    return g4media_orig_dcf_remain_folders ? g4media_orig_dcf_remain_folders(slot_mask_arr, mode, out_arr) : 0u;
}

/**
 * @brief 为 appFw.so / libmp5.so / libOb5.so 统一挂载 C-API Fsys_* GOT 适配、mpr 探针与 DMM/DCF 修复
 */
static inline void g4media_install_c_fsys_got_hooks(uintptr_t app_base, uintptr_t mp5_base, uintptr_t ob5_base)
{
    g4media_mp5_base = mp5_base;
    static const g4media_got_entry_t mp5_missing6_tbl[] = {
        { 0x002830f8u, (void *)g4media_c_fsys_lock,        "libmp5.so GOT[Fsys_Lock]" },
        { 0x00285c40u, (void *)g4media_c_fsys_combine,     "libmp5.so GOT[Fsys_Combine]" },
        { 0x00284c98u, (void *)g4media_c_fsys_pg_enter,    "libmp5.so GOT[Fsys_PGEnter]" },
        { 0x00282d9cu, (void *)g4media_c_fsys_pg_exit,     "libmp5.so GOT[Fsys_PGExit]" },
        { 0x00285c60u, (void *)g4media_c_fsys_pg_start_wt, "libmp5.so GOT[Fsys_PGStartWriteThru]" },
        { 0x002831c0u, (void *)g4media_c_fsys_pg_stop_wt,  "libmp5.so GOT[Fsys_PGStopWriteThru]" },
    };

    static const g4media_got_entry_t mp5_fsys_tbl[] = {
        { 0x00283eb8u, (void *)g4media_c_fsys_get_drive_info,  "libmp5.so GOT[Fsys_GetDriveInfo]" },
        { 0x002847a0u, (void *)g4media_c_fsys_get_free_space,  "libmp5.so GOT[Fsys_GetFreeSpace]" },
        { 0x002850bcu, (void *)g4media_c_fsys_mount,           "libmp5.so GOT[Fsys_Mount]" },
        { 0x00283978u, (void *)g4media_c_fsys_unmount,         "libmp5.so GOT[Fsys_Unmount]" },
        { 0x0028491cu, (void *)g4media_c_fsys_find_first,      "libmp5.so GOT[Fsys_FindFirst]" },
        { 0x00285704u, (void *)g4media_c_fsys_find_next,       "libmp5.so GOT[Fsys_FindNext]" },
        { 0x002830f4u, (void *)g4media_c_fsys_stat,            "libmp5.so GOT[Fsys_Stat]" },
        { 0x00283898u, (void *)g4media_c_fsys_open,            "libmp5.so GOT[Fsys_Open]" },
        { 0x00284210u, (void *)g4media_c_fsys_close,           "libmp5.so GOT[Fsys_Close]" },
        { 0x00286188u, (void *)g4media_c_fsys_mkdir,           "libmp5.so GOT[Fsys_Mkdir]" },
        { 0x002834ccu, (void *)g4media_c_fsys_remove,          "libmp5.so GOT[Fsys_Remove]" },
        { 0x00284e8cu, (void *)g4media_c_fsys_chmod,           "libmp5.so GOT[Fsys_Chmod]" },
        { 0x0028471cu, (void *)g4media_c_fsys_read,            "libmp5.so GOT[Fsys_Read]" },
        { 0x002831acu, (void *)g4media_c_fsys_write,           "libmp5.so GOT[Fsys_Write]" },
        { 0x00283084u, (void *)g4media_c_fsys_write_and_flush, "libmp5.so GOT[Fsys_WriteAndFlush]" },
    };

    static const g4media_got_entry_t ob5_fsys_tbl[] = {
        { 0x003551ccu, (void *)g4media_c_fsys_get_drive_info, "libOb5.so GOT[Fsys_GetDriveInfo]" },
        { 0x003553f8u, (void *)g4media_c_fsys_get_free_space, "libOb5.so GOT[Fsys_GetFreeSpace]" },
        { 0x003555b4u, (void *)g4media_c_fsys_mount,          "libOb5.so GOT[Fsys_Mount]" },
        { 0x00355078u, (void *)g4media_c_fsys_unmount,        "libOb5.so GOT[Fsys_Unmount]" },
        { 0x00355440u, (void *)g4media_c_fsys_find_first,     "libOb5.so GOT[Fsys_FindFirst]" },
        { 0x003556d4u, (void *)g4media_c_fsys_find_next,      "libOb5.so GOT[Fsys_FindNext]" },
        { 0x00354eccu, (void *)g4media_c_fsys_stat,           "libOb5.so GOT[Fsys_Stat]" },
        { 0x00355050u, (void *)g4media_c_fsys_open,           "libOb5.so GOT[Fsys_Open]" },
        { 0x00355298u, (void *)g4media_c_fsys_close,          "libOb5.so GOT[Fsys_Close]" },
        { 0x00355908u, (void *)g4media_c_fsys_mkdir,          "libOb5.so GOT[Fsys_Mkdir]" },
        { 0x00354fa0u, (void *)g4media_c_fsys_remove,         "libOb5.so GOT[Fsys_Remove]" },
    };

    static const g4media_got_entry_t app_fsys_tbl[] = {
        { 0x0377b338u, (void *)g4media_c_fsys_get_drive_info,  "appFw.so GOT[Fsys_GetDriveInfo]" },
        { 0x0377acf0u, (void *)g4media_c_fsys_get_device_info, "appFw.so GOT[Fsys_GetDeviceInfo]" },
        { 0x0377b424u, (void *)g4media_c_fsys_get_free_space,  "appFw.so GOT[Fsys_GetFreeSpace]" },
        { 0x0377b4c0u, (void *)g4media_c_fsys_mount,           "appFw.so GOT[Fsys_Mount]" },
        { 0x0377af88u, (void *)g4media_c_fsys_unmount,         "appFw.so GOT[Fsys_Unmount]" },
        { 0x0377ac74u, (void *)g4media_c_fsys_find_first,      "appFw.so GOT[Fsys_FindFirst]" },
        { 0x0377b4d4u, (void *)g4media_c_fsys_find_next,       "appFw.so GOT[Fsys_FindNext]" },
        { 0x0377add8u, (void *)g4media_c_fsys_open,            "appFw.so GOT[Fsys_Open]" },
        { 0x0377b548u, (void *)g4media_c_fsys_close,           "appFw.so GOT[Fsys_Close]" },
        { 0x0377b2b0u, (void *)g4media_c_fsys_mkdir,           "appFw.so GOT[Fsys_Mkdir]" },
        { 0x0377ace8u, (void *)g4media_c_fsys_remove,          "appFw.so GOT[Fsys_Remove]" },
    };

    if (mp5_base) {
        g4media_install_got_table(mp5_base, mp5_missing6_tbl,
                                  sizeof(mp5_missing6_tbl) / sizeof(mp5_missing6_tbl[0]));
    }

    const g4media_fsys_api_t *api = g4media_resolve_g4_fsys();
    if (api->available || g4media_custom_got_hook_cb != NULL) {
        g4media_install_got_table(mp5_base, mp5_fsys_tbl,
                                  sizeof(mp5_fsys_tbl) / sizeof(mp5_fsys_tbl[0]));
        g4media_install_got_table(ob5_base, ob5_fsys_tbl,
                                  sizeof(ob5_fsys_tbl) / sizeof(ob5_fsys_tbl[0]));
        g4media_install_got_table(app_base, app_fsys_tbl,
                                  sizeof(app_fsys_tbl) / sizeof(app_fsys_tbl[0]));
    }

    /* 安装 mpr::Init / mpr::Load 诊断包装，确认 appFw -> libmp5 调用与返回路径 */
    if (app_base && mp5_base) {
        if (!g4media_orig_mpr_init) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr4InitERKNS_11initInParamE");
            g4media_orig_mpr_init = sym ? (g4media_mpr_init_fn_t)sym
                                        : (g4media_mpr_init_fn_t)(mp5_base + 0x000c1dbdu);
        }
        if (!g4media_orig_mpr_load) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr4LoadERKNS_11loadInParamE");
            g4media_orig_mpr_load = sym ? (g4media_mpr_load_fn_t)sym
                                        : (g4media_mpr_load_fn_t)(mp5_base + 0x000c71b9u);
        }
        if (!g4media_orig_mpr_get_movie_remain) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr14GetMovieRemainERKNS_21getMovieRemainInParamEPNS_22getMovieRemainOutParamE");
            g4media_orig_mpr_get_movie_remain = sym ? (g4media_mpr_get_movie_remain_fn_t)sym
                                                    : (g4media_mpr_get_movie_remain_fn_t)(mp5_base + 0x000dcb61u);
        }
        if (!g4media_orig_mpr_set_movie_rec_param) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr16SetMovieRecParamERKNS_13movieRecParamE");
            g4media_orig_mpr_set_movie_rec_param = sym ? (g4media_mpr_set_movie_rec_param_fn_t)sym
                                                       : (g4media_mpr_set_movie_rec_param_fn_t)(mp5_base + 0x000eb111u);
        }
        if (!g4media_orig_mpr_set_playback_param) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr16SetPlaybackParamERKNS_13playbackParamE");
            g4media_orig_mpr_set_playback_param = sym ? (g4media_mpr_set_playback_param_fn_t)sym
                                                      : (g4media_mpr_set_playback_param_fn_t)(mp5_base + 0x000eb0a9u);
        }
        if (!g4media_orig_mpr_get_movie_rec_status_internal) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr25GetMovieRecStatusInternalEPNS_25getMovieRecStatusOutParamE");
            g4media_orig_mpr_get_movie_rec_status_internal = sym ? (g4media_mpr_get_movie_rec_status_internal_fn_t)sym
                                                                 : (g4media_mpr_get_movie_rec_status_internal_fn_t)(mp5_base + 0x000eb791u);
        }
        g4media_apply_got_slot(app_base, 0x0377b15cu, (void *)g4media_wrap_mpr_init, "appFw.so GOT[mpr::Init]");
        g4media_apply_got_slot(app_base, 0x0377b428u, (void *)g4media_wrap_mpr_load, "appFw.so GOT[mpr::Load]");
        g4media_apply_got_slot(app_base, 0x0377b63cu, (void *)g4media_wrap_mpr_get_movie_remain, "appFw.so GOT[mpr::GetMovieRemain]");
        g4media_apply_got_slot(app_base, 0x0377b654u, (void *)g4media_wrap_mpr_set_movie_rec_param, "appFw.so GOT[mpr::SetMovieRecParam]");
        g4media_apply_got_slot(app_base, 0x0377b0ccu, (void *)g4media_wrap_mpr_set_playback_param, "appFw.so GOT[mpr::SetPlaybackParam]");
    }
    if (mp5_base) {
        if (!g4media_orig_mpr_set_issue_event) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr13SetIssueEventENS_5EVTIDEPvj");
            g4media_orig_mpr_set_issue_event = sym ? (g4media_mpr_set_issue_event_fn_t)sym
                                                   : (g4media_mpr_set_issue_event_fn_t)(mp5_base + 0x000c05e1u);
        }
        if (!g4media_orig_mpr_get_movie_rec_param) {
            void *sym = dlsym(RTLD_DEFAULT, "_ZN3mpr16GetMovieRecParamEPNS_13movieRecParamE");
            g4media_orig_mpr_get_movie_rec_param = sym ? (g4media_mpr_get_movie_rec_param_fn_t)sym
                                                       : (g4media_mpr_get_movie_rec_param_fn_t)(mp5_base + 0x000ea501u);
        }
        g4media_apply_got_slot(mp5_base, 0x002845dcu, (void *)g4media_wrap_mpr_set_issue_event, "libmp5.so GOT[mpr::SetIssueEvent]");
        g4media_apply_got_slot(mp5_base, 0x00286128u, (void *)g4media_wrap_mpr_get_movie_rec_param, "libmp5.so GOT[mpr::GetMovieRecParam]");
    }

    if (mp5_base && g4media_custom_got_hook_cb == NULL) {
        static const uint8_t sig_dmm_alloc_core[8]     = {0x2du, 0xe9u, 0xf0u, 0x4fu, 0x9bu, 0xb0u, 0x00u, 0xafu};
        static const uint8_t sig_dmm_close_and_free[8] = {0x80u, 0xb5u, 0x04u, 0x21u, 0x00u, 0xafu, 0x02u, 0x22u};
        static const uint8_t sig_dcf_load[8]           = {0x2du, 0xe9u, 0xf0u, 0x4fu, 0x8bu, 0xb0u, 0x00u, 0xafu};
        static const uint8_t sig_dcf_remain[8]         = {0x2du, 0xe9u, 0xf0u, 0x4fu, 0x99u, 0xb0u, 0x00u, 0xafu};
        static const uint8_t sig_calc_movie_remain[8]  = {0x2du, 0xe9u, 0xf0u, 0x4fu, 0xadu, 0xf5u, 0x9cu, 0x6du};
        static const uint8_t sig_sidb_get_remain[8]     = {0x2du, 0xe9u, 0xf0u, 0x4fu, 0x87u, 0xb0u, 0x00u, 0xafu};
        static const uint8_t sig_calc_record_time[8]    = {0x84u, 0xb0u, 0x2du, 0xe9u, 0xf0u, 0x4fu, 0x9fu, 0xb0u};
        static const uint8_t sig_rate_check[8]          = {0x82u, 0xb0u, 0xf0u, 0xb5u, 0xadu, 0xf5u, 0x09u, 0x7du};

        g4media_orig_dmm_alloc_core = (g4media_dmm_alloc_core_fn_t)g4media_install_tramp8(
            mp5_base + 0x002371b8u, sig_dmm_alloc_core, (void *)g4media_hook_dmm_alloc_core, "libmp5:dmm_alloc_core");
        g4media_orig_dmm_close_and_free = (g4media_dmm_close_and_free_fn_t)g4media_install_tramp8(
            mp5_base + 0x00237770u, sig_dmm_close_and_free, (void *)g4media_hook_dmm_close_and_free, "libmp5:dmm_close_and_free");
        g4media_orig_dcf_load = (g4media_dcf_load_fn_t)g4media_install_tramp8(
            mp5_base + 0x0010c11cu, sig_dcf_load, (void *)g4media_hook_dcf_load, "libmp5:DcfNamer_Load");
        g4media_orig_dcf_remain_folders = (g4media_dcf_remain_folders_fn_t)g4media_install_tramp8(
            mp5_base + 0x0010da50u, sig_dcf_remain, (void *)g4media_hook_dcf_remain_folders, "libmp5:DcfNamer_GetRemainSlotFolders");
        g4media_orig_calc_movie_remain = (g4media_calc_movie_remain_fn_t)g4media_install_tramp8(
            mp5_base + 0x001129b8u, sig_calc_movie_remain, (void *)g4media_hook_calc_movie_remain, "libmp5:CalcMovieRemain");
        g4media_orig_sidb_get_remain = (g4media_sidb_get_remain_fn_t)g4media_install_tramp8(
            mp5_base + 0x002177bcu, sig_sidb_get_remain, (void *)g4media_hook_sidb_get_remain, "libmp5:sidb_GetRemain");
        g4media_orig_calc_recordable_time = (g4media_calc_recordable_time_fn_t)g4media_install_tramp8(
            mp5_base + 0x00111018u, sig_calc_record_time, (void *)g4media_hook_calc_recordable_time, "libmp5:CalcRecordableTime");
        g4media_orig_rate_check = (g4media_rate_check_fn_t)g4media_install_tramp8(
            mp5_base + 0x000f49fcu, sig_rate_check, (void *)g4media_hook_rate_check, "libmp5:RateCheck_GetMediaTransferRateInh");
    }

    logf_("G4_MEDIA: v34 C-API Fsys_* GOT、DMM 0x660/DcfNamer 与 MovieRecParam 规范化桥接装载完成 (app=%p mp5=%p ob5=%p g4_avail=%d)",
          (void *)app_base, (void *)mp5_base, (void *)ob5_base, api->available);
}

#ifdef __cplusplus
}
#endif

#endif /* G4HOST_BRIDGE_MEDIA_H */
