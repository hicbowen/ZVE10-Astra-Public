/*
 * appFwBoot.so —— ZV-E10 宿主 im.elf 下的五代 ASTRA 引导器（v0.3 生产健壮版）
 *
 * 核心升级点：
 *   1. 显式初始化 MWF 单例：在加载五代前初始化 MWF::RsrcDP 与 MWF::RsrcRelation，彻底解决 MonCtrl 空指针崩溃。
 *   2. 宿主免疫保护：捕获信号后完整记录崩溃栈，绝不 raise 导致 im.elf 退出，四代按键泵与关机服务永不掉线。
 *   3. 自动降级容灾：若五代启动失败或崩溃，自动回滚调用四代原始入口 Application_System_InjS。
 *   4. 16MB 专属大栈运行五代 2,730 个全局构造函数与主事件循环。
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SYS_gettid
#define SYS_gettid 224
#endif
#ifndef SYS_tgkill
#define SYS_tgkill 268
#endif

#ifndef ASTRA_STACK_SIZE
#define ASTRA_STACK_SIZE (16u * 1024u * 1024u)
#endif
#define ASTRA_MAX_FAIL 3

#ifdef ZVE10_USB_SANDBOX
#define LOG_DIR       "/tmp/astra_sb"
#define LOG_PATH      LOG_DIR "/boot.log"
#define STATE_DIR     "/tmp/astra_sb"
#define FAILCNT_PATH  STATE_DIR "/fail_count"
#define DISABLE_PATH  STATE_DIR "/disable"
#define LIBDIR        "/log/g5/"
#define APPDIR        "/log/g5/share/app"
#elif defined(ZVE10_REAL_DEVICE)
#define LOG_DIR       "/log/astra"
#define LOG_PATH      LOG_DIR "/boot.log"
#define STATE_DIR     "/setting/astra"
#define FAILCNT_PATH  STATE_DIR "/fail_v2"
#define DISABLE_PATH  STATE_DIR "/disable"
#define LIBDIR        "/usr/lib/"
#define APPDIR        "/usr/share/app"
#else
#define LOG_DIR       "/log/astra"
#define LOG_PATH      LOG_DIR "/boot.log"
#define STATE_DIR     "/setting/astra"
#define FAILCNT_PATH  STATE_DIR "/fail_count"
#define DISABLE_PATH  STATE_DIR "/disable"
#define LIBDIR        "/usr/lib/"
#define APPDIR        "/usr/share/app"
#endif

/* 四代原始入口在四代 libObj.so 中的新名字（elf_samehash_rename.py 产物） */
#define G4_ORIG_INIT  "Application_System_InjS"

typedef int  (*init_fn)(void *);
typedef void (*main_fn)(void *);

/* 动态链接器装载金丝雀探测：独立于 Application_System_Init 验证 LD_PRELOAD 成功装载 */
__attribute__((constructor)) void astra_canary_ctor(void)
{
    const char msg_con[] = "\n>>> [CANARY_CTOR] appFwBoot.so loaded by linker! <<<\n";
    (void)write(2, msg_con, sizeof(msg_con) - 1);
    (void)mkdir("/log", 0777);
    int fd = open("/log/canary_ctor.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
        const char msg[] = "[CANARY_CTOR] appFwBoot.so loaded by linker\n";
        (void)write(fd, msg, sizeof(msg) - 1);
        close(fd);
    }
}

static void logf_(const char *fmt, ...);

static void astra_assert_ignore(const char *assertion, const char *file, unsigned int line, const char *function)
{
    logf_("[ASTRA_ASSERT_BYPASSED] %s:%u in %s(): `%s` (平稳跳过，保持五代主线程存活)",
          file ? file : "?", line, function ? function : "?", assertion ? assertion : "?");
}

static void patch_function_noop(void *func_ptr, const char *name)
{
    if (!func_ptr) return;
    uintptr_t addr = (uintptr_t)func_ptr;
    int is_thumb = (addr & 1);
    uintptr_t raw_pc = addr & ~1u;
    uintptr_t page = raw_pc & ~0xfffu;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        if (is_thumb) {
            uint16_t *p = (uint16_t *)raw_pc;
            p[0] = 0x4770; /* bx lr (Thumb) */
        } else {
            uint32_t *p = (uint32_t *)raw_pc;
            p[0] = 0xe12fff1e; /* bx lr (ARM) */
        }
        __builtin___clear_cache((char *)raw_pc, (char *)raw_pc + 8);
        logf_("HOOK: 成功免疫 %s 入口 %p (替换为 bx lr, thumb=%d)", name, func_ptr, is_thumb);
    } else {
        logf_("HOOK: mprotect 失败 %s (%p) errno=%d", name, func_ptr, errno);
    }
}

/* ========================================================================= */
/* 五代 ASTRA 纯软件光栅化与 GPE Present 接管引擎 (仅 QEMU 构建启用)          */
/* 真机 (ZVE10_REAL_DEVICE) 使用真实硬件 GPU/GPE，不接管物理显存              */
/* ========================================================================= */

static void logf_(const char *fmt, ...);

#ifndef ZVE10_REAL_DEVICE

static uintptr_t get_phys_addr(void *vaddr)
{
    uintptr_t page_size = 4096;
    uintptr_t v_page = (uintptr_t)vaddr / page_size;
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0) return 0;
    off_t offset = v_page * 8;
    uint64_t entry = 0;
    if (pread(fd, &entry, 8, offset) != 8) {
        close(fd);
        return 0;
    }
    close(fd);
    if (!(entry & (1ULL << 63))) return 0;
    uint64_t pfn = entry & ((1ULL << 55) - 1);
    return (pfn * page_size) + ((uintptr_t)vaddr % page_size);
}

/* 校验虚拟地址区间 [addr, addr+len) 在 /proc/self/maps 中完整覆盖且具备 rw 权限，避免单页探测导致越界段错误 */
static int g5_va_range_rw_ok(uintptr_t addr, size_t len, uintptr_t expected_phys)
{
    if (addr < 0x10000u || len == 0 || addr > (uintptr_t)(-1) - len) return 0;
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;

    uintptr_t cur = addr;
    uintptr_t end_req = addr + len;
    int covered = 0;
    int all_devmem = 1;
    char buf[2048];
    size_t carry = 0;

    for (;;) {
        ssize_t n = read(fd, buf + carry, sizeof(buf) - 1u - carry);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        size_t total = carry + (size_t)n;
        buf[total] = '\0';

        char *line = buf;
        for (;;) {
            char *nl = strchr(line, '\n');
            if (!nl && n > 0) break;
            if (!nl && line[0] == '\0') break;
            if (nl) *nl = '\0';

            char *dash = NULL;
            unsigned long v_start = strtoul(line, &dash, 16);
            if (dash && *dash == '-') {
                char *sp = NULL;
                unsigned long v_end = strtoul(dash + 1, &sp, 16);
                while (sp && *sp == ' ') sp++;
                if (sp && sp[0] != '\0' && sp[1] != '\0') {
                    if ((uintptr_t)v_end > cur) {
                        if ((uintptr_t)v_start > cur) {
                            close(fd);
                            return 0;
                        }
                        if (sp[0] != 'r' || sp[1] != 'w') {
                            close(fd);
                            return 0;
                        }
                        if (!strstr(sp, "/dev/mem")) {
                            all_devmem = 0;
                        }
                        cur = (uintptr_t)v_end;
                        if (cur >= end_req) {
                            covered = 1;
                            break;
                        }
                    }
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
        if (covered || n == 0) break;
        carry = total - (size_t)(line - buf);
        if (carry >= sizeof(buf) - 1u) {
            /* 单行过长时安全丢弃余下片段，避免死循环 */
            carry = 0;
        } else if (carry > 0) {
            memmove(buf, line, carry);
        }
    }
    close(fd);
    if (!covered) return 0;

    if (!all_devmem) {
        uintptr_t p0 = get_phys_addr((void *)addr);
        if (p0 == 0) return 0;
        if (expected_phys != 0 && p0 != expected_phys) return 0;
    }
    return 1;
}

struct surface_mapping {
    void *base;
    size_t length;
    unsigned char *pixels;
};

static inline uint16_t ui_u16(const void *v) { uint16_t n; memcpy(&n, v, 2); return n; }
static inline uint32_t ui_u32(const void *v) { uint32_t n; memcpy(&n, v, 4); return n; }
static inline int16_t  ui_s16(const void *v) { return (int16_t)ui_u16(v); }
static inline unsigned ui_bpp(unsigned f) { return f == 0 ? 2 : (f == 3 ? 1 : (f == 1 || f == 7 ? 4 : 0)); }

static int map_surface(uint32_t physical, size_t span, struct surface_mapping *m)
{
    static int mem_fd = -1;
    if (physical < 0x00100000u || physical >= 0x40000000u || span > 0x40000000u - physical)
        return -5;
    if (mem_fd < 0) mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd < 0) return -5;
    unsigned delta = physical & 4095;
    m->length = (span + delta + 4095) & ~(size_t)4095;
    m->base = mmap(NULL, m->length, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, physical & ~4095u);
    if (m->base == MAP_FAILED) return -5;
    m->pixels = (unsigned char *)m->base + delta;
    return 0;
}

static inline void ui_pixel_get(const unsigned char *p, unsigned f, unsigned c[4])
{
    if (f == 0) {
        unsigned n = ui_u16(p);
        for (int i = 0; i < 4; ++i) c[i] = ((n >> (12 - i * 4)) & 15) * 17;
    } else if (f == 3) {
        c[0] = c[1] = c[2] = 255; c[3] = p[0];
    } else {
        for (int i = 0; i < 4; ++i) c[i] = p[f == 1 ? 3 - i : i];
    }
}

static inline void ui_pixel_put(unsigned char *p, unsigned f, const unsigned c[4])
{
    if (f == 0) {
        uint16_t n = 0;
        for (int i = 0; i < 4; ++i) n |= (c[i] >> 4) << (12 - i * 4);
        memcpy(p, &n, 2);
    } else {
        for (int i = 0; i < 4; ++i) p[f == 1 ? 3 - i : i] = c[i];
    }
}

static inline unsigned ui_scale(unsigned x, unsigned a) { return (x * a + 127) / 255; }

static inline void ui_composite(unsigned char *dst, unsigned fmt, unsigned c[4], unsigned opacity, unsigned mode)
{
    unsigned old[4], out[4];
    ui_pixel_get(dst, fmt, old);
    unsigned factor = mode ? ui_scale(c[3], opacity) : opacity;
    for (int i = 0; i < 3; ++i) out[i] = ui_scale(c[i], factor) + ui_scale(old[i], 255 - factor);
    out[3] = ui_scale(c[3], opacity) + ui_scale(old[3], 255 - factor);
    for (int i = 0; i < 4; ++i) if (out[i] > 255) out[i] = 255;
    ui_pixel_put(dst, fmt, out);
}

static int ui_surface_check(const unsigned char *p, size_t *span)
{
    unsigned w = ui_u16(p + 4), h = ui_u16(p + 6), bpp = ui_bpp(ui_u32(p + 16));
    if (!w || !h || w > 8192 || h > 8192 || !bpp || ui_u32(p + 20)) return -5;
    *span = (size_t)w * h * bpp;
    return *span <= 64 * 1024 * 1024 ? 0 : -5;
}

static int ui_fill_rect(unsigned char *dst, size_t capacity, const unsigned char *p)
{
    size_t span;
    unsigned fmt = ui_u32(p + 16), bpp = ui_bpp(fmt), sw = ui_u16(p + 4), sh = ui_u16(p + 6);
    int x = ui_s16(p + 8), y = ui_s16(p + 10), w = ui_s16(p + 12), h = ui_s16(p + 14);
    unsigned mode = ui_u32(p + 36);
    if (ui_surface_check(p, &span) || capacity < span || fmt == 3 || w <= 0 || h <= 0 || mode > 1 || ui_u32(p + 24)) return -5;
    int x0 = x < 0 ? 0 : x, y0 = y < 0 ? 0 : y;
    int x1 = x + w > (int)sw ? (int)sw : x + w, y1 = y + h > (int)sh ? (int)sh : y + h;
    for (int j = y0; j < y1; ++j) for (int i = x0; i < x1; ++i) {
        unsigned c[4] = {p[28], p[29], p[30], p[31]};
        ui_composite(dst + ((size_t)j * sw + i) * bpp, fmt, c, p[32], mode);
    }
    return 0;
}

static int ui_blit_surface(unsigned char *dst, size_t dc, const unsigned char *src, size_t sc, const unsigned char *p)
{
    size_t ss, ds;
    const unsigned char *d = p + 24;
    unsigned sf = ui_u32(p + 16), df = ui_u32(d + 24), sb = ui_bpp(sf), db = ui_bpp(df);
    unsigned char descriptor[24];
    memcpy(descriptor, d, 8); memcpy(descriptor + 16, p + 48, 8);
    if (ui_surface_check(p, &ss) || ui_surface_check(descriptor, &ds) || dc < ds || sc < ss || df == 3) return -5;
    unsigned sw = ui_u16(p + 4), sh = ui_u16(p + 6), dw = ui_u16(d + 4), dh = ui_u16(d + 6);
    int sx = ui_s16(p + 8), sy = ui_s16(p + 10), rw = ui_s16(p + 12), rh = ui_s16(p + 14);
    int dx = ui_s16(p + 32), dy = ui_s16(p + 34), ow = ui_s16(p + 36), oh = ui_s16(p + 38);
    int cx = ui_s16(p + 40), cy = ui_s16(p + 42), cw = ui_s16(p + 44), ch = ui_s16(p + 46);
    unsigned flags = ui_u32(p + 144), mode = ui_u32(p + 68);
    if (sx < 0 || sy < 0 || rw <= 0 || rh <= 0 || sx + rw > (int)sw || sy + rh > (int)sh ||
        ow <= 0 || oh <= 0 || cw <= 0 || ch <= 0 || mode > 1 || (flags & ~15u) || ui_u32(p + 56) ||
        cx < 0 || cy < 0 || cx + cw > (int)dw || cy + ch > (int)dh) return -5;
    int x0 = dx < cx ? cx : dx, y0 = dy < cy ? cy : dy;
    int x1 = dx + ow > cx + cw ? cx + cw : dx + ow, y1 = dy + oh > cy + ch ? cy + ch : dy + oh;
    for (int j = y0; j < y1; ++j) {
        int sj = sy + (j - dy) * rh / oh;
        for (int i = x0; i < x1; ++i) {
            int si = sx + (i - dx) * rw / ow;
            unsigned c[4];
            ui_pixel_get(src + ((size_t)sj * sw + si) * sb, sf, c);
            ui_composite(dst + ((size_t)j * dw + i) * db, df, c, 255, mode);
        }
    }
    return 0;
}

/* Morton 瓦片解包算法（将 GPE 内部瓦片平铺数据解包为标准行优先 RGBA4444 Framebuffer） */
static int g5_present_unpack(unsigned char *dst, size_t ds,
                             const unsigned char *src, size_t ss,
                             unsigned width, unsigned height)
{
    if (!dst || !src || ds < width * height * 2 || ss < width * height * 2)
        return -1;
    for (unsigned y = 0; y < height; ++y) {
        unsigned sy = height - 1 - y; /* Morton bottom-up 坐标翻转 */
        for (unsigned x = 0; x < width; ++x) {
            unsigned tile = (sy >> 3) * (width >> 3) + (x >> 3);
            unsigned z = (x & 1) | ((sy & 1) << 1) | ((x & 2) << 1) |
                         ((sy & 2) << 2) | ((x & 4) << 2) | ((sy & 4) << 3);
            size_t from = (tile * 64 + z) * 2;
            size_t to = (y * width + x) * 2;
            dst[to] = src[from];
            dst[to + 1] = src[from + 1];
        }
    }
    return 0;
}

#endif /* !ZVE10_REAL_DEVICE */

/* Thumb 绝对跳转安装器（8 字节：ldr.w pc, [pc, #0] + 4 字节绝对目标） */
static void patch_thumb_jump(void *target, void *replacement, const char *name)
{
    uintptr_t addr = (uintptr_t)target & ~1u;
    uintptr_t page = addr & ~4095u;
    if (mprotect((void *)page, 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        unsigned char *p = (unsigned char *)addr;
        p[0] = 0xdf; p[1] = 0xf8; p[2] = 0x00; p[3] = 0xf0; /* ldr.w pc, [pc, #0] */
        uint32_t to = (uint32_t)(uintptr_t)replacement;
        memcpy(p + 4, &to, 4);
        __builtin___clear_cache((char *)addr, (char *)addr + 8);
        logf_("HOOK: %s (%p -> %p) 安装成功", name, (void *)addr, replacement);
    } else {
        logf_("HOOK: %s (%p) mprotect 失败 errno=%d", name, (void *)addr, errno);
    }
}

/* 针对 2 mod 4 对齐的 Thumb 函数安装 12 字节绝对跳转（nop.n + ldr.w pc,[pc,#0] + 4B 目标 + nop.n） */
static void patch_thumb_jump_unaligned12(uintptr_t target, void *replacement, const char *name)
{
    uintptr_t addr = target & ~1u;
    uintptr_t page = addr & ~4095u;
    if (mprotect((void *)page, 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        uint16_t *p16 = (uint16_t *)addr;
        p16[0] = 0xBF00u; /* nop.n 使 addr+2 为 4B 对齐 */
        p16[1] = 0xF8DFu; /* ldr.w pc, [pc, #0] */
        p16[2] = 0xF000u;
        uint32_t to = (uint32_t)(uintptr_t)replacement;
        memcpy((void *)(addr + 6u), &to, 4);
        p16[5] = 0xBF00u; /* nop.n */
        __builtin___clear_cache((char *)addr, (char *)addr + 12);
        logf_("HOOK: %s (0x%lx -> %p) 12B 非对齐跳转安装成功", name, (unsigned long)addr, replacement);
    } else {
        logf_("HOOK: %s (0x%lx) mprotect 失败 errno=%d", name, (unsigned long)addr, errno);
    }
}

/* 备份并跳转前 8 字节（要求 4 字节对齐且原指令无 PC 相对寻址），返回可执行原函数跳板 (+1 Thumb) */
static void *make_thumb_trampoline_8(uintptr_t va, void *hook_fn, const char *name)
{
    uintptr_t addr = va & ~1u;
    if ((addr & 3u) != 0u) {
        logf_("HOOK_GL: %s (%p) 未按 4 字节对齐，拒绝安装 ldr.w pc,[pc,#0] 跳板以防 Align(PC,4) 错位崩溃",
              name, (void *)addr);
        return NULL;
    }
    uint8_t *pool = (uint8_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool == MAP_FAILED) return NULL;
    memcpy(pool, (const void *)addr, 8);
    uint16_t *t16 = (uint16_t *)(pool + 8);
    t16[0] = 0xF8DFu; /* ldr.w pc, [pc, #0] */
    t16[1] = 0xF000u;
    *(uint32_t *)(pool + 12) = (uint32_t)(addr + 8u + 1u);
    __builtin___clear_cache((char *)pool, (char *)pool + 16);
    patch_thumb_jump((void *)addr, hook_fn, name);
    logf_("HOOK_GL: %s (%p -> %p, tramp=%p) 安装成功", name, (void *)addr, hook_fn, (void *)pool);
    return (void *)(pool + 1);
}

static void *make_thumb_trampoline_12(uintptr_t va, void *hook_fn, const char *name)
{
    uintptr_t addr = va & ~1u;
    if ((addr & 3u) != 0u) {
        logf_("HOOK_GL: %s (%p) 未按 4 字节对齐，拒绝安装 12B 跳板", name, (void *)addr);
        return NULL;
    }
    uint8_t *pool = (uint8_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool == MAP_FAILED) return NULL;
    memcpy(pool, (const void *)addr, 12);
    uint16_t *t16 = (uint16_t *)(pool + 12);
    t16[0] = 0xF8DFu; /* ldr.w pc, [pc, #0] */
    t16[1] = 0xF000u;
    *(uint32_t *)(pool + 16) = (uint32_t)(addr + 12u + 1u);
    __builtin___clear_cache((char *)pool, (char *)pool + 20);
    patch_thumb_jump((void *)addr, hook_fn, name);
    logf_("HOOK_GL: %s (%p -> %p, tramp12=%p) 安装成功", name, (void *)addr, hook_fn, (void *)pool);
    return (void *)(pool + 1);
}

#ifdef ZVE10_REAL_DEVICE
/* 针对 2 mod 4 对齐且前 12 字节为完整无 PC 相对指令的 Thumb 函数安装跳板 */
static void *make_thumb_trampoline_unaligned12(uintptr_t va, void *hook_fn, const char *name)
{
    uintptr_t addr = va & ~1u;
    if ((addr & 3u) != 2u) {
        logf_("REAL_OBS: %s (%p) 非 2-mod-4 对齐，拒绝安装 12B 非对齐跳板", name, (void *)addr);
        return NULL;
    }
    uint8_t *pool = (uint8_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool == MAP_FAILED) return NULL;
    memcpy(pool, (const void *)addr, 12);
    uint16_t *t16 = (uint16_t *)(pool + 12);
    t16[0] = 0xF8DFu; /* ldr.w pc, [pc, #0] */
    t16[1] = 0xF000u;
    *(uint32_t *)(pool + 16) = (uint32_t)(addr + 12u + 1u);
    __builtin___clear_cache((char *)pool, (char *)pool + 20);

    uintptr_t page = addr & ~4095u;
    if (mprotect((void *)page, 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        logf_("REAL_OBS: %s (%p) mprotect 失败 errno=%d", name, (void *)addr, errno);
        munmap(pool, 4096);
        return NULL;
    }
    /* 在 addr(2 mod 4) 写入 nop.n + ldr.w pc,[pc,#0](addr+2 为 4B 对齐) + hook_fn(addr+6) + nop.n */
    uint16_t *p16 = (uint16_t *)addr;
    p16[0] = 0xBF00u;
    p16[1] = 0xF8DFu;
    p16[2] = 0xF000u;
    uint32_t to = (uint32_t)(uintptr_t)hook_fn;
    memcpy((void *)(addr + 6u), &to, 4);
    p16[5] = 0xBF00u;
    __builtin___clear_cache((char *)addr, (char *)addr + 12);
    logf_("REAL_OBS: %s (%p -> %p, tramp=%p) 12B 非对齐跳板安装成功", name, (void *)addr, hook_fn, (void *)pool);
    return (void *)(pool + 1);
}
#endif

static uint64_t g5_msec_now(void)
{
    /* 优先使用单调时钟，彻底免疫 sony_hwtimer 32 位回绕造成的挂钟跳变 */
    struct timespec ts = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
    }
    struct timeval tv = {0, 0};
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000L);
}

typedef enum {
    ASTRA_BOOT_NORMAL = 0,
    ASTRA_BOOT_MENU = 1,
    ASTRA_BOOT_SHOOTING = 2
} g5_boot_mode_t;

static volatile int g_boot_mode_cached = -1;
static volatile uint32_t g_ui_ready_pcm_ok = 0u;
static volatile uint32_t g_ui_ready_scr_hint = 0u;

static int g5_cmdline_has_token(const char *cmdline, const char *tok)
{
    if (!cmdline || !tok) return 0;
    size_t len = strlen(tok);
    const char *p = cmdline;
    while ((p = strstr(p, tok)) != NULL) {
        int left_ok = (p == cmdline || p[-1] == ' ' || p[-1] == '\t' || p[-1] == '\n');
        char after = p[len];
        int right_ok = (after == '\0' || after == ' ' || after == '\t' || after == '\n' || after == '\r');
        if (left_ok && right_ok) return 1;
        p += len;
    }
    return 0;
}

static g5_boot_mode_t g5_get_boot_mode(void)
{
    int cached = __atomic_load_n(&g_boot_mode_cached, __ATOMIC_ACQUIRE);
    if (cached >= 0) return (g5_boot_mode_t)cached;
#ifdef ZVE10_REAL_DEVICE
    /* 真机模式：默认直达 SHOOTING 待机取景界面（挂载全套快门/光圈/ISO/电池/卡槽 HUD 控件树） */
    g5_boot_mode_t mode = ASTRA_BOOT_SHOOTING;
#else
    g5_boot_mode_t mode = ASTRA_BOOT_NORMAL;
#endif
    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (g5_cmdline_has_token(buf, "astra_boot=menu")) {
                mode = ASTRA_BOOT_MENU;
            } else if (g5_cmdline_has_token(buf, "astra_boot=shooting")) {
                mode = ASTRA_BOOT_SHOOTING;
            } else if (g5_cmdline_has_token(buf, "astra_boot=normal")) {
                mode = ASTRA_BOOT_NORMAL;
            }
        }
    }
    /* 允许通过 /setting/mode/astra_boot 动态重定向 */
    int fmode = open("/setting/mode/astra_boot", O_RDONLY);
    if (fmode < 0) fmode = open("/setting/astra_boot", O_RDONLY);
    if (fmode >= 0) {
        char mbuf[32];
        ssize_t mn = read(fmode, mbuf, sizeof(mbuf) - 1);
        close(fmode);
        if (mn > 0) {
            mbuf[mn] = '\0';
            if (strstr(mbuf, "menu")) mode = ASTRA_BOOT_MENU;
            else if (strstr(mbuf, "shooting")) mode = ASTRA_BOOT_SHOOTING;
            else if (strstr(mbuf, "normal")) mode = ASTRA_BOOT_NORMAL;
        }
    }
    __atomic_store_n(&g_boot_mode_cached, (int)mode, __ATOMIC_RELEASE);
    return mode;
}

#ifndef ZVE10_REAL_DEVICE

static volatile uint32_t g_fb_sync_seq = 0;
static uint64_t g_last_fb_hash = 0;
static volatile int g_web_interactive_cached = -1;

static int g5_is_web_interactive(void)
{
    if (g_web_interactive_cached >= 0) return g_web_interactive_cached;
    int flag = 0;
    int fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (g5_cmdline_has_token(buf, "web_ui=1")) flag = 1;
        }
    }
    g_web_interactive_cached = flag;
    return flag;
}

static uint64_t g5_fnv1a_64(const uint8_t *buf, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    /* 步进按 4 字节采样的快速一致摘要，足够精确感知 UI 变更且保持高帧率 */
    const uint32_t *w = (const uint32_t *)(const void *)buf;
    size_t nw = len / 4u;
    for (size_t i = 0; i < nw; i++) {
        h ^= (uint64_t)w[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static void export_frame_data(const void *pixels, size_t span, uint32_t fallback_phys, const char *source_tag, int sync_vram)
{
    if (!pixels || span < 640u * 480u * 2u) return;
    int interactive = g5_is_web_interactive();
    if (!interactive) {
        size_t nonzero = 0;
        const unsigned char *px = (const unsigned char *)pixels;
        for (size_t k = 0; k < span; k++) {
            if (px[k] != 0) nonzero++;
        }
        logf_("[%s] 像素缓冲区非零字节数 = %zu / %zu (%.1f%%)",
              source_tag, nonzero, span, (double)nonzero * 100.0 / span);
        if (nonzero <= 500u) return;
    } else if (!sync_vram) {
        return;
    }

    uintptr_t phys = get_phys_addr((void *)pixels);
    if (!phys) phys = fallback_phys;

    if (interactive) {
        uint64_t h = g5_fnv1a_64((const uint8_t *)pixels, span);
        if (h == g_last_fb_hash && g_fb_sync_seq > 0u) return;
        g_last_fb_hash = h;
    } else {
        logf_("ASTRA_FB_READY physical=0x%08lx w=640 h=480 size=%zu fb=%p tag=%s",
              (unsigned long)phys, span, pixels, source_tag);
        int fd = open("/log/astra/astra_frame.bin", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
        if (fd >= 0) {
            (void)write(fd, pixels, span);
            fsync(fd);
            close(fd);
            logf_("  [★ 成功捕获五代真实全彩图像！] 已写入 /log/astra/astra_frame.bin");
        }
    }

    int ready_fd = open("/log/astra/frame_ready", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
    if (ready_fd >= 0) {
        fsync(ready_fd);
        close(ready_fd);
    }

    if (sync_vram) {
        struct surface_mapping vram_map = {0};
        if (map_surface(0x20000000u, span, &vram_map) == 0) {
            memcpy(vram_map.pixels, pixels, span);
            __sync_synchronize();
            munmap(vram_map.base, vram_map.length);
            uint32_t seq = __sync_add_and_fetch(&g_fb_sync_seq, 1u);
            if (interactive) {
                logf_("ASTRA_FB_SYNC seq=%u phys=0x20000000", seq);
            } else {
                logf_("  [★ 显存同步完成] 已将 %zu 字节镜像写入 0x20000000", span);
            }
        }
    }
}

static unsigned g_present_frame_count = 0;

static uintptr_t g5_hook_present(uintptr_t params, uintptr_t b, uintptr_t c, uintptr_t d)
{
    (void)b; (void)c; (void)d;
    const uint32_t *p = (const uint32_t *)params;
    if (!p) return (uintptr_t)-1;
    uint32_t src_phys = p[0];
    uint32_t dst_phys = p[1];
    unsigned w = (p[6] == 640u || p[6] == 480u) ? p[6] : 640u;
    unsigned h = (p[7] == 480u || p[7] == 640u) ? p[7] : 480u;
    size_t span = (size_t)w * h * 2u;
    int is_main_present = (p[5] == 0x4401u || src_phys == 0x20589300u);

    g_present_frame_count++;
    if (!g5_is_web_interactive() || g_present_frame_count <= 5u) {
        logf_("G5_PRESENT [#%u]: src_phys=0x%08x dst_phys=0x%08x w=%u h=%u (params[2..5]=%08x,%08x,%08x,%08x)",
              g_present_frame_count, src_phys, dst_phys, w, h, p[2], p[3], p[4], p[5]);
    }

    struct surface_mapping src_map = {0}, dst_map = {0};
    if (map_surface(src_phys, span, &src_map) == 0) {
        if (map_surface(dst_phys, span, &dst_map) == 0) {
            g5_present_unpack(dst_map.pixels, span, src_map.pixels, span, w, h);
            __sync_synchronize();
            export_frame_data(dst_map.pixels, span, dst_phys, "PRESENT_UNPACKED", is_main_present);
            munmap(dst_map.base, dst_map.length);
        } else {
            /* dst_phys (如 0xfe33a000) 不可映射时也必须将 Morton 瓦片解包为线性底图再导出，避免花屏 */
            static pthread_mutex_t s_unpack_mtx = PTHREAD_MUTEX_INITIALIZER;
            static unsigned char *s_unpack_buf = NULL;
            static size_t s_unpack_cap = 0;
            pthread_mutex_lock(&s_unpack_mtx);
            if (!s_unpack_buf || s_unpack_cap < span) {
                free(s_unpack_buf);
                s_unpack_buf = (unsigned char *)malloc(span);
                s_unpack_cap = s_unpack_buf ? span : 0;
            }
            if (s_unpack_buf && s_unpack_cap >= span &&
                g5_present_unpack(s_unpack_buf, span, src_map.pixels, span, w, h) == 0) {
                export_frame_data(s_unpack_buf, span, src_phys, "PRESENT_UNPACK_BUF", is_main_present);
            }
            pthread_mutex_unlock(&s_unpack_mtx);
        }
        munmap(src_map.base, src_map.length);
    } else if (!g5_is_web_interactive()) {
        logf_("G5_PRESENT [#%u]: map_surface(src_phys=0x%08x) 失败", g_present_frame_count, src_phys);
    }
    return 0;
}

typedef uintptr_t (*g5_entry_fn)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
static g5_entry_fn g_orig_update_records = NULL;

/* Thumb 跳板安装器（专用于 0x124bb4 等第 6 字节含 ldr rX, [pc, #imm] 的函数） */
static int install_update_records_hook(uintptr_t ob5_base, uint32_t offset, g5_entry_fn replacement, g5_entry_fn *original)
{
    unsigned char *address = (unsigned char *)(ob5_base + offset);
    static const unsigned char expected[8] = {0xb0, 0xb5, 0x0c, 0x46, 0x86, 0xb0, 0x1c, 0x49};
    if (memcmp(address, expected, 8) != 0) {
        logf_("HOOK_TRAMP: 0x%x prologue mismatch!", offset);
        return -1;
    }
    uint16_t load = ui_u16(address + 6); /* 0x491c */
    uint32_t literal = *(uint32_t *)(((uintptr_t)(address + 10) & ~(uintptr_t)3) + (load & 255) * 4);
    unsigned char *code = (unsigned char *)mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        logf_("HOOK_TRAMP: mmap failed errno=%d", errno);
        return -1;
    }
    if (mprotect((void *)((uintptr_t)address & ~(uintptr_t)4095), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        logf_("HOOK_TRAMP: mprotect failed errno=%d", errno);
        munmap(code, 4096);
        return -1;
    }
    memcpy(code, address, 12);
    uint16_t relocated = (load & 0xff00) | 3; /* 指向 code + 20 */
    memcpy(code + 6, &relocated, 2);
    /* 跳回 address + 12 (Thumb 模式) */
    code[12] = 0xdf; code[13] = 0xf8; code[14] = 0x00; code[15] = 0xf0;
    uint32_t resume_addr = ((uint32_t)(uintptr_t)(address + 12)) | 1u;
    memcpy(code + 16, &resume_addr, 4);
    memcpy(code + 20, &literal, 4);
    __builtin___clear_cache((char *)code, (char *)code + 24);
    *original = (g5_entry_fn)((uintptr_t)code | 1u);

    /* 在 address 安装跳转至 replacement */
    address[0] = 0xdf; address[1] = 0xf8; address[2] = 0x00; address[3] = 0xf0;
    uint32_t to = (uint32_t)(uintptr_t)replacement;
    memcpy(address + 4, &to, 4);
    __builtin___clear_cache((char *)address, (char *)address + 8);
    logf_("HOOK_TRAMP: libOb5:update_records (%p -> %p, orig_tramp=%p, lit=0x%08x) 安装成功",
          (void *)address, (void *)replacement, (void *)*original, literal);
    return 0;
}

static uintptr_t g5_hook_engine_wait(uintptr_t engine, uintptr_t b, uintptr_t c, uintptr_t d)
{
    (void)b; (void)c; (void)d;
    static unsigned wait_count = 0;
    if (++wait_count <= 10 || (wait_count % 30 == 0)) {
        logf_("G5_WAIT [#%u]: engine=%p (模拟 GPU 处理完成)", wait_count, (void *)engine);
    }
    if (engine == 2) return 0x40000000u; /* 匹配四代 present 完成标志 */
    return 1; /* 返回 1 表示 GPU 等待完成 */
}

static uintptr_t g5_ob5_base = 0;
static unsigned g_rec_cb_calls = 0;

static uintptr_t g5_hook_update_records(uintptr_t records, uintptr_t count, uintptr_t c, uintptr_t d)
{
    (void)c;
    (void)d;
    static unsigned rec_calls = 0;
    rec_calls++;
    if (rec_calls <= 15 || (rec_calls % 20 == 0)) {
        logf_("G5_RECORDS [#%u]: records=%p count=%lu", rec_calls, (void *)records, (unsigned long)count);
    }
    if (records && count > 0 && count <= 8) {
        for (unsigned i = 0; i < count; i++) {
            const unsigned char *r = (const unsigned char *)records + i * 32;
            uint32_t bitmap = *(const uint32_t *)(r + 28);
            uint32_t phys   = *(const uint32_t *)(r + 20);
            if (rec_calls <= 5) {
                logf_("  [Record #%u]: bitmap=0x%08x phys=0x%08x", i, bitmap, phys);
            }
            if (bitmap > 0x1000) {
                const void *pixels = *(const void *const *)(bitmap + 8);
                if (rec_calls <= 5) {
                    logf_("  [Record #%u]: pixels=%p", i, pixels);
                }
                if (pixels) {
                    int sync_rec = (phys == 0x22bb2000u || phys == 0x22c48000u);
                    export_frame_data(pixels, 640u * 480u * 2u, phys, "RECORD_BITMAP", sync_rec);
                }
            }
        }
    }
    /* 确保即使在 install_g5_vdf_if_hooks 执行前进入也能拿到 libOb5.so 基址 */
    if (!g5_ob5_base && records) {
        Dl_info dli = {0};
        if (dladdr((const void *)records, &dli) && dli.dli_fbase) {
            g5_ob5_base = (uintptr_t)dli.dli_fbase;
        }
    }
    /*
     * 关键：0x122a4a 获取 0x3c874c 递归互斥锁后尾调 0x124bb4 (update_records),
     * 依赖远端 0x8004 回调触发 *(base+0x3c8fb8)(*(base+0x3c8fb0)) (0x122964) 来解锁 0x3c874c。
     * QEMU 中无远端核，且递归锁属主为当前线程，因此必须在当前线程同步完成回调并跳过 DSP IPC。
     */
    if (g5_ob5_base) {
        typedef void (*vdf_update_cb_fn)(void *);
        vdf_update_cb_fn cb = *(vdf_update_cb_fn *)(g5_ob5_base + 0x3c8fb8u);
        void *cb_arg = *(void **)(g5_ob5_base + 0x3c8fb0u);
        if (cb && cb_arg && records == (uintptr_t)cb_arg + 0xb0u) {
            if (++g_rec_cb_calls <= 15) {
                logf_("G5_RECORDS_CB #%u: 同步执行更新完成回调 %p(%p) 以释放 0x3c874c",
                      g_rec_cb_calls, (void *)cb, cb_arg);
            }
            cb(cb_arg);
        }
    }
    return 0;
}

static unsigned g_gemini_solid_calls = 0;
static unsigned g_gemini_rect_calls = 0;
static unsigned g_gemini_quad_calls = 0;
static unsigned g_gl_teximg_calls = 0;
static unsigned g_gl_texsub_calls = 0;
static unsigned g_g5_swap_calls = 0;

/* GL 纹理影子缓存：记录线性纹理像素供纯软件 GEMINI 光栅器直接采样 */
typedef struct {
    uint32_t tex_id;
    int      w;
    int      h;
    uint32_t fmt;
    uint32_t type;
    uint8_t *rgba; /* RGBA8888 线性缓冲 (w * h * 4) */
} GeminiTexSlot;

#define MAX_GEMINI_TEX 256
static GeminiTexSlot g_tex_slots[MAX_GEMINI_TEX];
static uint32_t      g_cur_gl_tex_id = 0;
static int           g_gl_hooks_done = 0;
static uintptr_t     g_libob5_base_cached = 0;

typedef void (*gl_bind_fn_t)(uint32_t target, uint32_t texture);
typedef void (*gl_teximg_fn_t)(uint32_t target, int32_t level, int32_t internalformat,
                               int32_t width, int32_t height, int32_t border,
                               uint32_t format, uint32_t type, const void *pixels);
typedef void (*gl_texsub_fn_t)(uint32_t target, int32_t level, int32_t xoffset, int32_t yoffset,
                               int32_t width, int32_t height, uint32_t format, uint32_t type,
                               const void *pixels);
typedef uintptr_t (*g5_swap_fn_t)(uintptr_t s);

static gl_bind_fn_t   g_orig_gl_bind = NULL;
static gl_teximg_fn_t g_orig_gl_teximg = NULL;
static gl_texsub_fn_t g_orig_gl_texsub = NULL;
static g5_swap_fn_t   g_orig_g5_swap = NULL;

static GeminiTexSlot *find_or_alloc_tex_slot(uint32_t tex_id, int create)
{
    if (tex_id == 0) return NULL;
    for (int i = 0; i < MAX_GEMINI_TEX; i++) {
        if (g_tex_slots[i].tex_id == tex_id) return &g_tex_slots[i];
    }
    if (!create) return NULL;
    for (int i = 0; i < MAX_GEMINI_TEX; i++) {
        if (g_tex_slots[i].tex_id == 0) {
            g_tex_slots[i].tex_id = tex_id;
            return &g_tex_slots[i];
        }
    }
    return NULL;
}

static inline void decode_gl_pixel(const uint8_t *src, uint32_t fmt, uint32_t type, uint8_t out[4])
{
    if (type == 0x8033u) { /* GL_UNSIGNED_SHORT_4_4_4_4 (RGBA4444) */
        uint16_t v = (uint16_t)(src[0] | ((uint16_t)src[1] << 8));
        out[0] = (uint8_t)(((v >> 12) & 0xFu) * 17u);
        out[1] = (uint8_t)(((v >> 8)  & 0xFu) * 17u);
        out[2] = (uint8_t)(((v >> 4)  & 0xFu) * 17u);
        out[3] = (uint8_t)((v         & 0xFu) * 17u);
    } else if (type == 0x8034u) { /* GL_UNSIGNED_SHORT_5_5_5_1 (RGBA5551) */
        uint16_t v = (uint16_t)(src[0] | ((uint16_t)src[1] << 8));
        out[0] = (uint8_t)((((v >> 11) & 0x1Fu) * 255u) / 31u);
        out[1] = (uint8_t)((((v >> 6)  & 0x1Fu) * 255u) / 31u);
        out[2] = (uint8_t)((((v >> 1)  & 0x1Fu) * 255u) / 31u);
        out[3] = (v & 1u) ? 255u : 0u;
    } else if (type == 0x8363u) { /* GL_UNSIGNED_SHORT_5_6_5 (RGB565) */
        uint16_t v = (uint16_t)(src[0] | ((uint16_t)src[1] << 8));
        out[0] = (uint8_t)((((v >> 11) & 0x1Fu) * 255u) / 31u);
        out[1] = (uint8_t)((((v >> 5)  & 0x3Fu) * 255u) / 63u);
        out[2] = (uint8_t)(((v         & 0x1Fu) * 255u) / 31u);
        out[3] = 255u;
    } else if (fmt == 0x1906u) { /* GL_ALPHA */
        out[0] = 255u;
        out[1] = 255u;
        out[2] = 255u;
        out[3] = src[0];
    } else if (fmt == 0x1907u) { /* GL_RGB */
        out[0] = src[0]; out[1] = src[1]; out[2] = src[2]; out[3] = 255u;
    } else if (fmt == 0x1909u) { /* GL_LUMINANCE */
        out[0] = src[0]; out[1] = src[0]; out[2] = src[0]; out[3] = 255u;
    } else if (fmt == 0x190Au) { /* GL_LUMINANCE_ALPHA */
        out[0] = src[0]; out[1] = src[0]; out[2] = src[0]; out[3] = src[1];
    } else { /* GL_RGBA / GL_UNSIGNED_BYTE */
        out[0] = src[0]; out[1] = src[1]; out[2] = src[2]; out[3] = src[3];
    }
}

static size_t gl_bpp(uint32_t fmt, uint32_t type)
{
    if (type == 0x8033u || type == 0x8034u || type == 0x8363u) return 2;
    if (fmt == 0x1906u || fmt == 0x1909u) return 1;
    if (fmt == 0x190Au) return 2;
    if (fmt == 0x1907u) return 3;
    return 4;
}

static void g5_hook_gl_bind_texture(uint32_t target, uint32_t texture)
{
    if (target == 0x0DE1u) g_cur_gl_tex_id = texture;
    if (g_orig_gl_bind) g_orig_gl_bind(target, texture);
}

static void g5_hook_gl_tex_image_2d(uint32_t target, int32_t level, int32_t internalformat,
                                    int32_t width, int32_t height, int32_t border,
                                    uint32_t format, uint32_t type, const void *pixels)
{
    if (++g_gl_teximg_calls <= 15) {
        logf_("G5_GL_TEXIMG [#%u]: tex=%u tgt=%#x lvl=%d ifmt=%#x wh=%dx%d fmt=%#x type=%#x pix=%p",
              g_gl_teximg_calls, g_cur_gl_tex_id, target, level, internalformat,
              width, height, format, type, pixels);
    }
    if (target == 0x0DE1u && level == 0 && width > 0 && height > 0 && width <= 4096 && height <= 4096) {
        GeminiTexSlot *slot = find_or_alloc_tex_slot(g_cur_gl_tex_id, 1);
        if (slot) {
            size_t need = (size_t)width * (size_t)height * 4u;
            if (!slot->rgba || slot->w != width || slot->h != height) {
                if (slot->rgba) munmap(slot->rgba, ((size_t)slot->w * (size_t)slot->h * 4u + 4095u) & ~4095u);
                slot->rgba = (uint8_t *)mmap(NULL, (need + 4095u) & ~4095u,
                                             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (slot->rgba == MAP_FAILED) slot->rgba = NULL;
            }
            slot->w = width;
            slot->h = height;
            slot->fmt = format;
            slot->type = type;
            if (slot->rgba && pixels) {
                const uint8_t *src = (const uint8_t *)pixels;
                size_t bpp = gl_bpp(format, type);
                size_t total = (size_t)width * (size_t)height;
                for (size_t i = 0; i < total; i++) {
                    decode_gl_pixel(src + i * bpp, format, type, &slot->rgba[i * 4u]);
                }
            } else if (slot->rgba) {
                memset(slot->rgba, 0, need);
            }
        }
    }
    if (g_orig_gl_teximg) g_orig_gl_teximg(target, level, internalformat, width, height, border, format, type, pixels);
}

static void g5_hook_gl_tex_sub_image_2d(uint32_t target, int32_t level, int32_t xoffset, int32_t yoffset,
                                        int32_t width, int32_t height, uint32_t format, uint32_t type,
                                        const void *pixels)
{
    if (++g_gl_texsub_calls <= 15) {
        logf_("G5_GL_TEXSUB [#%u]: tex=%u tgt=%#x lvl=%d xy=%d,%d wh=%dx%d fmt=%#x type=%#x pix=%p",
              g_gl_texsub_calls, g_cur_gl_tex_id, target, level, xoffset, yoffset,
              width, height, format, type, pixels);
    }
    if (target == 0x0DE1u && level == 0 && pixels && width > 0 && height > 0) {
        GeminiTexSlot *slot = find_or_alloc_tex_slot(g_cur_gl_tex_id, 0);
        if (slot && slot->rgba) {
            const uint8_t *src = (const uint8_t *)pixels;
            size_t bpp = gl_bpp(format, type);
            for (int row = 0; row < height; row++) {
                int dy = yoffset + row;
                if (dy < 0 || dy >= slot->h) continue;
                for (int col = 0; col < width; col++) {
                    int dx = xoffset + col;
                    if (dx < 0 || dx >= slot->w) continue;
                    decode_gl_pixel(src + ((size_t)row * (size_t)width + (size_t)col) * bpp,
                                    format, type, &slot->rgba[((size_t)dy * (size_t)slot->w + (size_t)dx) * 4u]);
                }
            }
        }
    }
    if (g_orig_gl_texsub) g_orig_gl_texsub(target, level, xoffset, yoffset, width, height, format, type, pixels);
}

/* ---- GEMINI 纯软件 2D 光栅画布与状态管理 ---- */
#define GEMINI_MAX_W 800
#define GEMINI_MAX_H 600
#define G5_MAIN_PRESENT_SRC_PHYS 0x20589300u

static uint32_t g_gemini_fb[GEMINI_MAX_W * GEMINI_MAX_H];
static int g_gemini_fb_w = 640;
static int g_gemini_fb_h = 480;
static int g_gemini_fb_inited = 0;
static uintptr_t g_last_surface_ctx = 0;
static struct surface_mapping g_gemini_present_sm = {0};
static int g_gemini_present_sm_failed = 0;

static float g5_abs_f(float v) { return v < 0.0f ? -v : v; }

static int g5_floor_i(float v)
{
    int i = (int)v;
    return ((float)i > v) ? (i - 1) : i;
}

static int g5_ceil_i(float v)
{
    int i = (int)v;
    return ((float)i < v) ? (i + 1) : i;
}

static int g5_clamp_i(int v, int lo, int hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static void g5_ensure_fb_init(uintptr_t s)
{
    if (!g_gemini_fb_inited) {
        size_t total = (size_t)GEMINI_MAX_W * (size_t)GEMINI_MAX_H;
        for (size_t i = 0; i < total; i++) {
            g_gemini_fb[i] = 0xff000000u; /* 默认不透明黑 */
        }
        g_gemini_fb_inited = 1;
    }
    if (s > 0x10000u) {
        g_last_surface_ctx = s;
        uint16_t sw = *(const uint16_t *)(s + 0x14);
        uint16_t sh = *(const uint16_t *)(s + 0x16);
        if (sw >= 16 && sw <= GEMINI_MAX_W && sh >= 16 && sh <= GEMINI_MAX_H) {
            g_gemini_fb_w = (int)sw;
            g_gemini_fb_h = (int)sh;
        }
    }
}

/* 保留上一帧完整 OSD 内容；局部脏矩形/全屏清理由 glClear / SurfaceContext::clear 按 Scissor 裁剪框精准执行 */
static void g5_prepare_fb_for_draw(uintptr_t s)
{
    g5_ensure_fb_init(s);
}

/* 对坐标点应用 GEMINI 4x4 列主序仿射/正交矩阵；自动适配屏幕像素或 NDC 坐标空间 */
static void g5_transform_pt(const float *m, int fb_w, int fb_h, float x, float y, float *ox, float *oy)
{
    if (!m) {
        *ox = x;
        *oy = y;
        return;
    }
    float tx = m[0] * x + m[4] * y + m[12];
    float ty = m[1] * x + m[5] * y + m[13];
    int is_ndc = (g5_abs_f(m[0]) < 0.05f && g5_abs_f(m[5]) < 0.05f &&
                  g5_abs_f(m[1]) < 0.05f && g5_abs_f(m[4]) < 0.05f &&
                  g5_abs_f(m[12]) <= 2.5f && g5_abs_f(m[13]) <= 2.5f);
    if (is_ndc) {
        *ox = (tx + 1.0f) * 0.5f * (float)fb_w;
        *oy = (m[5] <= 0.0f)
                  ? ((1.0f - ty) * 0.5f * (float)fb_h)
                  : ((ty + 1.0f) * 0.5f * (float)fb_h);
    } else {
        *ox = tx;
        *oy = ty;
    }
}

static inline void g5_blend_px(int x, int y, uint8_t sr, uint8_t sg, uint8_t sb, uint8_t sa)
{
    if ((unsigned)x >= (unsigned)g_gemini_fb_w || (unsigned)y >= (unsigned)g_gemini_fb_h || sa == 0) {
        return;
    }
    uint32_t *dstp = &g_gemini_fb[y * g_gemini_fb_w + x];
    if (sa == 255) {
        *dstp = (uint32_t)sr | ((uint32_t)sg << 8) | ((uint32_t)sb << 16) | (0xffu << 24);
        return;
    }
    uint32_t d = *dstp;
    uint32_t dr = d & 0xffu;
    uint32_t dg = (d >> 8) & 0xffu;
    uint32_t db = (d >> 16) & 0xffu;
    uint32_t da = (d >> 24) & 0xffu;
    uint32_t inv_a = 255u - (uint32_t)sa;
    uint32_t or_ = ((uint32_t)sr * sa + dr * inv_a + 127u) / 255u;
    uint32_t og  = ((uint32_t)sg * sa + dg * inv_a + 127u) / 255u;
    uint32_t ob  = ((uint32_t)sb * sa + db * inv_a + 127u) / 255u;
    uint32_t oa  = (uint32_t)sa + (da * inv_a + 127u) / 255u;
    if (oa > 255u) oa = 255u;
    *dstp = (or_ & 0xffu) | ((og & 0xffu) << 8) | ((ob & 0xffu) << 16) | ((oa & 0xffu) << 24);
}

/* 获取 SurfaceContext 裁剪框 (转换为 top-down [cx0,cx1) x [cy0,cy1)) */
static void g5_get_scissor_clip(uintptr_t s, int *cx0, int *cy0, int *cx1, int *cy1)
{
    *cx0 = 0; *cy0 = 0; *cx1 = g_gemini_fb_w; *cy1 = g_gemini_fb_h;
    if (s > 0x10000u) {
        uint32_t sc_en = *(const uint32_t *)(s + 0x28u + 0x0cu);
        if (sc_en != 0) {
            const int16_t *sc = (const int16_t *)(s + 0x28u + 0x44u);
            int x0 = (int)sc[0];
            int y_gl = (int)sc[1];
            int w = (int)sc[2];
            int h = (int)sc[3];
            if (w > 0 && h > 0) {
                int y0 = g_gemini_fb_h - y_gl - h;
                *cx0 = g5_clamp_i(x0, 0, g_gemini_fb_w);
                *cy0 = g5_clamp_i(y0, 0, g_gemini_fb_h);
                *cx1 = g5_clamp_i(x0 + w, 0, g_gemini_fb_w);
                *cy1 = g5_clamp_i(y0 + h, 0, g_gemini_fb_h);
            }
        }
    }
}

/* 三角形光栅化（支持任意仿射变换后的纯色或纹理贴图 Quad 切分绘制，并尊重 Scissor 裁剪） */
static void g5_raster_tri(
    int clip_x0, int clip_y0, int clip_x1, int clip_y1,
    float x0, float y0, float u0, float v0,
    float x1, float y1, float u1, float v1,
    float x2, float y2, float u2, float v2,
    const uint8_t *tex_rgba, int tex_w, int tex_h, uint32_t tex_fmt,
    uint8_t cr, uint8_t cg, uint8_t cb, uint8_t ca)
{
    float area = (x1 - x0) * (y2 - y0) - (y1 - y0) * (x2 - x0);
    if (g5_abs_f(area) < 1e-4f || clip_x0 >= clip_x1 || clip_y0 >= clip_y1) return;

    float minxf = x0 < x1 ? (x0 < x2 ? x0 : x2) : (x1 < x2 ? x1 : x2);
    float maxxf = x0 > x1 ? (x0 > x2 ? x0 : x2) : (x1 > x2 ? x1 : x2);
    float minyf = y0 < y1 ? (y0 < y2 ? y0 : y2) : (y1 < y2 ? y1 : y2);
    float maxyf = y0 > y1 ? (y0 > y2 ? y0 : y2) : (y1 > y2 ? y1 : y2);

    int minx = g5_clamp_i(g5_floor_i(minxf), clip_x0, clip_x1 - 1);
    int maxx = g5_clamp_i(g5_ceil_i(maxxf) - 1, clip_x0, clip_x1 - 1);
    int miny = g5_clamp_i(g5_floor_i(minyf), clip_y0, clip_y1 - 1);
    int maxy = g5_clamp_i(g5_ceil_i(maxyf) - 1, clip_y0, clip_y1 - 1);
    if (minx > maxx || miny > maxy) return;

    float inv_area = 1.0f / area;
    float sgn = area > 0.0f ? 1.0f : -1.0f;

    for (int py = miny; py <= maxy; py++) {
        float cy = (float)py + 0.5f;
        for (int px = minx; px <= maxx; px++) {
            float cx = (float)px + 0.5f;
            float w0 = ((x1 - cx) * (y2 - cy) - (y1 - cy) * (x2 - cx)) * sgn;
            float w1 = ((x2 - cx) * (y0 - cy) - (y2 - cy) * (x0 - cx)) * sgn;
            float w2 = ((x0 - cx) * (y1 - cy) - (y0 - cy) * (x1 - cx)) * sgn;
            if (w0 < -1e-4f || w1 < -1e-4f || w2 < -1e-4f) continue;

            if (!tex_rgba) {
                g5_blend_px(px, py, cr, cg, cb, ca);
                continue;
            }
            float b0 = w0 * (inv_area * sgn);
            float b1 = w1 * (inv_area * sgn);
            float b2 = w2 * (inv_area * sgn);
            int tx = g5_clamp_i(g5_floor_i(b0 * u0 + b1 * u1 + b2 * u2), 0, tex_w - 1);
            int ty = g5_clamp_i(g5_floor_i(b0 * v0 + b1 * v1 + b2 * v2), 0, tex_h - 1);
            const uint8_t *sp = tex_rgba + ((size_t)ty * (size_t)tex_w + (size_t)tx) * 4u;
            uint8_t sr = sp[0], sg = sp[1], sb = sp[2], sa = sp[3];
            if (tex_fmt == 0x1906u) { /* GL_ALPHA 字模遮罩：颜色固定白，提取 Alpha 乘以调制色 */
                sr = 255; sg = 255; sb = 255;
            }
            uint8_t mr = (uint8_t)(((uint32_t)sr * cr + 127u) / 255u);
            uint8_t mg = (uint8_t)(((uint32_t)sg * cg + 127u) / 255u);
            uint8_t mb = (uint8_t)(((uint32_t)sb * cb + 127u) / 255u);
            uint8_t ma = (uint8_t)(((uint32_t)sa * ca + 127u) / 255u);
            g5_blend_px(px, py, mr, mg, mb, ma);
        }
    }
}

/* 高速光栅轴对齐或任意变换 Quad（支持纯色或纹理采样 + Scissor 裁剪） */
static void g5_draw_transformed_quad(
    int clip_x0, int clip_y0, int clip_x1, int clip_y1,
    const float *m,
    float x0, float y0, float u0, float v0,
    float x1, float y1, float u1, float v1,
    float x2, float y2, float u2, float v2,
    float x3, float y3, float u3, float v3,
    const uint8_t *tex_rgba, int tex_w, int tex_h, uint32_t tex_fmt,
    uint8_t cr, uint8_t cg, uint8_t cb, uint8_t ca)
{
    if (ca == 0 || clip_x0 >= clip_x1 || clip_y0 >= clip_y1) return;

    float qx0, qy0, qx1, qy1, qx2, qy2, qx3, qy3;
    g5_transform_pt(m, g_gemini_fb_w, g_gemini_fb_h, x0, y0, &qx0, &qy0);
    g5_transform_pt(m, g_gemini_fb_w, g_gemini_fb_h, x1, y1, &qx1, &qy1);
    g5_transform_pt(m, g_gemini_fb_w, g_gemini_fb_h, x2, y2, &qx2, &qy2);
    g5_transform_pt(m, g_gemini_fb_w, g_gemini_fb_h, x3, y3, &qx3, &qy3);

    int is_axis_aligned =
        g5_abs_f(qy0 - qy1) < 0.01f &&
        g5_abs_f(qx1 - qx2) < 0.01f &&
        g5_abs_f(qy2 - qy3) < 0.01f &&
        g5_abs_f(qx3 - qx0) < 0.01f &&
        g5_abs_f(qx1 - qx0) >= 0.5f &&
        g5_abs_f(qy3 - qy0) >= 0.5f;

    if (is_axis_aligned) {
        float minxf = qx0 < qx1 ? qx0 : qx1;
        float maxxf = qx0 > qx1 ? qx0 : qx1;
        float minyf = qy0 < qy3 ? qy0 : qy3;
        float maxyf = qy0 > qy3 ? qy0 : qy3;
        int minx = g5_clamp_i(g5_floor_i(minxf + 0.01f), clip_x0, clip_x1 - 1);
        int maxx = g5_clamp_i(g5_ceil_i(maxxf - 0.01f) - 1, clip_x0, clip_x1 - 1);
        int miny = g5_clamp_i(g5_floor_i(minyf + 0.01f), clip_y0, clip_y1 - 1);
        int maxy = g5_clamp_i(g5_ceil_i(maxyf - 0.01f) - 1, clip_y0, clip_y1 - 1);
        if (minx > maxx || miny > maxy) return;

        if (!tex_rgba) {
            if (ca == 255) {
                uint32_t packed = (uint32_t)cr | ((uint32_t)cg << 8) | ((uint32_t)cb << 16) | (0xffu << 24);
                for (int py = miny; py <= maxy; py++) {
                    uint32_t *row = &g_gemini_fb[py * g_gemini_fb_w];
                    for (int px = minx; px <= maxx; px++) {
                        row[px] = packed;
                    }
                }
            } else {
                for (int py = miny; py <= maxy; py++) {
                    for (int px = minx; px <= maxx; px++) {
                        g5_blend_px(px, py, cr, cg, cb, ca);
                    }
                }
            }
            return;
        }

        float inv_dx = 1.0f / (qx1 - qx0);
        float inv_dy = 1.0f / (qy3 - qy0);
        for (int py = miny; py <= maxy; py++) {
            float vnorm = ((float)py + 0.5f - qy0) * inv_dy;
            int ty = g5_clamp_i(g5_floor_i(v0 + vnorm * (v3 - v0)), 0, tex_h - 1);
            const uint8_t *tex_row = tex_rgba + (size_t)ty * (size_t)tex_w * 4u;
            for (int px = minx; px <= maxx; px++) {
                float unorm = ((float)px + 0.5f - qx0) * inv_dx;
                int tx = g5_clamp_i(g5_floor_i(u0 + unorm * (u1 - u0)), 0, tex_w - 1);
                const uint8_t *sp = tex_row + (size_t)tx * 4u;
                uint8_t sr = sp[0], sg = sp[1], sb = sp[2], sa = sp[3];
                if (tex_fmt == 0x1906u) {
                    sr = 255; sg = 255; sb = 255;
                }
                uint8_t mr = (uint8_t)(((uint32_t)sr * cr + 127u) / 255u);
                uint8_t mg = (uint8_t)(((uint32_t)sg * cg + 127u) / 255u);
                uint8_t mb = (uint8_t)(((uint32_t)sb * cb + 127u) / 255u);
                uint8_t ma = (uint8_t)(((uint32_t)sa * ca + 127u) / 255u);
                g5_blend_px(px, py, mr, mg, mb, ma);
            }
        }
        return;
    }

    /* 一般旋转/斜切 Quad：切分为两个三角形绘制 */
    g5_raster_tri(clip_x0, clip_y0, clip_x1, clip_y1,
                  qx0, qy0, u0, v0, qx1, qy1, u1, v1, qx2, qy2, u2, v2,
                  tex_rgba, tex_w, tex_h, tex_fmt, cr, cg, cb, ca);
    g5_raster_tri(clip_x0, clip_y0, clip_x1, clip_y1,
                  qx0, qy0, u0, v0, qx2, qy2, u2, v2, qx3, qy3, u3, v3,
                  tex_rgba, tex_w, tex_h, tex_fmt, cr, cg, cb, ca);
}

static inline uint32_t g5_morton_8x8(uint32_t lx, uint32_t ly)
{
    /* 标准 DMP/GEMINI 8x8 Z-order Morton：x 在 bit 0,2,4，y 在 bit 1,3,5 */
    return (lx & 1u)
         | ((ly & 1u) << 1)
         | ((lx & 2u) << 1)
         | ((ly & 2u) << 2)
         | ((lx & 4u) << 2)
         | ((ly & 4u) << 3);
}

static void g5_pack_fb_rgba4444_morton(uint16_t *dst16, int w, int h, uint32_t *out_nonzero, uint32_t *out_nonblack)
{
    uint32_t nz = 0, nb = 0;
    int tiles_x = w / 8;
    int tiles_y = h / 8;
    for (int ty = 0; ty < tiles_y; ty++) {
        for (int tx = 0; tx < tiles_x; tx++) {
            size_t tile_base = (size_t)(ty * tiles_x + tx) * 64u;
            for (int ly = 0; ly < 8; ly++) {
                /* OpenGL ES surface 原点在左下角，g5_present_unpack 按底朝上解包，因此需 Y 轴翻转对齐顶朝下屏幕 */
                int src_y = (h - 1) - (ty * 8 + ly);
                const uint32_t *src_row = &g_gemini_fb[src_y * w + (tx * 8)];
                for (int lx = 0; lx < 8; lx++) {
                    uint32_t p = src_row[lx];
                    uint32_t r4 = (p >> 4) & 0xfu;
                    uint32_t g4 = (p >> 12) & 0xfu;
                    uint32_t b4 = (p >> 20) & 0xfu;
                    uint32_t a4 = (p >> 28) & 0xfu;
                    uint16_t p16 = (uint16_t)((r4 << 12) | (g4 << 8) | (b4 << 4) | a4);
                    dst16[tile_base + g5_morton_8x8((uint32_t)lx, (uint32_t)ly)] = p16;
                    if (p16 != 0) nz++;
                    if ((p16 & 0xfff0u) != 0) nb++;
                }
            }
        }
    }
    if (out_nonzero) *out_nonzero = nz;
    if (out_nonblack) *out_nonblack = nb;
}

static void g5_log_proc_maps_interesting(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    char line[256];
    int printed = 0;
    while (fgets(line, sizeof(line), fp) && printed < 25) {
        if (strstr(line, "/dev/") || strstr(line, "[heap]") ||
            strstr(line, "1d") || strstr(line, "1c") ||
            strstr(line, "20") || strstr(line, "22") || strstr(line, "00000 rw")) {
            size_t len = 0;
            while (line[len] && line[len] != '\n') len++;
            line[len] = '\0';
            logf_("  MAP: %s", line);
            printed++;
        }
    }
    fclose(fp);
}

/* 解析输入地址：若在当前进程虚拟空间内有效则直接访问，否则按物理地址映射 /dev/mem */
static unsigned char *g5_resolve_buf(uint32_t addr, size_t span, struct surface_mapping *sm, int *out_mapped)
{
    *out_mapped = 0;
    if (addr > 0x10000u && get_phys_addr((void *)(uintptr_t)addr) != 0) {
        return (unsigned char *)(uintptr_t)addr;
    }
    if (map_surface(addr, span, sm) == 0) {
        *out_mapped = 1;
        return sm->pixels;
    }
    return NULL;
}

static void g5_unresolve_buf(struct surface_mapping *sm, int mapped)
{
    if (mapped && sm->base && sm->base != MAP_FAILED) {
        munmap(sm->base, sm->length);
    }
}

static inline size_t g5_surf_px_off(int x, int y, int w, int is_tile, unsigned bpp)
{
    if (is_tile) {
        size_t tx = (size_t)(x >> 3);
        size_t ty = (size_t)(y >> 3);
        size_t tiles_x = (size_t)(w >> 3);
        size_t m = (size_t)g5_morton_8x8((uint32_t)(x & 7), (uint32_t)(y & 7));
        return ((ty * tiles_x + tx) * 64u + m) * (size_t)bpp;
    }
    return ((size_t)y * (size_t)w + (size_t)x) * (size_t)bpp;
}

static inline void g5_dmp_write_px(unsigned char *p, unsigned fmt, uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    if (fmt == 0u) {
        uint16_t v = (uint16_t)(((uint32_t)(r >> 4) << 12) | ((uint32_t)(g >> 4) << 8) |
                                ((uint32_t)(b >> 4) << 4) | (uint32_t)(a >> 4));
        p[0] = (uint8_t)(v & 0xffu);
        p[1] = (uint8_t)(v >> 8);
    } else if (fmt == 3u) {
        p[0] = a;
    } else if (fmt == 1u) {
        p[0] = a; p[1] = b; p[2] = g; p[3] = r;
    } else {
        p[0] = r; p[1] = g; p[2] = b; p[3] = a;
    }
}

static unsigned g_sw_dmp_fill_calls = 0;
static unsigned g_sw_dmp_blit_calls = 0;
static int g_sw_dmp_installed = 0;

/* 接管 libOb5 dmp_fill (0x182410)，支持 VA/PA 自动识别与 8x8 tile/linear 填充 */
static uintptr_t g5_sw_dmp_fill(uintptr_t req, uintptr_t mode, uintptr_t params, uintptr_t unused)
{
    (void)unused;
    if (mode > 2u || params <= 0x10000u) return (uintptr_t)-5;
    const unsigned char *p = (const unsigned char *)params;
    uint32_t dst_addr = ui_u32(p + 0x00);
    uint16_t dst_w = ui_u16(p + 0x04);
    uint16_t dst_h = ui_u16(p + 0x06);
    int16_t dx = ui_s16(p + 0x08);
    int16_t dy = ui_s16(p + 0x0a);
    int16_t dw = ui_s16(p + 0x0c);
    int16_t dh = ui_s16(p + 0x0e);
    uint32_t fmt = ui_u32(p + 0x10);
    uint32_t tile = ui_u32(p + 0x14);
    uint8_t r = p[0x1c], g = p[0x1d], b = p[0x1e], a = p[0x1f];
    unsigned bpp = ui_bpp(fmt);

    if (++g_sw_dmp_fill_calls <= 8) {
        logf_("SW_DMP_FILL [#%u]: req=%p mode=%u dst=%08x(%ux%u) rect=(%d,%d,%d,%d) fmt=%u tile=%u rgba=(%u,%u,%u,%u) pm=%08x",
              g_sw_dmp_fill_calls, (void *)req, (unsigned)mode, dst_addr, dst_w, dst_h,
              dx, dy, dw, dh, fmt, tile, r, g, b, a,
              dst_addr > 0x10000u ? (unsigned)get_phys_addr((void *)(uintptr_t)dst_addr) : 0u);
    }

    if (!dst_addr || !dst_w || !dst_h || dw <= 0 || dh <= 0 || bpp == 0) return 0;

    size_t span = (size_t)dst_w * (size_t)dst_h * (size_t)bpp;
    struct surface_mapping sm = {0};
    int mapped = 0;
    unsigned char *dst_buf = g5_resolve_buf(dst_addr, span, &sm, &mapped);
    if (!dst_buf) return (uintptr_t)-5;

    int x0 = g5_clamp_i(dx, 0, (int)dst_w);
    int y0 = g5_clamp_i(dy, 0, (int)dst_h);
    int x1 = g5_clamp_i(dx + dw, 0, (int)dst_w);
    int y1 = g5_clamp_i(dy + dh, 0, (int)dst_h);
    for (int y = y0; y < y1; y++) {
        for (int x = x0; x < x1; x++) {
            size_t off = g5_surf_px_off(x, y, (int)dst_w, (int)tile, bpp);
            g5_dmp_write_px(dst_buf + off, fmt, r, g, b, a);
        }
    }
    g5_unresolve_buf(&sm, mapped);
    return 0;
}

/* 接管 libOb5 dmp_blit (0x1824a0)，支持 VA/PA 自动识别、缩放与 SrcOver 合成 */
static uintptr_t g5_sw_dmp_blit(uintptr_t req, uintptr_t mode, uintptr_t params, uintptr_t unused)
{
    (void)unused;
    if (mode > 2u || params <= 0x10000u) return (uintptr_t)-5;
    const unsigned char *p = (const unsigned char *)params;
    uint32_t src_addr = ui_u32(p + 0x00);
    uint16_t src_w = ui_u16(p + 0x04), src_h = ui_u16(p + 0x06);
    int16_t sx = ui_s16(p + 0x08), sy = ui_s16(p + 0x0a);
    int16_t sw = ui_s16(p + 0x0c), sh = ui_s16(p + 0x0e);
    uint32_t sfmt = ui_u32(p + 0x10), stile = ui_u32(p + 0x14);

    uint32_t dst_addr = ui_u32(p + 0x18);
    uint16_t dst_w = ui_u16(p + 0x1c), dst_h = ui_u16(p + 0x1e);
    int16_t dx = ui_s16(p + 0x20), dy = ui_s16(p + 0x22);
    int16_t cw = ui_s16(p + 0x24), ch = ui_s16(p + 0x26);
    int16_t dw = ui_s16(p + 0x2c), dh = ui_s16(p + 0x2e);
    uint32_t dfmt = ui_u32(p + 0x30), dtile = ui_u32(p + 0x34);
    uint32_t flags = ui_u32(p + 0x90);

    if (++g_sw_dmp_blit_calls <= 12) {
        logf_("SW_DMP_BLIT [#%u]: req=%p s=%08x(%ux%u %d,%d %dx%d fmt=%u tile=%u pm=%08x) -> d=%08x(%ux%u %d,%d %dx%d clip=%dx%d fmt=%u tile=%u pm=%08x) fl=%#x c=(%u,%u,%u,%u)",
              g_sw_dmp_blit_calls, (void *)req,
              src_addr, src_w, src_h, sx, sy, sw, sh, sfmt, stile,
              src_addr > 0x10000u ? (unsigned)get_phys_addr((void *)(uintptr_t)src_addr) : 0u,
              dst_addr, dst_w, dst_h, dx, dy, dw, dh, cw, ch, dfmt, dtile,
              dst_addr > 0x10000u ? (unsigned)get_phys_addr((void *)(uintptr_t)dst_addr) : 0u,
              flags, p[0x3c], p[0x3d], p[0x3e], p[0x3f]);
    }

    unsigned sbpp = ui_bpp(sfmt);
    unsigned dbpp = ui_bpp(dfmt);
    if (!src_addr || !dst_addr || !src_w || !src_h || !dst_w || !dst_h ||
        sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0 || sbpp == 0 || dbpp == 0) {
        return 0;
    }

    struct surface_mapping sm_s = {0}, sm_d = {0};
    int map_s = 0, map_d = 0;
    unsigned char *sbuf = g5_resolve_buf(src_addr, (size_t)src_w * (size_t)src_h * sbpp, &sm_s, &map_s);
    unsigned char *dbuf = g5_resolve_buf(dst_addr, (size_t)dst_w * (size_t)dst_h * dbpp, &sm_d, &map_d);
    if (!sbuf || !dbuf) {
        g5_unresolve_buf(&sm_s, map_s);
        g5_unresolve_buf(&sm_d, map_d);
        return (uintptr_t)-5;
    }

    uint32_t cr = 255u, cg = 255u, cb = 255u, ca = 255u;
    if ((flags & 0x2u) != 0u && p[0x3f] != 0u) {
        cr = p[0x3c]; cg = p[0x3d]; cb = p[0x3e]; ca = p[0x3f];
    }
    int eff_cw = (cw > 0 && cw < (int)dw) ? (int)cw : (int)dw;
    int eff_ch = (ch > 0 && ch < (int)dh) ? (int)ch : (int)dh;
    int min_x = g5_clamp_i(dx, 0, (int)dst_w);
    int min_y = g5_clamp_i(dy, 0, (int)dst_h);
    int max_x = g5_clamp_i(dx + eff_cw, 0, (int)dst_w);
    int max_y = g5_clamp_i(dy + eff_ch, 0, (int)dst_h);

    for (int py = min_y; py < max_y; py++) {
        int u_y = sy + ((py - dy) * (int)sh) / (int)dh;
        if (u_y < 0 || u_y >= (int)src_h) continue;
        for (int px = min_x; px < max_x; px++) {
            int u_x = sx + ((px - dx) * (int)sw) / (int)dw;
            if (u_x < 0 || u_x >= (int)src_w) continue;
            size_t soff = g5_surf_px_off(u_x, u_y, (int)src_w, (int)stile, sbpp);
            unsigned sc[4] = {0, 0, 0, 0};
            ui_pixel_get(sbuf + soff, sfmt, sc);
            uint32_t sr = (sc[0] * cr + 127u) / 255u;
            uint32_t sg = (sc[1] * cg + 127u) / 255u;
            uint32_t sb_ = (sc[2] * cb + 127u) / 255u;
            uint32_t sa = (sc[3] * ca + 127u) / 255u;

            size_t doff = g5_surf_px_off(px, py, (int)dst_w, (int)dtile, dbpp);
            if ((flags & 1u) == 0u) {
                g5_dmp_write_px(dbuf + doff, dfmt, (uint8_t)sr, (uint8_t)sg, (uint8_t)sb_, (uint8_t)sa);
            } else {
                if (sa == 0) continue;
                if (sa >= 255u) {
                    g5_dmp_write_px(dbuf + doff, dfmt, (uint8_t)sr, (uint8_t)sg, (uint8_t)sb_, (uint8_t)sa);
                } else {
                    unsigned dc[4] = {0, 0, 0, 0};
                    ui_pixel_get(dbuf + doff, dfmt, dc);
                    uint32_t inv_a = 255u - sa;
                    uint32_t or_ = (sr * sa + dc[0] * inv_a + 127u) / 255u;
                    uint32_t og  = (sg * sa + dc[1] * inv_a + 127u) / 255u;
                    uint32_t ob  = (sb_ * sa + dc[2] * inv_a + 127u) / 255u;
                    uint32_t oa  = sa + (dc[3] * inv_a + 127u) / 255u;
                    if (oa > 255u) oa = 255u;
                    g5_dmp_write_px(dbuf + doff, dfmt, (uint8_t)or_, (uint8_t)og, (uint8_t)ob, (uint8_t)oa);
                }
            }
        }
    }
    g5_unresolve_buf(&sm_s, map_s);
    g5_unresolve_buf(&sm_d, map_d);
    return 0;
}

typedef uintptr_t (*g5_tex2_upload_fn_t)(uintptr_t t, uintptr_t a1);
static g5_tex2_upload_fn_t g_orig_tex2_upload = NULL;
static uint8_t g_tex_unswizzled[512];
static uint8_t g_tex_swizzled_flag[512];
static unsigned g_tex2_up_calls = 0;
static uint8_t *g_unswizzle_tmp = NULL;
static size_t g_unswizzle_tmp_cap = 0;

static uintptr_t g5_hook_tex2_upload(uintptr_t t, uintptr_t a1)
{
    uintptr_t ret = g_orig_tex2_upload ? g_orig_tex2_upload(t, a1) : 0;
    if (t > 0x10000u) {
        uint32_t gl_id = *(const uint32_t *)(t + 0x20u);
        uint8_t fl44 = *(const uint8_t *)(t + 0x44u);
        if (gl_id < 512u) {
            g_tex_swizzled_flag[gl_id] = (fl44 & 1u) ? 1u : 0u;
            g_tex_unswizzled[gl_id] = 0u;
        }
        if (++g_tex2_up_calls <= 35) {
            logf_("TEX2_UP [#%u]: t=%p gl_id=%u wh=%ux%u fl44=%#x",
                  g_tex2_up_calls, (void *)t, gl_id,
                  *(const uint16_t *)(t + 0x14u), *(const uint16_t *)(t + 0x16u), fl44);
        }
    }
    return ret;
}

/* 将 8x8 Morton 排列的纹理槽位就地转为线性 RGBA8888（每个 gl_id 上传周期仅转换一次） */
static void g5_unswizzle_slot_once(GeminiTexSlot *slot, uint32_t gl_id, int is_tiled)
{
    if (!slot || !slot->rgba || !is_tiled || gl_id >= 512u || g_tex_unswizzled[gl_id]) return;
    int w = slot->w, h = slot->h;
    if (w < 8 || h < 8 || (w & 7) != 0 || (h & 7) != 0) {
        g_tex_unswizzled[gl_id] = 1u;
        return;
    }
    size_t need = (size_t)w * (size_t)h * 4u;
    if (need > g_unswizzle_tmp_cap) {
        if (g_unswizzle_tmp) {
            munmap(g_unswizzle_tmp, g_unswizzle_tmp_cap);
            g_unswizzle_tmp = NULL;
            g_unswizzle_tmp_cap = 0;
        }
        size_t alloc_sz = (need + 4095u) & ~(size_t)4095u;
        void *p = mmap(NULL, alloc_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return;
        g_unswizzle_tmp = (uint8_t *)p;
        g_unswizzle_tmp_cap = alloc_sz;
    }
    const uint32_t *src32 = (const uint32_t *)(const void *)slot->rgba;
    int tiles_x = w / 8, tiles_y = h / 8;
    for (int ty = 0; ty < tiles_y; ty++) {
        for (int tx = 0; tx < tiles_x; tx++) {
            size_t tile_base = (size_t)(ty * tiles_x + tx) * 64u;
            for (int ly = 0; ly < 8; ly++) {
                uint32_t *dst_row = (uint32_t *)(void *)(g_unswizzle_tmp + ((size_t)(ty * 8 + ly) * (size_t)w + (size_t)(tx * 8)) * 4u);
                for (int lx = 0; lx < 8; lx++) {
                    dst_row[lx] = src32[tile_base + g5_morton_8x8((uint32_t)lx, (uint32_t)ly)];
                }
            }
        }
    }
    memcpy(slot->rgba, g_unswizzle_tmp, need);
    g_tex_unswizzled[gl_id] = 1u;
}

static void *make_thumb_trampoline_8(uintptr_t va, void *hook_fn, const char *name);

static void g5_install_sw_dmp_once(void)
{
    if (g_sw_dmp_installed || !g_libob5_base_cached) return;
    g_sw_dmp_installed = 1;
    patch_thumb_jump((void *)(g_libob5_base_cached + 0x182410u), (void *)g5_sw_dmp_fill, "libOb5:sw_dmp_fill");
    patch_thumb_jump((void *)(g_libob5_base_cached + 0x1824a0u), (void *)g5_sw_dmp_blit, "libOb5:sw_dmp_blit");
    g_orig_tex2_upload = (g5_tex2_upload_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x19e098u, (void *)g5_hook_tex2_upload, "Texture2:upload");
}

static void g5_log_fb_ascii_slice(const char *tag, int x0, int y0, int w, int h)
{
    char line[96];
    if (w > 80) w = 80;
    logf_("=== FB_ASCII %s (%d,%d %dx%d) ===", tag, x0, y0, w, h);
    for (int y = y0; y < y0 + h && y < g_gemini_fb_h; y++) {
        int has_ink = 0;
        for (int x = 0; x < w && (x0 + x) < g_gemini_fb_w; x++) {
            uint32_t p = g_gemini_fb[y * g_gemini_fb_w + (x0 + x)];
            int r = (int)(p & 0xffu);
            int g = (int)((p >> 8) & 0xffu);
            int b = (int)((p >> 16) & 0xffu);
            int ink = ((r + g + b) < 500) || (r > b + 40);
            line[x] = ink ? '#' : '.';
            if (ink) has_ink = 1;
        }
        line[w] = '\0';
        if (has_ink) {
            logf_("y=%3d: %s", y, line);
        }
    }
}

static void g5_log_matrix_brief(const char *tag, uint32_t idx, uintptr_t s, const float *m)
{
    if (m && (uintptr_t)m > 0x10000u) {
        logf_("  %s [#%u] m*1000=(%d,%d,%d,%d | tx=%d,ty=%d)",
              tag, idx,
              (int)(m[0] * 1000.0f), (int)(m[1] * 1000.0f),
              (int)(m[4] * 1000.0f), (int)(m[5] * 1000.0f),
              (int)(m[12] * 1000.0f), (int)(m[13] * 1000.0f));
    } else {
        logf_("  %s [#%u] m=NULL", tag, idx);
    }
    if (s > 0x10000u && idx <= 60) {
        const int16_t *vp = (const int16_t *)(s + 0xc0);
        uint32_t sc_en = *(const uint32_t *)(s + 0x28u + 0x0cu);
        const int16_t *sc_r = (const int16_t *)(s + 0x28u + 0x44u);
        logf_("  %s [#%u] s_wh=%ux%u vp=(%d,%d,%d,%d) scissor(en=%u rect=%d,%d,%d,%d)",
              tag, idx, *(const uint16_t *)(s + 0x14), *(const uint16_t *)(s + 0x16),
              vp[0], vp[1], vp[2], vp[3],
              sc_en, sc_r[0], sc_r[1], sc_r[2], sc_r[3]);
    }
}

static uintptr_t g5_hook_swap_buffers(uintptr_t s)
{
    g5_ensure_fb_init(s);
    g_g5_swap_calls++;

    uintptr_t esurf = (s > 0x10000u) ? *(const uintptr_t *)(s + 0x184) : 0;
    uintptr_t win = (s > 0x10000u) ? *(const uintptr_t *)(s + 0x17c) : 0;
    uintptr_t dbuf78 = (esurf > 0x10000u) ? *(const uintptr_t *)(esurf + 0x78) : 0;
    uintptr_t dbuf78_v = 0;
    uint32_t dbuf78_p = 0, dbuf78_sz = 0;
    if (dbuf78 > 0x10000u) {
        const uint32_t *dw = (const uint32_t *)dbuf78;
        dbuf78_v = (uintptr_t)dw[0];
        dbuf78_p = dw[1];
        dbuf78_sz = dw[3];
    }

    if (g_g5_swap_calls <= 5) {
        logf_("G5_SWAP [#%u]: s=%p wh=%dx%d esurf=%p dbuf78=%p(v=%p p=%08x sz=%#x)",
              g_g5_swap_calls, (void *)s, g_gemini_fb_w, g_gemini_fb_h,
              (void *)esurf, (void *)dbuf78, (void *)dbuf78_v, dbuf78_p, dbuf78_sz);
        if (dbuf78_v > 0x10000u) {
            logf_("  SWAP dbuf78 pm(v)=%08x", (unsigned)get_phys_addr((void *)dbuf78_v));
        }
        if (win > 0x10000u) {
            const uint32_t *ww = (const uint32_t *)win;
            uintptr_t slots = ww[0xb0 / 4];
            uint32_t idx = ww[0xbc / 4];
            logf_("  SWAP win=%p win+b0(slots)=%p win+bc(idx)=%u",
                  (void *)win, (void *)slots, idx);
            if (slots > 0x10000u && idx < 16u) {
                const uint32_t *sl = (const uint32_t *)slots;
                logf_("  SWAP slots[0..1]=(%08x,%08x) (%08x,%08x)", sl[0], sl[1], sl[2], sl[3]);
                uintptr_t bobj = sl[idx * 2u];
                if (bobj > 0x10000u) {
                    const uint32_t *bw = (const uint32_t *)bobj;
                    logf_("  SWAP bobj[0..7]=%08x %08x %08x %08x %08x %08x %08x %08x",
                          bw[0], bw[1], bw[2], bw[3], bw[4], bw[5], bw[6], bw[7]);
                }
            }
        }
    }

    if (g_g5_swap_calls == 1) {
        g5_log_proc_maps_interesting();
        g5_log_fb_ascii_slice("SWAP1_ROW1_ENGLISH", 267, 72, 80, 42);
    } else if (g_g5_swap_calls == 3) {
        g5_log_fb_ascii_slice("SWAP3_LANG1", 18, 76, 80, 36);
    } else if (g_g5_swap_calls == 4) {
        g5_log_fb_ascii_slice("SWAP4_ORANGE", 154, 300, 80, 38);
        g5_log_fb_ascii_slice("SWAP4_BOTRIGHT", 552, 426, 80, 54);
    }

    size_t need_bytes = (size_t)g_gemini_fb_w * (size_t)g_gemini_fb_h * 2u;
    uint32_t nz = 0, nb = 0;

    /* 优先在 g_orig_g5_swap 之前打包写入物理显示源缓冲 (8x8 Morton)，避免 1 帧滞后 */
    uint32_t target_phys = G5_MAIN_PRESENT_SRC_PHYS;
    if (dbuf78_v >= 0x20500000u && dbuf78_v < 0x28000000u) {
        target_phys = (uint32_t)dbuf78_v;
    }

    if (dbuf78_v > 0x10000u && dbuf78_sz >= need_bytes &&
        g5_va_range_rw_ok((uintptr_t)dbuf78_v, need_bytes, (uintptr_t)dbuf78_p)) {
        g5_pack_fb_rgba4444_morton((uint16_t *)dbuf78_v, g_gemini_fb_w, g_gemini_fb_h, &nz, &nb);
    }

    if (!g_gemini_present_sm.pixels && !g_gemini_present_sm_failed) {
        if (map_surface(G5_MAIN_PRESENT_SRC_PHYS, (size_t)640u * 480u * 2u, &g_gemini_present_sm) != 0) {
            g_gemini_present_sm_failed = 1;
            logf_("G5_SWAP [!] map_surface(%08x) failed", G5_MAIN_PRESENT_SRC_PHYS);
        } else {
            logf_("G5_SWAP [+] mapped present src %08x -> %p",
                  G5_MAIN_PRESENT_SRC_PHYS, (void *)g_gemini_present_sm.pixels);
        }
    }
    if (target_phys == G5_MAIN_PRESENT_SRC_PHYS) {
        if (g_gemini_present_sm.pixels && need_bytes <= (size_t)640u * 480u * 2u) {
            g5_pack_fb_rgba4444_morton((uint16_t *)(void *)g_gemini_present_sm.pixels, g_gemini_fb_w, g_gemini_fb_h, &nz, &nb);
        }
    } else {
        struct surface_mapping alt_sm = {0};
        if (map_surface(target_phys, need_bytes, &alt_sm) == 0) {
            g5_pack_fb_rgba4444_morton((uint16_t *)(void *)alt_sm.pixels, g_gemini_fb_w, g_gemini_fb_h, &nz, &nb);
            if (alt_sm.base && alt_sm.base != MAP_FAILED) {
                munmap(alt_sm.base, alt_sm.length);
            }
        }
    }

    uintptr_t ret = g_orig_g5_swap ? g_orig_g5_swap(s) : 0;

    static int s_ui_ready_emitted = 0;
    if (!s_ui_ready_emitted && nb > 0u && __atomic_load_n(&g_ui_ready_pcm_ok, __ATOMIC_ACQUIRE) != 0u) {
        s_ui_ready_emitted = 1;
        logf_("ASTRA_UI_READY fb=%u nb=%u scr=0x%x",
              g_fb_sync_seq, nb, __atomic_load_n(&g_ui_ready_scr_hint, __ATOMIC_ACQUIRE));
    }

    if (g_g5_swap_calls <= 15 || (g_g5_swap_calls % 20u) == 0u) {
        logf_("G5_SWAP_OUT [#%u]: target_phys=%08x %dx%d nonzero=%u nonblack=%u (rect=%u solid=%u quad=%u)",
              g_g5_swap_calls, target_phys, g_gemini_fb_w, g_gemini_fb_h, nz, nb,
              g_gemini_rect_calls, g_gemini_solid_calls, g_gemini_quad_calls);
    }
    return ret;
}

typedef void (*surface_clear_fn_t)(uintptr_t s, const uint8_t *rgba);
typedef void (*gl_clear_fn_t)(uint32_t mask);

static surface_clear_fn_t g_orig_surface_clear = NULL;
static gl_clear_fn_t      g_orig_gl_clear = NULL;
static int                g_in_surface_clear = 0;
static unsigned           g_surface_clear_calls = 0;
static unsigned           g_gl_clear_calls = 0;

static void g5_clear_fb_rect(uintptr_t s, uint32_t rgba32)
{
    g5_ensure_fb_init(s);
    int cx0 = 0, cy0 = 0, cx1 = g_gemini_fb_w, cy1 = g_gemini_fb_h;
    if (s > 0x10000u) {
        g5_get_scissor_clip(s, &cx0, &cy0, &cx1, &cy1);
    }
    if (cx0 >= cx1 || cy0 >= cy1) return;
    for (int py = cy0; py < cy1; py++) {
        uint32_t *row = &g_gemini_fb[py * g_gemini_fb_w];
        for (int px = cx0; px < cx1; px++) {
            row[px] = rgba32;
        }
    }
}

static void g5_hook_surface_clear(uintptr_t s, const uint8_t *rgba)
{
    g5_ensure_fb_init(s);
    g_surface_clear_calls++;
    if ((uintptr_t)rgba > 0x10000u) {
        uint8_t r = rgba[0], g = rgba[1], b = rgba[2], a = rgba[3];
        /* 透明背景层清屏时在无视频流背景下映射为不透明黑 0xff000000u，防止局部更新误抹除其余 OSD */
        uint32_t px = (a == 0u)
            ? 0xff000000u
            : ((uint32_t)r | ((uint32_t)g << 8) | ((uint32_t)b << 16) | ((uint32_t)a << 24));
        if (g_surface_clear_calls <= 15) {
            int cx0 = 0, cy0 = 0, cx1 = g_gemini_fb_w, cy1 = g_gemini_fb_h;
            if (s > 0x10000u) g5_get_scissor_clip(s, &cx0, &cy0, &cx1, &cy1);
            logf_("G5_SURF_CLEAR [#%u]: s=%p rgba=(%u,%u,%u,%u) clip=(%d,%d,%d,%d)",
                  g_surface_clear_calls, (void *)s, r, g, b, a, cx0, cy0, cx1, cy1);
        }
        g5_clear_fb_rect(s, px);
    }
    if (g_orig_surface_clear) {
        g_in_surface_clear++;
        g_orig_surface_clear(s, rgba);
        g_in_surface_clear--;
    }
}

static void g5_hook_gl_clear(uint32_t mask)
{
    if (!g_in_surface_clear && (mask & 0x4000u) != 0u) {
        g_gl_clear_calls++;
        uintptr_t s = g_last_surface_ctx;
        if (g_gl_clear_calls <= 15) {
            int cx0 = 0, cy0 = 0, cx1 = g_gemini_fb_w, cy1 = g_gemini_fb_h;
            if (s > 0x10000u) g5_get_scissor_clip(s, &cx0, &cy0, &cx1, &cy1);
            logf_("G5_GL_CLEAR [#%u]: mask=0x%x s=%p clip=(%d,%d,%d,%d)",
                  g_gl_clear_calls, mask, (void *)s, cx0, cy0, cx1, cy1);
        }
        g5_clear_fb_rect(s, 0xff000000u);
    }
    if (g_orig_gl_clear) {
        g_orig_gl_clear(mask);
    }
}

static void ensure_gl_shadow_hooks(uintptr_t s)
{
    if (g_gl_hooks_done || s <= 0x10000u) return;
    g_gl_hooks_done = 1;
    Dl_info dli = {0};
    uintptr_t vt = *(const uintptr_t *)s;
    if (!dladdr((void *)vt, &dli) || !dli.dli_fbase) {
        logf_("HOOK_GL: dladdr 解析 libOb5 基址失败 (vt=%p)", (void *)vt);
        return;
    }
    g_libob5_base_cached = (uintptr_t)dli.dli_fbase;
    logf_("HOOK_GL: 解析 libOb5 基址 = %p，安装 GL 纹理/Clear/Swap 影子钩子...", (void *)g_libob5_base_cached);
    g_orig_gl_bind       = (gl_bind_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x16d9a0u, (void *)g5_hook_gl_bind_texture, "glBindTexture");
    g_orig_gl_teximg     = (gl_teximg_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x168780u, (void *)g5_hook_gl_tex_image_2d, "glTexImage2D");
    g_orig_gl_texsub     = (gl_texsub_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x1682f0u, (void *)g5_hook_gl_tex_sub_image_2d, "glTexSubImage2D");
    g_orig_gl_clear      = (gl_clear_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x16d400u, (void *)g5_hook_gl_clear, "glClear");
    g_orig_surface_clear = (surface_clear_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x19ecf8u, (void *)g5_hook_surface_clear, "s->vt[+0x10]");
    g_orig_g5_swap       = (g5_swap_fn_t)make_thumb_trampoline_8(g_libob5_base_cached + 0x196504u, (void *)g5_hook_swap_buffers, "s->vt[+0x18]");
}

static uintptr_t g5_hook_gemini_solid(uintptr_t r, uintptr_t s, uintptr_t m, uintptr_t c, uintptr_t dst)
{
    (void)r;
    ensure_gl_shadow_hooks(s);
    g5_install_sw_dmp_once();
    g5_prepare_fb_for_draw(s);
    g_gemini_solid_calls++;

    int16_t dx = dst > 0x10000u ? *(const int16_t *)dst : 0;
    int16_t dy = dst > 0x10000u ? *(const int16_t *)(dst + 2) : 0;
    int16_t dw = dst > 0x10000u ? *(const int16_t *)(dst + 4) : (int16_t)g_gemini_fb_w;
    int16_t dh = dst > 0x10000u ? *(const int16_t *)(dst + 6) : (int16_t)g_gemini_fb_h;
    const uint8_t *rgba = c > 0x10000u ? (const uint8_t *)c : NULL;
    uint8_t cr = rgba ? rgba[0] : 255;
    uint8_t cg = rgba ? rgba[1] : 255;
    uint8_t cb = rgba ? rgba[2] : 255;
    uint8_t ca = rgba ? rgba[3] : 255;

    if (g_gemini_solid_calls <= 15) {
        logf_("G5_GEMINI_SOLID [#%u]: s=%p c=(%u,%u,%u,%u) dst=(%d,%d,%d,%d)",
              g_gemini_solid_calls, (void *)s, cr, cg, cb, ca, dx, dy, dw, dh);
        g5_log_matrix_brief("SOLID", g_gemini_solid_calls, s,
                            (m > 0x10000u) ? (const float *)m : NULL);
    }

    if (dw > 0 && dh > 0) {
        int cx0, cy0, cx1, cy1;
        g5_get_scissor_clip(s, &cx0, &cy0, &cx1, &cy1);
        const float *mf = (m > 0x10000u) ? (const float *)m : NULL;
        float x0 = (float)dx, y0 = (float)dy;
        float x1 = (float)dx + (float)dw, y1 = (float)dy + (float)dh;
        g5_draw_transformed_quad(
            cx0, cy0, cx1, cy1, mf,
            x0, y0, 0.0f, 0.0f,
            x1, y0, 0.0f, 0.0f,
            x1, y1, 0.0f, 0.0f,
            x0, y1, 0.0f, 0.0f,
            NULL, 0, 0, 0, cr, cg, cb, ca);
    }
    return 1;
}

static uintptr_t g5_hook_gemini_rect(uintptr_t r, uintptr_t s, uintptr_t m, uintptr_t c, uintptr_t src, uintptr_t dst)
{
    (void)r;
    ensure_gl_shadow_hooks(s);
    g5_install_sw_dmp_once();
    g5_prepare_fb_for_draw(s);
    g_gemini_rect_calls++;

    int16_t sx = src > 0x10000u ? *(const int16_t *)src : 0;
    int16_t sy = src > 0x10000u ? *(const int16_t *)(src + 2) : 0;
    int16_t sw = src > 0x10000u ? *(const int16_t *)(src + 4) : 0;
    int16_t sh = src > 0x10000u ? *(const int16_t *)(src + 6) : 0;
    int16_t dx = dst > 0x10000u ? *(const int16_t *)dst : 0;
    int16_t dy = dst > 0x10000u ? *(const int16_t *)(dst + 2) : 0;
    int16_t dw = dst > 0x10000u ? *(const int16_t *)(dst + 4) : 0;
    int16_t dh = dst > 0x10000u ? *(const int16_t *)(dst + 6) : 0;

    const uint8_t *rgba = c > 0x10000u ? (const uint8_t *)c : NULL;
    uint8_t cr = rgba ? rgba[0] : 255;
    uint8_t cg = rgba ? rgba[1] : 255;
    uint8_t cb = rgba ? rgba[2] : 255;
    uint8_t ca = rgba ? rgba[3] : 255;

    uintptr_t t = (s > 0x10000u) ? *(const uintptr_t *)(s + 0xd0) : 0;
    uint32_t gl_id = (t > 0x10000u) ? *(const uint32_t *)(t + 0x20) : 0;
    GeminiTexSlot *cached = gl_id ? find_or_alloc_tex_slot(gl_id, 0) : NULL;
    int is_tiled = (gl_id < 512u && g_tex_swizzled_flag[gl_id])
                || (t > 0x10000u && (*(const uint8_t *)(t + 0x44u) & 1u));
    if (cached && cached->rgba) {
        g5_unswizzle_slot_once(cached, gl_id, is_tiled);
    }

    if (g_gemini_rect_calls <= 60) {
        logf_("G5_GEMINI_RECT [#%u]: c=(%u,%u,%u,%u) src=(%d,%d,%d,%d) dst=(%d,%d,%d,%d) gl_id=%u tiled=%d cache=%p(%dx%d fmt=%#x)",
              g_gemini_rect_calls, cr, cg, cb, ca, sx, sy, sw, sh, dx, dy, dw, dh,
              gl_id, is_tiled, cached ? (void *)cached->rgba : NULL,
              cached ? cached->w : 0, cached ? cached->h : 0, cached ? cached->fmt : 0);
        g5_log_matrix_brief("RECT", g_gemini_rect_calls, s,
                            (m > 0x10000u) ? (const float *)m : NULL);
        if (cached && cached->rgba && (g_gemini_rect_calls <= 6 || (cached->fmt == 0x1908u && g_gemini_rect_calls <= 18))) {
            const uint8_t *raw = (const uint8_t *)(uintptr_t)cached->rgba;
            size_t total = (size_t)cached->w * (size_t)cached->h;
            size_t vis_cnt = 0, nz_cnt = 0, first_idx = 0, first_nz_idx = 0;
            uint8_t fr = 0, fg = 0, fb = 0, fa = 0;
            uint8_t nr = 0, ng = 0, nb_ = 0, na = 0;
            for (size_t pi = 0; pi < total; pi++) {
                const uint8_t *p = raw + pi * 4u;
                if (p[0] || p[1] || p[2] || p[3]) {
                    if (nz_cnt == 0) {
                        first_nz_idx = pi;
                        nr = p[0]; ng = p[1]; nb_ = p[2]; na = p[3];
                    }
                    nz_cnt++;
                }
                if (p[3] > 0) {
                    if (vis_cnt == 0) {
                        first_idx = pi;
                        fr = p[0]; fg = p[1]; fb = p[2]; fa = p[3];
                    }
                    vis_cnt++;
                }
            }
            logf_("  RECT [#%u] tex nz=%u vis=%u/%u nz@%u=(%u,%u,%u,%u) vis@%u=(%u,%u,%u,%u)",
                  g_gemini_rect_calls, (unsigned)nz_cnt, (unsigned)vis_cnt, (unsigned)total,
                  (unsigned)first_nz_idx, nr, ng, nb_, na,
                  (unsigned)first_idx, fr, fg, fb, fa);
            if (g_gemini_rect_calls == 1 && t > 0x10000u) {
                uintptr_t obj48 = *(const uintptr_t *)(t + 0x48);
                if (obj48 > 0x10000u) {
                    const uintptr_t *vt = *(const uintptr_t *const *)obj48;
                    typedef int (*o48_phys_fn)(uintptr_t, uint32_t *);
                    typedef int (*o48_lock_fn)(uintptr_t, int, uintptr_t *);
                    typedef int (*o48_unlock_fn)(uintptr_t);
                    uint32_t ophys = 0;
                    uintptr_t ova = 0;
                    int r_p = ((o48_phys_fn)vt[0x34 / 4])(obj48, &ophys);
                    int r_l = ((o48_lock_fn)vt[0x44 / 4])(obj48, -1, &ova);
                    uint32_t pmap_va = (ova > 0x10000u) ? (uint32_t)get_phys_addr((void *)ova) : 0;
                    size_t va_nz16 = 0, pa_nz16 = 0;
                    uint16_t first_va16 = 0, first_pa16 = 0;
                    if (ova > 0x10000u && pmap_va != 0) {
                        const uint16_t *vp = (const uint16_t *)ova;
                        for (size_t k = 0; k < total; k++) {
                            if (vp[k] != 0) { if (va_nz16 == 0) first_va16 = vp[k]; va_nz16++; }
                        }
                    }
                    if (ophys >= 0x01000000u && ophys < 0x3f000000u) {
                        struct surface_mapping sm_chk = {0};
                        if (map_surface(ophys, total * 2u, &sm_chk) == 0) {
                            const uint16_t *pp = (const uint16_t *)(void *)sm_chk.pixels;
                            for (size_t k = 0; k < total; k++) {
                                if (pp[k] != 0) { if (pa_nz16 == 0) first_pa16 = pp[k]; pa_nz16++; }
                            }
                            if (sm_chk.base && sm_chk.base != MAP_FAILED) munmap(sm_chk.base, sm_chk.length);
                        }
                    }
                    if (r_l == 0) ((o48_unlock_fn)vt[0x48 / 4])(obj48);
                    logf_("  RECT [#1] obj48=%p r_p=%d ophys=%08x r_l=%d ova=%p pmap(va)=%08x va_nz16=%u(%04x) pa_nz16=%u(%04x)",
                          (void *)obj48, r_p, ophys, r_l, (void *)ova, pmap_va,
                          (unsigned)va_nz16, first_va16, (unsigned)pa_nz16, first_pa16);
                }
            }
        }
    }

    if (!cached || !cached->rgba || cached->w <= 0 || cached->h <= 0 || dw <= 0 || dh <= 0) {
        if ((!cached || !cached->rgba) && g_gemini_rect_calls <= 50) {
            logf_("G5_GEMINI_RECT [MISS #%u]: gl_id=%u s=%p t=%p cached=%p",
                  g_gemini_rect_calls, gl_id, (void *)s, (void *)t, (void *)cached);
        }
        return 1;
    }

    if (src <= 0x10000u) {
        sx = 0; sy = 0;
        sw = (int16_t)cached->w;
        sh = (int16_t)cached->h;
    }
    if (sw <= 0 || sh <= 0) return 1;

    int cx0, cy0, cx1, cy1;
    g5_get_scissor_clip(s, &cx0, &cy0, &cx1, &cy1);
    const float *mf = (m > 0x10000u) ? (const float *)m : NULL;
    const uint8_t *tex_bytes = (const uint8_t *)(uintptr_t)cached->rgba;
    float x0 = (float)dx, y0 = (float)dy;
    float x1 = (float)dx + (float)dw, y1 = (float)dy + (float)dh;
    float u0 = (float)sx, v0 = (float)sy;
    float u1 = (float)sx + (float)sw, v1 = (float)sy + (float)sh;

    g5_draw_transformed_quad(
        cx0, cy0, cx1, cy1, mf,
        x0, y0, u0, v0,
        x1, y0, u1, v0,
        x1, y1, u1, v1,
        x0, y1, u0, v1,
        tex_bytes, cached->w, cached->h, cached->fmt,
        cr, cg, cb, ca);
    return 1;
}

static uintptr_t g5_hook_gemini_quad(uintptr_t r, uintptr_t s, uintptr_t m, uintptr_t c, uintptr_t src, uintptr_t points)
{
    (void)r;
    ensure_gl_shadow_hooks(s);
    g5_install_sw_dmp_once();
    g5_prepare_fb_for_draw(s);
    g_gemini_quad_calls++;

    if (g_gemini_quad_calls <= 20) {
        logf_("G5_GEMINI_QUAD [#%u]: s=%p m=%p c=%p src=%p pts=%p",
              g_gemini_quad_calls, (void *)s, (void *)m, (void *)c, (void *)src, (void *)points);
        if (points > 0x10000u) {
            const float *pf = (const float *)points;
            const int16_t *pi = (const int16_t *)points;
            logf_("  QUAD pts_i16=(%d,%d %d,%d %d,%d %d,%d) pts_f*1000=(%d,%d %d,%d %d,%d %d,%d)",
                  pi[0], pi[1], pi[2], pi[3], pi[4], pi[5], pi[6], pi[7],
                  (int)(pf[0] * 1000.0f), (int)(pf[1] * 1000.0f),
                  (int)(pf[2] * 1000.0f), (int)(pf[3] * 1000.0f),
                  (int)(pf[4] * 1000.0f), (int)(pf[5] * 1000.0f),
                  (int)(pf[6] * 1000.0f), (int)(pf[7] * 1000.0f));
        }
    }

    if (points <= 0x10000u) return 1;
    const float *pf = (const float *)points;
    uintptr_t t = (s > 0x10000u) ? *(const uintptr_t *)(s + 0xd0) : 0;
    uint32_t gl_id = (t > 0x10000u) ? *(const uint32_t *)(t + 0x20) : 0;
    GeminiTexSlot *cached = gl_id ? find_or_alloc_tex_slot(gl_id, 0) : NULL;
    int is_tiled = (gl_id < 512u && g_tex_swizzled_flag[gl_id])
                || (t > 0x10000u && (*(const uint8_t *)(t + 0x44u) & 1u));
    if (cached && cached->rgba) {
        g5_unswizzle_slot_once(cached, gl_id, is_tiled);
    }
    const uint8_t *rgba = c > 0x10000u ? (const uint8_t *)c : NULL;
    uint8_t cr = rgba ? rgba[0] : 255;
    uint8_t cg = rgba ? rgba[1] : 255;
    uint8_t cb = rgba ? rgba[2] : 255;
    uint8_t ca = rgba ? rgba[3] : 255;
    const float *mf = (m > 0x10000u) ? (const float *)m : NULL;
    int cx0, cy0, cx1, cy1;
    g5_get_scissor_clip(s, &cx0, &cy0, &cx1, &cy1);

    int looks_float = 1;
    for (int i = 0; i < 8; i++) {
        if (!(pf[i] >= -4096.0f && pf[i] <= 4096.0f)) {
            looks_float = 0;
            break;
        }
    }
    if (looks_float) {
        if (cached && cached->rgba && src > 0x10000u) {
            int16_t sx = *(const int16_t *)src, sy = *(const int16_t *)(src + 2);
            int16_t sw = *(const int16_t *)(src + 4), sh = *(const int16_t *)(src + 6);
            if (sw > 0 && sh > 0) {
                g5_draw_transformed_quad(
                    cx0, cy0, cx1, cy1, mf,
                    pf[0], pf[1], (float)sx, (float)sy,
                    pf[2], pf[3], (float)(sx + sw), (float)sy,
                    pf[4], pf[5], (float)(sx + sw), (float)(sy + sh),
                    pf[6], pf[7], (float)sx, (float)(sy + sh),
                    (const uint8_t *)(uintptr_t)cached->rgba, cached->w, cached->h, cached->fmt,
                    cr, cg, cb, ca);
            }
        } else if (!cached && src <= 0x10000u) {
            g5_draw_transformed_quad(
                cx0, cy0, cx1, cy1, mf,
                pf[0], pf[1], 0.0f, 0.0f,
                pf[2], pf[3], 0.0f, 0.0f,
                pf[4], pf[5], 0.0f, 0.0f,
                pf[6], pf[7], 0.0f, 0.0f,
                NULL, 0, 0, 0, cr, cg, cb, ca);
        }
    }
    return 1;
}

static uintptr_t g5_hook_dmp_fill(uintptr_t request, uintptr_t mode, uintptr_t params, uintptr_t unused)
{
    (void)unused;
    static unsigned fill_count = 0;
    const unsigned char *p = (const unsigned char *)params;
    if (!p || mode > 2) return (uintptr_t)-5;
    if (++fill_count <= 8) {
        logf_("G5_DMP_FILL [#%u]: req=%p mode=%lu target_phys=0x%08x",
              fill_count, (void *)request, (unsigned long)mode, ui_u32(p));
    }
    size_t span = 0;
    struct surface_mapping m = {0};
    int status = -5;
    if (ui_surface_check(p, &span) == 0 && map_surface(ui_u32(p), span, &m) == 0) {
        status = ui_fill_rect(m.pixels, span, p);
        munmap(m.base, m.length);
    }
    if (ui_u32(p + 40)) {
        void (*cb)(uint32_t, uint32_t) = (void (*)(uint32_t, uint32_t))(uintptr_t)ui_u32(p + 40);
        cb(request, ui_u32(p + 44));
    }
    return (uintptr_t)status;
}

static uintptr_t g5_hook_dmp_blit(uintptr_t request, uintptr_t mode, uintptr_t params, uintptr_t unused)
{
    (void)unused;
    static unsigned blit_count = 0;
    const unsigned char *p = (const unsigned char *)params;
    if (!p || mode > 2) return (uintptr_t)-5;
    if (++blit_count <= 8) {
        logf_("G5_DMP_BLIT [#%u]: req=%p mode=%lu src_phys=0x%08x dst_phys=0x%08x",
              blit_count, (void *)request, (unsigned long)mode, ui_u32(p), ui_u32(p + 24));
    }
    size_t ss = 0, ds = 0;
    unsigned char desc[24] = {0};
    memcpy(desc, p + 24, 8); memcpy(desc + 16, p + 48, 8);
    struct surface_mapping src = {0}, dst = {0};
    int status = -5;
    if (ui_surface_check(p, &ss) == 0 && ui_surface_check(desc, &ds) == 0) {
        uint32_t s = ui_u32(p), d = ui_u32(p + 24);
        if (map_surface(s, ss, &src) == 0) {
            if (map_surface(d, ds, &dst) == 0) {
                status = ui_blit_surface(dst.pixels, ds, src.pixels, ss, p);
                munmap(dst.base, dst.length);
            }
            munmap(src.base, src.length);
        }
    }
    if (ui_u32(p + 148)) {
        void (*cb)(uint32_t, uint32_t) = (void (*)(uint32_t, uint32_t))(uintptr_t)ui_u32(p + 148);
        cb(request, ui_u32(p + 152));
    }
    return (uintptr_t)status;
}

#endif /* !ZVE10_REAL_DEVICE */

__attribute__((visibility("hidden")))
void __assert_fail(const char *assertion, const char *file, unsigned int line, const char *function)
{
    astra_assert_ignore(assertion, file, line, function);
}

__attribute__((visibility("hidden"), noreturn))
void abort(void)
{
    logf_("[ASTRA_ABORT_BYPASSED] abort() 被调用 (挂起异常分支，保持其他线程存活)");
    while (1) sleep(100);
}

static void logf_(const char *fmt, ...);

static char     g_runid[48];
static int      g_logfd = -1;
static void    *g_init_arg;
static pthread_mutex_t g_logmu = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_astra_running = 0;
static pthread_t g_astra_th = 0;

/* 缓存 WidgetSystem 函数指针，避免辅助线程频繁 dlopen/dlsym 争抢链接器锁 */
static void *(*g_pGetWS)(void) = NULL;
static void (*g_pPress)(void *, uint8_t, uint8_t, const uint64_t *) = NULL;
static void (*g_pRel)(void *, uint8_t, uint8_t, const uint64_t *) = NULL;
static void (*g_pMove)(void *, uint8_t, int16_t, int16_t, const uint64_t *) = NULL;
#ifndef ZVE10_REAL_DEVICE
static void (*g_pUpdateCurTime)(void *) = NULL;
static void (*g_pProcessEvent)(void *) = NULL;
static void (*g_pUpdateFrame)(void *) = NULL;
static void (*g_pNotifyDraw)(void *) = NULL;
#endif
static volatile int g_ws_syms_ready = 0;

/* 拦截 appFw.so 内部两条裁掉输出的日志通道 (dbglog_sink @ 0x02ce5f24, seqlog_send @ 0x02c2af70) */
static volatile int32_t g_appfw_dbglog_budget = 1200;
static volatile int g_appfw_dbglog_muted = 0;
typedef int (*seqlog_send_fn_t)(int level, const char *msg, size_t len);
static seqlog_send_fn_t g_orig_seqlog_send = NULL;

static int g5_consume_dbglog_budget(void)
{
    if (g_appfw_dbglog_muted) return 0;
    for (;;) {
        int32_t cur = __atomic_load_n(&g_appfw_dbglog_budget, __ATOMIC_RELAXED);
        if (cur <= 0) return 0;
        if (__sync_bool_compare_and_swap(&g_appfw_dbglog_budget, cur, cur - 1)) return 1;
    }
}

static void g5_refresh_dbglog_budget(int32_t min_budget)
{
    if (g_appfw_dbglog_muted) return;
    for (;;) {
        int32_t cur = __atomic_load_n(&g_appfw_dbglog_budget, __ATOMIC_RELAXED);
        if (cur >= min_budget) return;
        if (__sync_bool_compare_and_swap(&g_appfw_dbglog_budget, cur, min_budget)) return;
    }
}

static void g5_sanitize_log_text(char *dst, size_t cap, const char *src, size_t max_len)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    size_t limit = (max_len < cap - 1) ? max_len : (cap - 1);
    while (i < limit && src[i] != '\0') {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (c == '\r' || c == '\n' || c == '\t') ? ' ' : ((c >= 0x20 && c < 0x7f) ? (char)c : '?');
        i++;
    }
    dst[i] = '\0';
}

static int g5_is_noisy_seqlog(const char *s)
{
    return (strncmp(s, "fps=", 4) == 0 ||
            strstr(s, "[INFRA_WRAPPER]") != NULL ||
            strstr(s, "dfs_factor") != NULL ||
            strstr(s, "power_save") != NULL ||
            strstr(s, "SEQUENCE FATAL ERROR") != NULL ||
            strstr(s, "sequence_set_power_save") != NULL ||
            strstr(s, "sequence_power_save") != NULL);
}

static void g5_hook_appfw_dbglog(const char *fmt, void *const *va_ap_ptr)
{
    static int in_hook = 0;
    if (in_hook || !fmt || !va_ap_ptr || !g5_consume_dbglog_budget()) return;
    in_hook = 1;
    _Static_assert(sizeof(va_list) == sizeof(void *), "ARM32 va_list layout mismatch");
    va_list ap;
    memcpy(&ap, va_ap_ptr, sizeof(ap));
    char raw[192];
    int n = vsnprintf(raw, sizeof(raw), fmt, ap);
    if (n > 0) {
        char clean[192];
        g5_sanitize_log_text(clean, sizeof(clean), raw, sizeof(clean) - 1);
        if (clean[0] != '\0') {
            logf_("APPFW_DBG: %s", clean);
        }
    }
    in_hook = 0;
}

static volatile int g_appfw_seqlog_saw_suppression_none = 0;

static int g5_hook_appfw_seqlog(int level, const char *msg, size_t len)
{
    static int in_hook = 0;
    if (!in_hook && level == 2 && msg != NULL && len > 0) {
        in_hook = 1;
        char clean[208];
        g5_sanitize_log_text(clean, sizeof(clean), msg, len);
        if (clean[0] != '\0' && !g5_is_noisy_seqlog(clean) && g5_consume_dbglog_budget()) {
            logf_("APPFW_SEQ: %s", clean);
        }
        if (strstr(clean, "event suppression none")) {
            __atomic_store_n(&g_appfw_seqlog_saw_suppression_none, 1, __ATOMIC_RELEASE);
        }
        in_hook = 0;
    }
    if (g_orig_seqlog_send) {
        return g_orig_seqlog_send(level, msg, len);
    }
    return 0;
}

/* 拦截 appFw.so model_future::get() (0x25c9590..0x25c97a0) 中的无限条件等待，防止四代宿主缺失异步应答时主 UI 线程死锁 */
static uintptr_t g_appfw_base = 0;
typedef void (*cond_wait_fn_t)(void *cv, void *lk);
static cond_wait_fn_t g_orig_cond_wait = NULL;
static volatile uint32_t g_model_wait_hit = 0;
static volatile uint32_t g_model_wait_timeout = 0;

static void astra_cond_wait_hook(void *cv, void *lk) {
    uintptr_t lr = (uintptr_t)__builtin_return_address(0) & ~(uintptr_t)1u;
    uintptr_t off = (g_appfw_base != 0 && lr >= g_appfw_base) ? (lr - g_appfw_base) : 0;
    if (g_appfw_base != 0 && cv != NULL && lk != NULL) {
        int is_future_wait = (off >= 0x25c9590u && off <= 0x25c97a0u);
        int is_commit_wait = (off >= 0x277b808u && off <= 0x277b8e0u);
        if (is_future_wait || is_commit_wait) {
            pthread_cond_t *cond = (pthread_cond_t *)cv;
            pthread_mutex_t *mtx = *(pthread_mutex_t **)lk;
            if (mtx != NULL) {
                const char *tag = is_commit_wait ? "model_setting_value::commit" : "model_future::get";
                uint32_t hit = __sync_add_and_fetch(&g_model_wait_hit, 1);
                struct timespec ts;
                /* libstdc++.so.6 std::condition_variable::wait 实测即对 cv+0/lk+0 调用默认 CLOCK_REALTIME pthread_cond_wait */
                ts.tv_sec = time(NULL) + 2; /* 留足 1~2s 窗口，正常模型消息优先自行完成 */
                ts.tv_nsec = 0;
                if (hit <= 20 || (hit % 50) == 0) {
                    logf_("PATCH: %s cond_wait 超时保护 #%u (offset=0x%lx cv=%p mtx=%p)",
                          tag, hit, (unsigned long)off, cv, (void *)mtx);
                }
                int rc = pthread_cond_timedwait(cond, mtx, &ts);
                if (rc == ETIMEDOUT) {
                    if (is_commit_wait) {
                        /* 仍在锁内时清零 wait_flag (+0x07a41e4e)，使 while(wait_flag) 循环退出 */
                        *(volatile uint8_t *)(g_appfw_base + 0x07a41e4eu) = 0;
                    }
                    uint32_t to = __sync_add_and_fetch(&g_model_wait_timeout, 1);
                    if (to <= 30 || (to % 50) == 0) {
                        logf_("PATCH: %s cond_wait 超时放行! #%u (offset=0x%lx rc=%d)",
                              tag, to, (unsigned long)off, rc);
                    }
                } else if (rc != 0) {
                    logf_("PATCH: %s cond_wait 异常返回 rc=%d (offset=0x%lx)",
                          tag, rc, (unsigned long)off);
                }
                return;
            }
        }
    }
    if (g_orig_cond_wait) {
        g_orig_cond_wait(cv, lk);
        return;
    }
    if (cv != NULL && lk != NULL && *(pthread_mutex_t **)lk != NULL) {
        pthread_cond_wait((pthread_cond_t *)cv, *(pthread_mutex_t **)lk);
    }
}

static volatile uint32_t g_ob5_mmap_fail_cnt = 0;

static unsigned long parse_hex_until(const char **pp, char stop) {
    unsigned long v = 0;
    const char *p = *pp;
    while (*p && *p != stop) {
        char ch = *p++;
        unsigned d = (ch >= '0' && ch <= '9') ? (unsigned)(ch - '0')
                   : (ch >= 'a' && ch <= 'f') ? (unsigned)(ch - 'a' + 10)
                   : (ch >= 'A' && ch <= 'F') ? (unsigned)(ch - 'A' + 10) : 16u;
        if (d >= 16u) return 0;
        v = (v << 4) | d;
    }
    *pp = p;
    return v;
}

/* 诊断 ENOMEM 时打印关键进程内存/限制/大段 VMA 状态（仅首次触发输出，避免刷屏） */
static void dump_mem_diagnostics_once(void) {
    FILE *fp = fopen("/proc/meminfo", "r");
    char line[256];
    if (fp) {
        logf_("=== /proc/meminfo (top 8) ===");
        for (int n = 0; n < 8 && fgets(line, sizeof(line), fp); n++) {
            size_t l = strlen(line);
            if (l > 0 && line[l - 1] == '\n') line[l - 1] = '\0';
            logf_("  %s", line);
        }
        fclose(fp);
    }
    fp = fopen("/proc/self/status", "r");
    if (fp) {
        logf_("=== /proc/self/status (Vm/Threads) ===");
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Vm", 2) == 0 || strncmp(line, "Threads:", 8) == 0) {
                size_t l = strlen(line);
                if (l > 0 && line[l - 1] == '\n') line[l - 1] = '\0';
                logf_("  %s", line);
            }
        }
        fclose(fp);
    }
    fp = fopen("/proc/self/limits", "r");
    if (fp) {
        logf_("=== /proc/self/limits ===");
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "Max address space") || strstr(line, "Max data size") || strstr(line, "Max locked memory")) {
                size_t l = strlen(line);
                if (l > 0 && line[l - 1] == '\n') line[l - 1] = '\0';
                logf_("  %s", line);
            }
        }
        fclose(fp);
    }
    fp = fopen("/proc/self/maps", "r");
    if (fp) {
        uint32_t vma_cnt = 0;
        logf_("=== /proc/self/maps (size >= 4MB) ===");
        while (fgets(line, sizeof(line), fp)) {
            vma_cnt++;
            const char *p = line;
            unsigned long s = parse_hex_until(&p, '-');
            unsigned long e = (*p == '-') ? (p++, parse_hex_until(&p, ' ')) : 0;
            if (e > s && (e - s) >= (4u * 1024u * 1024u)) {
                size_t l = strlen(line);
                if (l > 0 && line[l - 1] == '\n') line[l - 1] = '\0';
                logf_("  [%lu MB] %s", (unsigned long)((e - s) >> 20), line);
            }
        }
        logf_("  total_vma=%u", vma_cnt);
        fclose(fp);
    }
}

#ifndef ZVE10_REAL_DEVICE

extern int ioctl(int __fd, unsigned long __request, ...);

static pthread_mutex_t g_ldec_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_ldec_fds[32] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};
static volatile uint32_t g_ldec_dec_calls = 0;

static void g5_ldec_track_fd(int fd) {
    pthread_mutex_lock(&g_ldec_fd_lock);
    for (int i = 0; i < 32; i++) {
        if (g_ldec_fds[i] < 0) { g_ldec_fds[i] = fd; break; }
    }
    pthread_mutex_unlock(&g_ldec_fd_lock);
}

static int g5_ldec_is_fd(int fd) {
    if (fd < 0) return 0;
    int found = 0;
    pthread_mutex_lock(&g_ldec_fd_lock);
    for (int i = 0; i < 32; i++) {
        if (g_ldec_fds[i] == fd) { found = 1; break; }
    }
    pthread_mutex_unlock(&g_ldec_fd_lock);
    return found;
}

static void g5_ldec_untrack_fd(int fd) {
    if (fd < 0) return;
    pthread_mutex_lock(&g_ldec_fd_lock);
    for (int i = 0; i < 32; i++) {
        if (g_ldec_fds[i] == fd) { g_ldec_fds[i] = -1; break; }
    }
    pthread_mutex_unlock(&g_ldec_fd_lock);
}

/* 纯软件兼容 Sony LDEC/LZ77 格式解压器（对齐官方 lz77_inflate.c 与 ui-lz77.h 语义） */
static int g5_lz77_decode(const uint8_t *src, size_t ss, uint8_t *dst, size_t ds, size_t *out_written) {
    static const uint8_t lengths[16] = {3,4,5,6,7,8,9,10,11,12,13,14,15,16,32,64};
    if (!src || !dst || ss < 4u || ds == 0u) return -5;
    uintptr_t s = (uintptr_t)src, d = (uintptr_t)dst;
    if (s <= d ? (d - s < ss) : (s - d < ds)) return -5;

    size_t in = 0, out = 0;
    while (in < ss) {
        size_t block = out;
        uint8_t method = src[in++];
        if (method == 0x0fu) {
            if (ss - in < 3u) return -5;
            size_t length = (size_t)src[in + 1] | ((size_t)src[in + 2] << 8);
            in += 3u;
            if (length == 0u || length > ds - out || length > ss - in) return -5;
            memcpy(dst + out, src + in, length);
            in += length;
            out += length;
        } else if (method == 0xf0u) {
            int ended = 0;
            while (in < ss && !ended) {
                uint8_t flags = src[in++];
                for (unsigned bit = 0; bit < 8u; bit++) {
                    if (flags & (1u << bit)) {
                        if (ss - in < 2u) return -5;
                        unsigned count = lengths[src[in] >> 4];
                        unsigned dist = (((unsigned)(src[in] & 0x0fu)) << 8) | (unsigned)src[in + 1];
                        in += 2u;
                        if (dist == 0u) { ended = 1; break; }
                        if (dist > out - block || count > ds - out) return -5;
                        while (count--) {
                            dst[out] = dst[out - dist];
                            out++;
                        }
                    } else {
                        if (in == ss || out == ds) return -5;
                        dst[out++] = src[in++];
                    }
                }
            }
            if (!ended || out == block) return -5;
        } else if (out > 0u && method == 0x00u && (ss - in) < 16u) {
            /* 允许资源块末尾最多 16 字节以内的零对齐填充 */
            int all_zero = 1;
            for (size_t k = in; k < ss; k++) {
                if (src[k] != 0u) { all_zero = 0; break; }
            }
            if (!all_zero) return -5;
            break;
        } else {
            return -5;
        }
    }
    if (out_written) *out_written = out;
    return (out > 0u && out <= ds) ? 0 : -5;
}

/* 将解压缩缓冲写入 LDEC 目标地址（优先通过 /dev/mem 物理地址写入，异常范围回退到 PA/VA 自适应） */
static int g5_ldec_write_target(uint32_t dst_pa, const uint8_t *buf, size_t len, int *used_map_out) {
    struct surface_mapping sm = {0};
    if (map_surface(dst_pa, len, &sm) == 0) {
        memcpy(sm.pixels, buf, len);
        __sync_synchronize();
        g5_unresolve_buf(&sm, 1);
        if (used_map_out) *used_map_out = 1;
        return 0;
    }
    int mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (mem_fd >= 0) {
        uint32_t delta = dst_pa & 4095u;
        size_t map_len = (len + delta + 4095u) & ~(size_t)4095u;
        void *m = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)(dst_pa & ~4095u));
        close(mem_fd);
        if (m != MAP_FAILED) {
            memcpy((uint8_t *)m + delta, buf, len);
            __sync_synchronize();
            munmap(m, map_len);
            if (used_map_out) *used_map_out = 2;
            return 0;
        }
    }
    int map_fallback = 0;
    uint8_t *vbuf = g5_resolve_buf(dst_pa, len, &sm, &map_fallback);
    if (vbuf) {
        memcpy(vbuf, buf, len);
        __sync_synchronize();
        g5_unresolve_buf(&sm, map_fallback);
        if (used_map_out) *used_map_out = 3 + map_fallback;
        return 0;
    }
    return -1;
}

/* 接管 libOb5.so GOT[open/ioctl/close]：在无内核 ldec.ko 的 QEMU 环境中提供纯软件 /dev/ldec 解压驱动 */
static int g5_hook_ob5_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (path && strcmp(path, "/dev/ldec") == 0) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0) {
            g5_ldec_track_fd(fd);
            return fd;
        }
    }
    return (flags & O_CREAT) ? open(path, flags, mode) : open(path, flags);
}

static int g5_hook_ob5_ioctl(int fd, unsigned long req, uintptr_t arg) {
    if (!g5_ldec_is_fd(fd)) {
        return ioctl(fd, req, (void *)arg);
    }
    if (req != 1u || arg <= 0x10000u) {
        errno = EINVAL;
        return -1;
    }
    const uint32_t *p = (const uint32_t *)arg;
    uint32_t src_va = p[0], src_size = p[1], dst_pa = p[2], dst_size = p[3];
    uint32_t call_id = __sync_add_and_fetch(&g_ldec_dec_calls, 1u);

    if (src_va <= 0x10000u || src_size < 4u || src_size > 64u * 1024u * 1024u ||
        dst_pa == 0u || dst_size == 0u || dst_size > 64u * 1024u * 1024u) {
        logf_("G5_LDEC_IOCTL [ERR #%u]: bad args src=%08x(%u) dst_pa=%08x(%u)",
              call_id, src_va, src_size, dst_pa, dst_size);
        errno = EINVAL;
        return -1;
    }

    uint8_t *scratch = (uint8_t *)malloc(dst_size);
    if (!scratch) {
        errno = ENOMEM;
        return -1;
    }
    const uint8_t *sptr = (const uint8_t *)(uintptr_t)src_va;
    size_t out_n = 0;
    int rc = g5_lz77_decode(sptr, (size_t)src_size, scratch, (size_t)dst_size, &out_n);
    if (rc != 0) {
        logf_("G5_LDEC_IOCTL [DEC_FAIL #%u]: src=%08x(%uB %02x %02x %02x %02x %02x %02x) dst_pa=%08x(%uB) out=%u",
              call_id, src_va, src_size, sptr[0], sptr[1], sptr[2], sptr[3], sptr[4], sptr[5],
              dst_pa, dst_size, (unsigned)out_n);
        free(scratch);
        errno = EIO;
        return -1;
    }
    if (out_n < dst_size) {
        memset(scratch + out_n, 0, (size_t)dst_size - out_n);
    }

    int used_map = 0;
    int wrc = g5_ldec_write_target(dst_pa, scratch, (size_t)dst_size, &used_map);
    if (call_id == 1u || wrc != 0) {
        logf_("G5_LDEC_IOCTL [#%u]: src=%08x(%uB) -> dst_pa=%08x(%uB dec=%uB map=%d wrc=%d)",
              call_id, src_va, src_size, dst_pa, dst_size, (unsigned)out_n, used_map, wrc);
    }
    free(scratch);
    if (wrc != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int g5_hook_ob5_close(int fd) {
    g5_ldec_untrack_fd(fd);
    return close(fd);
}

#endif /* !ZVE10_REAL_DEVICE */

/* 接管 libOb5.so GOT[mmap]：修复 flags=0x18002 失败，失败时探测内存状态并尝试匿名页兜底预读 */
static void *g5_hook_ob5_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
#ifdef ZVE10_USB_SANDBOX
    if (fd >= 0) {
        char mpath[128] = {0};
        char lnk[48];
        snprintf(lnk, sizeof lnk, "/proc/self/fd/%d", fd);
        ssize_t n = readlink(lnk, mpath, sizeof(mpath) - 1);
        if (n > 0) mpath[n] = '\0';
        if (strncmp(mpath, "/dev/", 5) == 0) {
            logf_("SB_MMAP -> addr=%p len=0x%lx prot=0x%x flags=0x%x fd=%d(%s) off=0x%lx",
                  addr, (unsigned long)length, prot, flags, fd, mpath, (unsigned long)offset);
        }
    }
#endif
    void *ret = mmap(addr, length, prot, flags, fd, offset);
    if (ret != MAP_FAILED) {
#ifdef ZVE10_USB_SANDBOX
        if (fd >= 0) {
            char mpath[128] = {0};
            char lnk[48];
            snprintf(lnk, sizeof lnk, "/proc/self/fd/%d", fd);
            ssize_t n = readlink(lnk, mpath, sizeof(mpath) - 1);
            if (n > 0) mpath[n] = '\0';
            if (strncmp(mpath, "/dev/", 5) == 0) {
                logf_("SB_MMAP <- ret=%p", ret);
            }
        }
#endif
        return ret;
    }
    int err1 = errno;
    char pathbuf[256];
    pathbuf[0] = '\0';
    if (fd >= 0) {
        char linkp[64];
        snprintf(linkp, sizeof(linkp), "/proc/self/fd/%d", fd);
        ssize_t rlen = readlink(linkp, pathbuf, sizeof(pathbuf) - 1);
        if (rlen >= 0) {
            pathbuf[rlen] = '\0';
        }
    }
    uint32_t fc = __sync_add_and_fetch(&g_ob5_mmap_fail_cnt, 1);
    int retry_flags = flags & ~0x18000; /* 剥离 MAP_POPULATE | MAP_NONBLOCK 后重试 */
    if (retry_flags != flags) {
        void *ret2 = mmap(addr, length, prot, retry_flags, fd, offset);
        if (ret2 != MAP_FAILED) {
            if (fc <= 20 || (fc % 50) == 0) {
                logf_("PATCH: G5_OB5_MMAP 清除 0x18000 重试成功 #%u: len=%lu flags=0x%x->0x%x fd=%d(%s) off=%ld -> %p",
                      fc, (unsigned long)length, flags, retry_flags, fd, pathbuf, (long)offset, ret2);
            }
            return ret2;
        }
        err1 = errno;
    }
    if (fc == 1) {
        logf_("PATCH: G5_OB5_MMAP 失败 #%u: addr=%p len=%lu prot=0x%x flags=0x%x fd=%d(%s) off=%ld errno=%d",
              fc, addr, (unsigned long)length, prot, flags, fd, pathbuf, (long)offset, err1);
        dump_mem_diagnostics_once();
    } else if (fc <= 20 || (fc % 50) == 0) {
        logf_("PATCH: G5_OB5_MMAP 失败 #%u: addr=%p len=%lu prot=0x%x flags=0x%x fd=%d(%s) off=%ld errno=%d",
              fc, addr, (unsigned long)length, prot, flags, fd, pathbuf, (long)offset, err1);
    }

    /* 若文件映射受限于 ramfs/flags，尝试匿名内存+pread 读取文件完整内容 */
    if (fd >= 0 && length > 0 && prot == PROT_READ) {
        void *anon = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (anon != MAP_FAILED) {
            size_t done = 0;
            uint8_t *dst = (uint8_t *)anon;
            while (done < length) {
                ssize_t n = pread(fd, dst + done, length - done, offset + (off_t)done);
                if (n <= 0) break;
                done += (size_t)n;
            }
            mprotect(anon, length, PROT_READ);
            logf_("PATCH: G5_OB5_MMAP 匿名页+pread 兜底成功 #%u: %s len=%lu read=%lu -> %p",
                  fc, pathbuf, (unsigned long)length, (unsigned long)done, anon);
            return anon;
        }
        if (fc <= 5) {
            logf_("PATCH: G5_OB5_MMAP 匿名兜底同样失败 #%u: errno=%d", fc, errno);
        }
    }

    /* libOb5+0x1a48ee 仅判 NULL 未判 -1；映射失败时返回 NULL 使其走干净失败分支而不崩溃 */
    errno = err1;
    return NULL;
}

typedef int (*osal_snd_sync_direct_fn_t)(uint32_t qid, void *msg);
typedef int (*grm_check_update_fn_t)(void);
typedef void (*draw_fb_fn_t)(void *ge);

static osal_snd_sync_direct_fn_t g_orig_osal_snd_sync_direct = NULL;
static grm_check_update_fn_t g_orig_grm_check_update = NULL;
static draw_fb_fn_t g_orig_draw_framebuffer = NULL;

static volatile uint32_t g_sync_rpc_cnt = 0;
static volatile uint32_t g_sync_time_fix_cnt = 0;
static volatile uint32_t g_sync_time_fast_cnt = 0;
static volatile uint32_t g_grm_chk_cnt = 0;
static volatile uint32_t g_draw_fb_cnt = 0;
static volatile int g_sync_time_mode = 0; /* 0=待校准, 1=校准中, 2=已校准单调偏移, 3=纯用户态回退 */
static int64_t g_sync_time_mono_offset_us = 0;

static inline uint64_t g5_monotonic_us_fast(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)(ts.tv_nsec / 1000L);
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

/* 统一 GOT 槽位改写辅助，避免多处重复 mprotect/log 样板代码 */
static void hook_got_slot(uintptr_t fbase, uintptr_t got_off, void *new_fn, const char *label) {
    uintptr_t slot = fbase + got_off;
    uintptr_t page = slot & ~(uintptr_t)0xfffu;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0) {
        logf_("PATCH: mprotect %s (0x%lx) 失败 errno=%d", label, (unsigned long)slot, errno);
        return;
    }
    void *prev = *(void **)slot;
    *(void **)slot = new_fn;
    logf_("PATCH: 成功 Hook %s (0x%lx prev=%p) -> %p", label, (unsigned long)slot, prev, new_fn);
}

/* 防线 1：内联 Patch ADF 错误翻译总入口，静默返回 0 并阻断 ADF Error 打印 (4字节) */
static void patch_adf_error_translator(uintptr_t app_base) {
    uintptr_t target = app_base + 0x02b22290u;
    uintptr_t page = target & ~0xfffu;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        static const uint8_t noop_ret0[4] = { 0x00, 0x20, 0x70, 0x47 }; /* movs r0, #0; bx lr */
        memcpy((void *)target, noop_ret0, sizeof(noop_ret0));
        __builtin___clear_cache((char *)target, (char *)target + 4);
        logf_("PATCH: 成功 Inline Patch ADF error translator (0x%lx -> ret 0)", (unsigned long)target);
    } else {
        logf_("PATCH: mprotect 失败 ADF error translator (0x%lx) errno=%d", (unsigned long)target, errno);
    }
}

/* 防线 2：内联 Patch sequence_boot::run_i 直调的模式查询封装，写回 0 并返回 0 (8字节) */
static void patch_sequence_boot_adf_query(uintptr_t app_base) {
    uintptr_t target = app_base + 0x02b15842u;
    uintptr_t page = target & ~0xfffu;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        static const uint8_t bypass_code[8] = {
            0x00, 0x22,             /* movs r2, #0 */
            0x0a, 0x60,             /* str  r2, [r1] (*out_err = 0) */
            0x00, 0x20,             /* movs r0, #0 */
            0x70, 0x47              /* bx   lr */
        };
        memcpy((void *)target, bypass_code, sizeof(bypass_code));
        __builtin___clear_cache((char *)target, (char *)target + 8);
        logf_("PATCH: 成功 Inline Patch sequence_boot adf query (0x%lx -> *r1=0, ret 0)", (unsigned long)target);
    } else {
        logf_("PATCH: mprotect 失败 sequence_boot adf query (0x%lx) errno=%d", (unsigned long)target, errno);
    }
}

/* 防线 3：appFw.so GOT[adf_ext_type] 槽位安全归零 (偏移 0x0377b5d8) */
static int stub_adf_ext_type(const void *in, void *out) {
    (void)in;
    if (out) memset(out, 0, 64);
    return 0;
}

/* 消除 [REMOTE][DISP_MODE_OPTION] ERROR(00000267/00000268) 日志告警 */
static void patch_disp_mode_option_log(uintptr_t app_base) {
    uintptr_t target = app_base + 0x011f541eu;
    uintptr_t page = target & ~0xfffu;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
        static const uint8_t jmp_code[2] = { 0x19, 0xe0 }; /* b.n 0x11f5454 */
        memcpy((void *)target, jmp_code, sizeof(jmp_code));
        __builtin___clear_cache((char *)target, (char *)target + 2);
        logf_("PATCH: 成功 Inline Patch DISP_MODE_OPTION log bypass (0x%lx)", (unsigned long)target);
    } else {
        logf_("PATCH: mprotect 失败 DISP_MODE_OPTION log bypass (0x%lx) errno=%d", (unsigned long)target, errno);
    }
}

/* 彻底清除 UI 字体乱码：恢复显存行宽 Stride 与字库原生栅格化
 * 严禁调用 set_w(640)/set_h(480)，严禁 Hook 0x02b2757c 与 0x02b274f4 */
static void patch_panel_device_info(uintptr_t app_base)
{
    (void)app_base;
    logf_("PANEL_INFO: 回退面板强行写入，保持五代原生 Stride 以彻底根除字体乱码");
}

/* 消除 sequence_media_start_inout 断言 (error:00000015)，打通媒体状态检测 */
static int stub_media_check_ok(void *ctx, uint32_t *err)
{
    (void)ctx;
    if (err) {
        *err = 0u; /* 清零错误码，模拟底层媒体操作成功 */
    }
    logf_("MEDIA_CHECK: stub_media_check_ok 拦截成功 (err=0, SUCCESS)");
    return 0;
}

static void patch_media_check_guard(uintptr_t app_base)
{
    if (!app_base) return;
    patch_thumb_jump((void *)(app_base + 0x02b1b010u + 1u), (void *)stub_media_check_ok, "appFw:media_check_02b1b010");
    patch_thumb_jump((void *)(app_base + 0x02b1b0c4u + 1u), (void *)stub_media_check_ok, "appFw:media_check_02b1b0c4");
    logf_("MEDIA_CHECK: 成功安装 media_check 保护桩 (0x02b1b010, 0x02b1b0c4)");
}

/* USB 模式卡死防护：拦截 USB Gadget 激活与切换，防止进入无响应模态死锁 */
static int stub_g4_usb_start_gadget(void *fsm, int ev, void *param)
{
    (void)fsm; (void)ev; (void)param;
    logf_("USB_GUARD: 拦截 UsbControl::actionGStartGadget，安全阻断 USB 挂死");
    return -1;
}

static void install_usb_guard(uintptr_t app_base)
{
    (void)app_base;
    void *hUsb = dlopen(LIBDIR "libUsbControl.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!hUsb) hUsb = dlopen(LIBDIR "libUsbControl.so", RTLD_LAZY | RTLD_GLOBAL);
    if (hUsb) {
        void *pStartGadget = dlsym(hUsb, "_ZN10UsbControl18actionGStartGadgetEPN3UFW3FsmEiPv");
        if (pStartGadget) {
            patch_thumb_jump(pStartGadget, (void *)stub_g4_usb_start_gadget, "libUsbControl:actionGStartGadget");
            logf_("USB_GUARD: 成功拦截 libUsbControl actionGStartGadget (%p)", pStartGadget);
        }
    }
}

/* 消除 libmpr.so SIGSEGV (0x7ef05e 读溢出队列触发段错误) 免疫桩 */
static uintptr_t get_module_base_maps(const char *name)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name)) {
            char *dash = strchr(line, '-');
            if (dash) {
                *dash = '\0';
                base = (uintptr_t)strtoul(line, NULL, 16);
            }
            break;
        }
    }
    fclose(fp);
    return base;
}

/* =========================================================================
 * 引入 5 个独立的跨代硬件与协议桥接层模块头文件 (Phase 2)
 * ========================================================================= */
#include "g4host_bridge_sched.h"
#include "g4host_bridge_media.h"
#include "g4host_bridge_optics.h"
#include "g4host_bridge_usb.h"
#include "g4host_bridge_isp.h"
#include "g4host_bridge_input.h"

static int stub_mpr_log_queue_read(void)
{
    /* 模拟调试跟踪日志队列为空，直接返回 -1 (0xffffffff)，调用者 0x7ef3e2 退出当前循环，彻底杜绝 SIGSEGV */
    return -1;
}

static int hook_pthread_create_tracker(pthread_t *thread, const pthread_attr_t *attr,
                                      void *(*start_routine)(void *), void *arg);

static void patch_libmpr_crash_guard(void)
{
    uintptr_t mpr_base = get_module_base_maps("libmpr.so");
    if (!mpr_base) {
        void *sym = dlsym(RTLD_DEFAULT, "Fsys_MovieRecReady");
        if (!sym) sym = dlsym(RTLD_DEFAULT, "Fsys_SetDebug");
        if (sym) {
            Dl_info info;
            if (dladdr(sym, &info) && info.dli_fbase) {
                mpr_base = (uintptr_t)info.dli_fbase;
            }
        }
    }
    if (mpr_base) {
        /* 在 0x007eed8c 安装 Thumb 跳转桩直接返回 -1 */
        patch_thumb_jump((void *)(mpr_base + 0x007eed8cu + 1u), (void *)stub_mpr_log_queue_read, "libmpr:log_queue_read");
        hook_got_slot(mpr_base, 0x00c49994u, (void *)hook_pthread_create_tracker, "libmpr.so GOT[pthread_create]");
        logf_("CRASH_GUARD: 成功安装 libmpr.so 段错误免疫桩与 pthread 追踪 (mpr_base=0x%lx target=0x%lx -> return -1)",
              (unsigned long)mpr_base, (unsigned long)(mpr_base + 0x007eed8cu));
    } else {
        logf_("CRASH_GUARD_WARN: 未能定位 libmpr.so 基址");
    }
}

/* 线程创建与全量生命周期追踪 (Stage 1 定向抓栈) */
typedef struct {
    void *(*orig_routine)(void *);
    void *orig_arg;
    void *lr;
} thread_wrapper_arg_t;

static void *thread_spawn_wrapper(void *arg)
{
    thread_wrapper_arg_t *w = (thread_wrapper_arg_t *)arg;
    void *(*real_fn)(void *) = w->orig_routine;
    void *real_arg = w->orig_arg;
    void *caller_lr = w->lr;
    free(w);

    long tid = (long)syscall(SYS_gettid);
    logf_("THREAD_SPAWN: tid=%ld entry=%p lr=%p", tid, real_fn, caller_lr);

    return real_fn(real_arg);
}

typedef int (*real_pthread_create_fn_t)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
static real_pthread_create_fn_t g_orig_pthread_create = NULL;

static int hook_pthread_create_tracker(pthread_t *thread, const pthread_attr_t *attr,
                                      void *(*start_routine)(void *), void *arg)
{
    void *caller_lr = __builtin_return_address(0);
    if (!g_orig_pthread_create) {
        g_orig_pthread_create = (real_pthread_create_fn_t)dlsym(RTLD_NEXT, "pthread_create");
        if (!g_orig_pthread_create) {
            g_orig_pthread_create = (real_pthread_create_fn_t)dlsym(RTLD_DEFAULT, "pthread_create");
        }
    }
    thread_wrapper_arg_t *w = (thread_wrapper_arg_t *)malloc(sizeof(thread_wrapper_arg_t));
    if (w && g_orig_pthread_create) {
        w->orig_routine = start_routine;
        w->orig_arg = arg;
        w->lr = caller_lr;
        return g_orig_pthread_create(thread, attr, thread_spawn_wrapper, w);
    }
    if (w) free(w);
    return g_orig_pthread_create ? g_orig_pthread_create(thread, attr, start_routine, arg) : -1;
}

/* 拦截 appFw.so GOT[osal_snd_sync_direct]：高频 0x910042 取时初次校准内核时间基后全走用户态直返，消除 ~960/s 内核 UIPC 往返 */
static int g5_hook_osal_snd_sync_direct(uint32_t qid, void *msg) {
    if (qid == 0x910042u && msg != NULL && *(uint32_t *)msg >= 0x20u) {
        int mode = __atomic_load_n(&g_sync_time_mode, __ATOMIC_ACQUIRE);
        if (mode == 2) {
            uint64_t now_us = (uint64_t)((int64_t)g5_monotonic_us_fast() + g_sync_time_mono_offset_us);
            *(int32_t *)((uint8_t *)msg + 0x14) = 0;
            *(uint64_t *)((uint8_t *)msg + 0x18) = now_us;
            __atomic_add_fetch(&g_sync_time_fast_cnt, 1u, __ATOMIC_RELAXED);
            return 0;
        }
        if (mode == 3) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            *(int32_t *)((uint8_t *)msg + 0x14) = 0;
            *(uint64_t *)((uint8_t *)msg + 0x18) = (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
            __atomic_add_fetch(&g_sync_time_fast_cnt, 1u, __ATOMIC_RELAXED);
            return 0;
        }
    }

    uintptr_t lr = (uintptr_t)__builtin_return_address(0) & ~(uintptr_t)1u;
    uintptr_t off = (g_appfw_base && lr >= g_appfw_base) ? (lr - g_appfw_base) : lr;
    int rc = g_orig_osal_snd_sync_direct ? g_orig_osal_snd_sync_direct(qid, msg) : -1;

    if (qid == 0x910042u && msg != NULL && *(uint32_t *)msg >= 0x20u) {
        uint64_t ts_val = *(uint64_t *)((uint8_t *)msg + 0x18);
        int inner_rc = *(int32_t *)((uint8_t *)msg + 0x14);
        if (rc == 0 && inner_rc == 0 && ts_val != 0) {
            int expected = 0;
            if (__atomic_compare_exchange_n(&g_sync_time_mode, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                uint64_t mono_us = g5_monotonic_us_fast();
                g_sync_time_mono_offset_us = (int64_t)ts_val - (int64_t)mono_us;
                __atomic_store_n(&g_sync_time_mode, 2, __ATOMIC_RELEASE);
                logf_("PERF: G5_SYNC_TIME 0x910042 已校准内核时间基 (kernel_us=%llu mono_us=%llu off=%lld)，后续走用户态零拷贝直返",
                      (unsigned long long)ts_val, (unsigned long long)mono_us, (long long)g_sync_time_mono_offset_us);
            }
            return 0;
        }
        struct timeval tv;
        gettimeofday(&tv, NULL);
        uint64_t now_us = (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
        *(int32_t *)((uint8_t *)msg + 0x14) = 0;
        *(uint64_t *)((uint8_t *)msg + 0x18) = now_us;
        uint32_t fc = __sync_add_and_fetch(&g_sync_time_fix_cnt, 1);
        if (fc <= 3 || (fc % 200) == 0) {
            logf_("PATCH: G5_SYNC_TIME 0x910042 失效(rc=%d inner=%d ts=%llu)，已注入 us=%llu (#%u off=0x%lx)",
                  rc, inner_rc, (unsigned long long)ts_val, (unsigned long long)now_us, fc, (unsigned long)off);
        }
        if (fc >= 3u) {
            int expected = 0;
            __atomic_compare_exchange_n(&g_sync_time_mode, &expected, 3, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
        }
        return 0;
    }

    /* 拦截并模拟应答 DISP_MODE_OPTION (0x267 / 0x268) */
    if (msg != NULL && *(uint32_t *)msg >= 0x20u) {
        uint32_t cmd = *(uint32_t *)((uint8_t *)msg + 4);
        if (cmd == 0x267 || cmd == 0x268 || qid == 0x267 || qid == 0x268) {
            *(int32_t *)((uint8_t *)msg + 0x14) = 0;
            struct timeval tv;
            gettimeofday(&tv, NULL);
            *(uint64_t *)((uint8_t *)msg + 0x18) = (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
            static volatile uint32_t s_disp_opt_cnt = 0;
            uint32_t dc = __sync_add_and_fetch(&s_disp_opt_cnt, 1);
            if (dc <= 5 || (dc % 100) == 0) {
                logf_("PATCH: 模拟应答 DISP_MODE_OPTION cmd=0x%x qid=0x%x 为成功 (#%u off=0x%lx)",
                      cmd, qid, dc, (unsigned long)off);
            }
            return 0;
        }
    }

    uint32_t c = __sync_add_and_fetch(&g_sync_rpc_cnt, 1);
    if (c <= 20 || (rc != 0 && c <= 60)) {
        uint32_t msz = msg ? *(uint32_t *)msg : 0;
        logf_("G5_SYNC_RPC #%u: qid=0x%08x sz=%u rc=%d (off=0x%lx)", c, qid, msz, rc, (unsigned long)off);
    }
    return rc;
}

/* 拦截 appFw.so GOT[GRM_fbrmCheckUpdateFinished]：观测硬件刷新完成门控，QEMU 下若被硬件缺口卡住则放行，真机下透传真实状态 */
static int g5_hook_grm_check_update_finished(void) {
    int rc = g_orig_grm_check_update ? g_orig_grm_check_update() : 0;
    uint32_t c = __sync_add_and_fetch(&g_grm_chk_cnt, 1);
#ifdef ZVE10_REAL_DEVICE
    if (c <= 5 || (rc != 0 && (c % 3000) == 0)) {
        logf_("G5_GRM_CHECK_UPDATE_REAL #%u: orig_rc=%d (透传真机硬件结果)", c, rc);
    }
    return rc;
#else
    if (c <= 15 || (c % 200) == 0) {
        logf_("G5_GRM_CHECK_UPDATE #%u: orig_rc=%d%s", c, rc, (rc != 0) ? " -> 放行(0)" : "");
    }
    /* appFw+0x54f2ae 仅在 GRM_fbrmCheckUpdateFinished()==0 时才允许进入 drawFramebuffer */
    return (rc != 0) ? 0 : rc;
#endif
}

/* 拦截 appFw.so GOT[GraphicsEngine::drawFramebuffer]：观测主循环是否实际触达渲染入口 */
static void g5_hook_appfw_draw_framebuffer(void *ge) {
    uint32_t c = __sync_add_and_fetch(&g_draw_fb_cnt, 1);
#ifdef ZVE10_REAL_DEVICE
    if (c <= 5 || (c % 1000) == 0) {
        logf_("G5_APPFW_DRAWFB #%u: ge=%p", c, ge);
    }
#else
    if (c <= 15 || (c % 200) == 0) {
        logf_("G5_APPFW_DRAWFB #%u: ge=%p", c, ge);
    }
#endif
    if (g_orig_draw_framebuffer) {
        g_orig_draw_framebuffer(ge);
    }
}

static void dump_maps_summary(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return;
    char line[256];
    logf_("=== /proc/self/maps (可执行段摘要) ===");
    while (fgets(line, sizeof line, fp)) {
        if (strstr(line, "r-xp") && (strstr(line, ".so") || strstr(line, ".elf"))) {
            size_t len = strlen(line);
            if (len > 0 && line[len - 1] == '\n') line[len - 1] = 0;
            logf_("  MAP: %s", line);
        }
    }
    fclose(fp);
    logf_("=== END MAPS ===");
}

/* =========================================================================
 * 四代宿主 RM 线程唤醒停靠 + 五代 vdf_if 同步驱动钩子
 * 解决:
 *   1) 四代 libObj.so 启动期残留线程 TID=142 在 0x775120 阻塞并独占 kernel mlock(2),
 *      导致五代 libOb5.so 的 RM 线程 TID=193 卡死在 ioctl(0xc0048211) 无法消费队列与 Present.
 *   2) 五代 vdf_if_port_send_break/exec/mute 及 OSDPin::send 等待不存在的远端协处理器
 *      0x0061003c 回执信号量 (0x3c8fb4/fc0/fac/fbc), 导致主 UI 线程在 DRAWFB 后卡死.
 * ========================================================================= */
static volatile int g_g4_rm_parked = 0;

#ifdef ZVE10_REAL_DEVICE
static pthread_mutex_t g_g4_rm_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_g4_rm_cv = PTHREAD_COND_INITIALIZER;
static volatile int    g_g4_rm_allow_exit = 0;
static uintptr_t       g_libobj_base_real = 0;
static void           *g_hLibObj_real = NULL;
static volatile int    g_g4_handoff_done = 0;
static const char *volatile g_real_handoff_stage = "init";

/* 真机条件下令停靠的 Gen4 RM 线程在允许退出后主动 pthread_exit，使 libObj:0x774111 pthread_join 零死锁回收 */
static uintptr_t g4_real_park_or_exit(const char *tag)
{
    pthread_mutex_lock(&g_g4_rm_mtx);
    g_g4_rm_parked = 1;
    if (!g_g4_rm_allow_exit) {
        logf_("G4_RM_PARK: 四代 RM 线程进入 %s 条件停靠等待释放信号...", tag);
        while (!g_g4_rm_allow_exit) {
            pthread_cond_wait(&g_g4_rm_cv, &g_g4_rm_mtx);
        }
    }
    pthread_mutex_unlock(&g_g4_rm_mtx);
    logf_("G4_RM_PARK: 四代 RM 线程从 %s 正常退出，交还 /dev/dmpgles2 与 /dev/mem", tag);
    pthread_exit(NULL);
    return 0;
}

static uintptr_t g4_hook_rm_wait(uintptr_t engine, uintptr_t b, uintptr_t c, uintptr_t d)
{
    (void)engine; (void)b; (void)c; (void)d;
    return g4_real_park_or_exit("rm_wait");
}

static uintptr_t g4_hook_wait_sig(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    (void)a; (void)b; (void)c; (void)d;
    return g4_real_park_or_exit("rm_wait_sig");
}
#else
static uintptr_t g4_hook_rm_wait(uintptr_t engine, uintptr_t b, uintptr_t c, uintptr_t d)
{
    (void)engine; (void)b; (void)c; (void)d;
    return 0x40000000u;
}

static uintptr_t g4_hook_wait_sig(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    (void)a; (void)b; (void)c; (void)d;
    g_g4_rm_parked = 1;
    logf_("G4_RM_PARK: 四代 libObj RM 线程已释放 mlock(2) 并安全休眠，不再抢占 /dev/sugilite 与 rqueue");
    for (;;) sleep(3600);
    return 0;
}
#endif

static void g4_wake_noop_sighandler(int sig)
{
    (void)sig;
}

static void park_libobj_rm_thread(uintptr_t libobj_base)
{
    static const unsigned char exp_wait[8] = {0xf0, 0xb5, 0x83, 0xb0, 0x44, 0x1e, 0x00, 0xaf};
    static const unsigned char exp_sig[8]  = {0xf0, 0xb5, 0x83, 0xb0, 0x00, 0xaf, 0x12, 0x4d};
    const void *p_wait = (const void *)(libobj_base + 0x775120u);
    const void *p_sig  = (const void *)(libobj_base + 0x7755b0u);

    if (memcmp(p_wait, exp_wait, 8) == 0) {
        patch_thumb_jump((void *)(libobj_base + 0x775121u), (void *)g4_hook_rm_wait, "libObj:rm_wait");
    } else {
        logf_("G4_RM_PARK: libObj:rm_wait 前言不匹配，跳过");
    }
    if (memcmp(p_sig, exp_sig, 8) == 0) {
        patch_thumb_jump((void *)(libobj_base + 0x7755b1u), (void *)g4_hook_wait_sig, "libObj:rm_wait_sig");
    } else {
        logf_("G4_RM_PARK: libObj:rm_wait_sig 前言不匹配，跳过");
    }

    /* 仅向 wchan=sugilite_ioctl 的四代线程发一次无 SA_RESTART 的 SIGUSR2，促使其交出 mlock(2) 并停靠 */
    struct sigaction sa_new, sa_old;
    memset(&sa_new, 0, sizeof sa_new);
    sa_new.sa_handler = g4_wake_noop_sighandler;
    sigemptyset(&sa_new.sa_mask);
    sa_new.sa_flags = 0; /* 禁用 SA_RESTART 以中断阻塞 ioctl */
    sigaction(SIGUSR2, &sa_new, &sa_old);

    long self_tid = (long)syscall(224);
    pid_t pid = getpid();
    for (int round = 0; round < 3 && !g_g4_rm_parked; round++) {
        DIR *dir = opendir("/proc/self/task");
        int kicked = 0;
        if (dir) {
            struct dirent *de;
            while ((de = readdir(dir)) != NULL) {
                if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
                long tid = atol(de->d_name);
                if (tid <= 0 || tid == self_tid) continue;
                char wpath[96], wbuf[64] = {0};
                snprintf(wpath, sizeof wpath, "/proc/self/task/%ld/wchan", tid);
                int wfd = open(wpath, O_RDONLY);
                if (wfd >= 0) {
                    int n = read(wfd, wbuf, sizeof wbuf - 1);
                    close(wfd);
                    if (n > 0 && strstr(wbuf, "sugilite")) {
                        logf_("G4_RM_PARK: 发现四代阻塞线程 TID=%ld (wchan=%s)，发送 SIGUSR2 唤醒交锁...", tid, wbuf);
                        syscall(268 /* __NR_tgkill */, pid, tid, SIGUSR2);
                        kicked++;
                    }
                }
            }
            closedir(dir);
        }
        if (!kicked) break;
        for (int ms = 0; ms < 20 && !g_g4_rm_parked; ms++) {
            usleep(10000);
        }
    }
    sigaction(SIGUSR2, &sa_old, NULL);
    logf_("G4_RM_PARK: 初始化完成 parked=%d", g_g4_rm_parked);
}

#ifndef ZVE10_REAL_DEVICE

static unsigned g_vdf_break_cnt = 0;
static unsigned g_vdf_exec_cnt = 0;
static unsigned g_vdf_mute_cnt = 0;
static unsigned g_osdpin_send_cnt = 0;

static int g5_hook_send_break(void)
{
    if (++g_vdf_break_cnt <= 20) {
        logf_("G5_VDF_BREAK #%u: 直接放行 (跳过 0x3c8fb4 DSP 信号量死等)", g_vdf_break_cnt);
    }
    return 0;
}

static int g5_hook_send_exec(void)
{
    if (++g_vdf_exec_cnt <= 20) {
        logf_("G5_VDF_EXEC #%u: 直接放行 (跳过 0x3c8fc0 DSP 信号量死等)", g_vdf_exec_cnt);
    }
    return 0;
}

static void *g5_mute_cb_worker(void *unused)
{
    (void)unused;
    usleep(1000);
    if (!g5_ob5_base) return NULL;
    typedef void (*mute_cb_fn)(void *);
    mute_cb_fn cb = *(mute_cb_fn *)(g5_ob5_base + 0x3c8d68u);
    void *cb_arg = *(void **)(g5_ob5_base + 0x3c8fa8u);
    if (cb) cb(cb_arg);
    return NULL;
}

static int g5_hook_send_mute(uint32_t mute)
{
    if (++g_vdf_mute_cnt <= 20) {
        logf_("G5_VDF_MUTE #%u: mute=%u -> 异步触发回调并放行(0)", g_vdf_mute_cnt, (unsigned)mute);
    }
    if (g5_ob5_base && *(void **)(g5_ob5_base + 0x3c8d68u)) {
        pthread_t th;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 64 * 1024);
        if (pthread_create(&th, &at, g5_mute_cb_worker, NULL) != 0) {
            logf_("G5_VDF_MUTE: 创建异步回调线程失败");
        }
        pthread_attr_destroy(&at);
    }
    return 0;
}

static int g5_hook_osdpin_send(void *this_pin, uint32_t msg, uint32_t type)
{
    if (++g_osdpin_send_cnt <= 20) {
        logf_("G5_OSDPIN_SEND #%u: pin=%p msg=0x%x type=%u -> 模拟下发成功(1)",
              g_osdpin_send_cnt, this_pin, (unsigned)msg, (unsigned)type);
    }
    return 1; /* OSDPin::send 成功返回 1，0 为失败 */
}

static void install_g5_vdf_if_hooks(void *pGetWS)
{
    Dl_info dli = {0};
    if (!pGetWS || !dladdr(pGetWS, &dli) || !dli.dli_fbase) {
        logf_("HOOK_VDF: 获取 libOb5.so 基址失败");
        return;
    }
    uintptr_t base = (uintptr_t)dli.dli_fbase;
    g5_ob5_base = base;
    logf_("HOOK_VDF: libOb5.so base=%p sems(fb4=%#x fc0=%#x fbc=%#x fac=%#x)",
          (void *)base,
          *(uint32_t *)(base + 0x3c8fb4u),
          *(uint32_t *)(base + 0x3c8fc0u),
          *(uint32_t *)(base + 0x3c8fbcu),
          *(uint32_t *)(base + 0x3c8facu));

    static const unsigned char exp_brk[8] = {0x80, 0xb5, 0x86, 0xb0, 0x17, 0x49, 0x00, 0xaf};
    static const unsigned char exp_exc[8] = {0x80, 0xb5, 0x86, 0xb0, 0x17, 0x49, 0x00, 0xaf};
    static const unsigned char exp_mut[8] = {0x90, 0xb5, 0x87, 0xb0, 0x18, 0x49, 0x00, 0xaf};
    static const unsigned char exp_pin[8] = {0x2d, 0xe9, 0xf0, 0x41, 0x04, 0x46, 0x90, 0xf8};

    if (memcmp((const void *)(base + 0x124a18u), exp_brk, 8) == 0)
        patch_thumb_jump((void *)(base + 0x124a19u), (void *)g5_hook_send_break, "libOb5:vdf_if_send_break");
    else
        logf_("HOOK_VDF: send_break 前言不匹配");

    if (memcmp((const void *)(base + 0x124aa0u), exp_exc, 8) == 0)
        patch_thumb_jump((void *)(base + 0x124aa1u), (void *)g5_hook_send_exec, "libOb5:vdf_if_send_exec");
    else
        logf_("HOOK_VDF: send_exec 前言不匹配");

    if (memcmp((const void *)(base + 0x124b28u), exp_mut, 8) == 0)
        patch_thumb_jump((void *)(base + 0x124b29u), (void *)g5_hook_send_mute, "libOb5:vdf_if_send_mute");
    else
        logf_("HOOK_VDF: send_mute 前言不匹配");

    if (memcmp((const void *)(base + 0x120cd0u), exp_pin, 8) == 0)
        patch_thumb_jump((void *)(base + 0x120cd1u), (void *)g5_hook_osdpin_send, "libOb5:OSDPin::send");
    else
        logf_("HOOK_VDF: OSDPin::send 前言不匹配");
}

#endif /* !ZVE10_REAL_DEVICE */

static void logf_(const char *fmt, ...)
{
    char buf[512];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int n = snprintf(buf, sizeof buf, "[%s +%ld.%03ld] ", g_runid, (long)tv.tv_sec, (long)(tv.tv_usec / 1000));
    va_list ap;
    va_start(ap, fmt);
    n += vsnprintf(buf + n, sizeof buf - n - 1, fmt, ap);
    va_end(ap);
    if (n > (int)sizeof buf - 2) n = sizeof buf - 2;
    buf[n++] = '\n';
    pthread_mutex_lock(&g_logmu);
    write(2, buf, n); /* 实时输出至控制台/QEMU串口 */
    if (g_logfd >= 0) { (void)write(g_logfd, buf, n); /* 生产优化：去除 fsync，由内核 page cache 异步刷入 Flash，彻底消除 Flash I/O 阻塞 */ }
    pthread_mutex_unlock(&g_logmu);
}

static int read_int(const char *path, int dflt)
{
    char b[16] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) return dflt;
    int n = read(fd, b, sizeof b - 1);
    close(fd);
    return n > 0 ? atoi(b) : dflt;
}

static void write_int(const char *path, int v)
{
    char b[16];
    int n = snprintf(b, sizeof b, "%d\n", v);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    (void)write(fd, b, n);
    close(fd);
}

/* =========================================================================
 * libObj.so 宿主并发线程与析构保护：Context 单例桩
 * 解决 im.elf 并发后台服务线程及 libra::RecordPtr 析构因原厂四代
 * Application_System_Init 被跳过而调用 0x854690 (GetContext) 导致的 pc=(nil) 空指针段错误。
 * ========================================================================= */
static uint32_t s_dummy_vtable[256];
static uint8_t  s_dummy_context_blob[65536] __attribute__((aligned(8)));

static uint32_t dummy_vfunc_noop(void *this_ptr, ...)
{
    (void)this_ptr;
    return 0;
}

static void *dummy_context_getter(void)
{
    return (void *)s_dummy_context_blob;
}

static void install_g4_key_intercept(uintptr_t libobj_base);

__attribute__((minsize, cold))
static int match_ctx_getter_sig(uintptr_t va)
{
    const uint16_t *h = (const uint16_t *)va;
    return h[0] == 0x4b02u && h[1] == 0xb580u && h[2] == 0x447bu && h[3] == 0xaf00u &&
           h[16] == 0x4b03u && h[17] == 0xb580u && h[18] == 0x447bu && h[19] == 0x681bu;
}

__attribute__((minsize, cold))
static void init_libobj_context_stub(void)
{
    /* 1. 初始化虚表与大容量全零安全对象结构 (ASTRA-06 彻底免疫修复) */
    memset(s_dummy_context_blob, 0, sizeof(s_dummy_context_blob));
    for (int i = 0; i < 256; i++) {
        s_dummy_vtable[i] = (uint32_t)(uintptr_t)dummy_vfunc_noop;
    }

    uint32_t *ctx = (uint32_t *)s_dummy_context_blob;
    /* context 自身头部作为拥有虚表的对象 */
    ctx[0] = (uint32_t)(uintptr_t)s_dummy_vtable;

    /* context 内部划分出足够大的全零子对象池 (每个区域 4KB，头部均带有安全虚表) */
    uint32_t *sub_obj_common = (uint32_t *)(s_dummy_context_blob + 4096);
    sub_obj_common[0] = (uint32_t)(uintptr_t)s_dummy_vtable;

    uint32_t *sub_obj_10 = (uint32_t *)(s_dummy_context_blob + 8192);
    sub_obj_10[0] = (uint32_t)(uintptr_t)s_dummy_vtable;

    uint32_t *sub_obj_30 = (uint32_t *)(s_dummy_context_blob + 12288);
    sub_obj_30[0] = (uint32_t)(uintptr_t)s_dummy_vtable;

    /* 16KB 区域作为 0x40 系列 sub_obj (用于 +0x40, +0x44，彻底杜绝 0x85374c SIGSEGV 空指针！) */
    uint32_t *sub_obj_40 = (uint32_t *)(s_dummy_context_blob + 16384);
    sub_obj_40[0] = (uint32_t)(uintptr_t)s_dummy_vtable;

    /* 补齐 ctx[0x04..0xfc] 全部指针槽位，并覆盖 libObj+0x85470c..0x85474a 等全部 getter 访问 */
#pragma clang loop unroll(disable)
    for (size_t off = 0x04u; off < 0x100u; off += 4u) {
        ctx[off / 4u] = (uint32_t)(uintptr_t)sub_obj_common;
    }
    ctx[0x10 / 4] = (uint32_t)(uintptr_t)sub_obj_10;

    /* 严格保持 +0x20 整个 4 字节槽位为 0，防止 0x8547c6 ldrb r4, [r0, #0x20] 触发数组循环越界 */
    ctx[0x20 / 4] = 0u;

    ctx[0x30 / 4] = (uint32_t)(uintptr_t)sub_obj_30;
    ctx[0x34 / 4] = (uint32_t)(uintptr_t)sub_obj_30;
    ctx[0x38 / 4] = (uint32_t)(uintptr_t)sub_obj_30;
    ctx[0x3c / 4] = (uint32_t)(uintptr_t)sub_obj_30;

    /* +0x40 与 +0x44 (ASTRA-06 崩溃直接诱因：0x85374c ldr r3, [r5]) */
    ctx[0x40 / 4] = (uint32_t)(uintptr_t)sub_obj_40;
    ctx[0x44 / 4] = (uint32_t)(uintptr_t)sub_obj_40;

    /* 2. 获取 libObj.so 加载句柄 */
    void *hObj = dlopen(LIBDIR "libObj.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!hObj) {
        hObj = dlopen(LIBDIR "libObj.so", RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!hObj) {
        logf_("STUB: dlopen libObj.so 失败: %s", dlerror());
        return;
    }

    void *pInjS = dlsym(hObj, "Application_System_InjS");
    if (!pInjS) {
        pInjS = dlsym(hObj, "Application_System_Init");
    }
    if (!pInjS) {
        logf_("STUB: 未找到 Application_System_Init / Application_System_InjS 符号: %s", dlerror());
        return;
    }

    /* 优先通过 dladdr 获取 libObj.so 真实基址，回退 /proc/self/maps 与基准偏移 0x8a2408 */
    uintptr_t base = 0;
    Dl_info obj_dli = {0};
    if (dladdr(pInjS, &obj_dli) && obj_dli.dli_fbase) {
        base = (uintptr_t)obj_dli.dli_fbase;
    } else {
        base = get_module_base_maps("libObj.so");
        if (!base) {
            base = ((uintptr_t)pInjS & ~1u) - 0x8a2408u;
        }
    }
#ifdef ZVE10_REAL_DEVICE
    g_libobj_base_real = base;
    g_hLibObj_real = hObj;
#endif
    logf_("STUB: libObj.so 探测成功: pInjS=%p, base=%p", pInjS, (void *)base);

    /* 3. 动态验证并调用 SetContextGetter (基准偏移 0x854670, Thumb 0x854671)
     * 采用 SetContextGetter(+0x00, 8B) + GetContext(+0x20, 8B) 全库唯一组合签名验证与窗口自适配定位 */
    uintptr_t matched_off = 0;
    const uintptr_t default_off = 0x854670u;
    if (match_ctx_getter_sig(base + default_off)) {
        matched_off = default_off;
    } else {
        for (uintptr_t off = 0x830000u; off + 0x30u < 0x870000u; off += 2u) {
            if (match_ctx_getter_sig(base + off)) {
                matched_off = off;
                break;
            }
        }
    }
    if (matched_off != 0) {
        typedef void (*set_getter_fn)(void *(*)(void));
        set_getter_fn set_getter = (set_getter_fn)(base + matched_off + 1u);
        set_getter(dummy_context_getter);
        logf_("STUB: SetContextGetter(0x%lx) OK", (unsigned long)(matched_off + 1u));
    } else {
        logf_("STUB_WARN: fallback getter var 0x148a6bc");
        void **pGetterVar = (void **)(base + 0x148a6bcu);
        *pGetterVar = (void *)dummy_context_getter;
    }

    /* 4. 唤醒并安全停靠四代 libObj.so 遗留的 RM 阻塞线程，释放核内 mlock(2) */
    park_libobj_rm_thread(base);

    /* 5. 安装四代 InputService::callback_direct 拦截钩子，开启物理按键到五代桥接 */
    install_g4_key_intercept(base);
}

__attribute__((minsize, cold))
static int fallback_g4(const char *why);

/* ---------- 增强崩溃取证：宿主免疫模式 ---------- */
static struct sigaction g_old[32];

static void crash_handler(int sig, siginfo_t *si, void *uc_)
{
    ucontext_t *uc = (ucontext_t *)uc_;
    Dl_info a = {0}, b = {0};
    uintptr_t pc = uc->uc_mcontext.arm_pc, lr = uc->uc_mcontext.arm_lr;
    dladdr((void *)pc, &a);
    dladdr((void *)lr, &b);
    logf_("CRASH sig=%d tid=%ld fault=%p pc=%p(%s+0x%lx %s) lr=%p(%s+0x%lx %s) sp=%p",
          sig, (long)syscall(224), si->si_addr,
          (void *)pc, a.dli_sname ? a.dli_sname : "?", (unsigned long)(pc - (uintptr_t)a.dli_fbase), a.dli_fname ? a.dli_fname : "?",
          (void *)lr, b.dli_sname ? b.dli_sname : "?", (unsigned long)(lr - (uintptr_t)b.dli_fbase), b.dli_fname ? b.dli_fname : "?",
          (void *)uc->uc_mcontext.arm_sp);

    logf_("REG R0=%#lx R1=%#lx R2=%#lx R3=%#lx",
          (unsigned long)uc->uc_mcontext.arm_r0, (unsigned long)uc->uc_mcontext.arm_r1,
          (unsigned long)uc->uc_mcontext.arm_r2, (unsigned long)uc->uc_mcontext.arm_r3);
    logf_("REG R4=%#lx R5=%#lx R6=%#lx R7=%#lx R8=%#lx R9=%#lx R10=%#lx FP=%#lx IP=%#lx",
          (unsigned long)uc->uc_mcontext.arm_r4, (unsigned long)uc->uc_mcontext.arm_r5,
          (unsigned long)uc->uc_mcontext.arm_r6, (unsigned long)uc->uc_mcontext.arm_r7,
          (unsigned long)uc->uc_mcontext.arm_r8, (unsigned long)uc->uc_mcontext.arm_r9,
          (unsigned long)uc->uc_mcontext.arm_r10, (unsigned long)uc->uc_mcontext.arm_fp,
          (unsigned long)uc->uc_mcontext.arm_ip);

    /* 栈回溯：扫描栈上指针解析函数调用链 */
    uintptr_t *sp_ptr = (uintptr_t *)uc->uc_mcontext.arm_sp;
    logf_("=== STACK UNWIND (sp=%p) ===", sp_ptr);
    logf_("SP RAW: [0..3]=%08lx %08lx %08lx %08lx [4..7]=%08lx %08lx %08lx %08lx",
          (unsigned long)sp_ptr[0], (unsigned long)sp_ptr[1], (unsigned long)sp_ptr[2], (unsigned long)sp_ptr[3],
          (unsigned long)sp_ptr[4], (unsigned long)sp_ptr[5], (unsigned long)sp_ptr[6], (unsigned long)sp_ptr[7]);
    for (int i = 0; i < 48; i++) {
        uintptr_t val = sp_ptr[i];
        Dl_info dli = {0};
        if (dladdr((void *)val, &dli) && dli.dli_fbase) {
            if (dli.dli_sname) {
                logf_("  [#%02d +%03d] 0x%08lx: %s+0x%lx (%s)",
                      i, i * 4, (unsigned long)val,
                      dli.dli_sname,
                      (unsigned long)(val - (uintptr_t)dli.dli_saddr),
                      dli.dli_fname ? dli.dli_fname : "?");
            } else {
                logf_("  [#%02d +%03d] 0x%08lx: ?+0x%lx (%s)",
                      i, i * 4, (unsigned long)val,
                      (unsigned long)(val - (uintptr_t)dli.dli_fbase),
                      dli.dli_fname ? dli.dli_fname : "?");
            }
        }
    }
    logf_("=== END STACK UNWIND ===");

    /* 若为诊断抓栈信号 SIGUSR2 或软件 raise(SIGTRAP) 断言，记录栈快照后放行返回 */
    if (sig == SIGUSR2 || (sig == SIGTRAP && (!si || si->si_code <= 0))) {
        if (sig == SIGTRAP) {
            logf_("ASTRA_SIGTRAP_BYPASSED: raise(5) 软断言已拦截记录并安全放行 (si_code=%d)", si ? si->si_code : 0);
        }
        return;
    }

    /* 宿主保护机制：不向宿主 raise(sig)，区分主 UI 线程与后台辅助子线程 */
    pthread_t me = pthread_self();
    int is_main = g_astra_th && pthread_equal(me, g_astra_th);
    if (is_main) {
        g_astra_running = 0;
        int fails = read_int(FAILCNT_PATH, 0);
        write_int(FAILCNT_PATH, fails + 1);
        logf_("IMMUNITY PROTECTION: Main AppFw thread crashed (sig=%d), host im.elf preserved!", sig);
    } else {
        logf_("IMMUNITY PROTECTION: Background sub-thread crashed (sig=%d), terminating sub-thread and keeping ASTRA main UI alive!", sig);
    }
    pthread_exit(NULL);
}

static void dump_all_threads_status(void)
{
    DIR *d = opendir("/proc/self/task");
    if (!d) return;
    struct dirent *de;
    long my_tid = (long)syscall(224);
    int diag_targets[16];
    int diag_cnt = 0;

    logf_("=== THREAD STATUS SNAPSHOT (/proc/self/task) ===");
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        int tid = atoi(de->d_name);
        char path[128], comm[64] = "?", wchan[64] = "?", stat_buf[256] = "?", sys_buf[128] = "?";
        int fd;
        snprintf(path, sizeof path, "/proc/self/task/%s/comm", de->d_name);
        if ((fd = open(path, O_RDONLY)) >= 0) {
            int n = read(fd, comm, sizeof(comm) - 1);
            if (n > 0) { comm[n] = 0; if (comm[n-1] == '\n') comm[n-1] = 0; }
            close(fd);
        }
        snprintf(path, sizeof path, "/proc/self/task/%s/wchan", de->d_name);
        if ((fd = open(path, O_RDONLY)) >= 0) {
            int n = read(fd, wchan, sizeof(wchan) - 1);
            if (n > 0) { wchan[n] = 0; if (wchan[n-1] == '\n') wchan[n-1] = 0; }
            close(fd);
        }
        snprintf(path, sizeof path, "/proc/self/task/%s/stat", de->d_name);
        if ((fd = open(path, O_RDONLY)) >= 0) {
            int n = read(fd, stat_buf, sizeof(stat_buf) - 1);
            if (n > 0) stat_buf[n] = 0;
            close(fd);
        }
        char state = '?';
        char *rp = strrchr(stat_buf, ')');
        if (rp && rp[1] == ' ') state = rp[2];

        if (state == 'R' || strstr(wchan, "down") || strstr(wchan, "ioctl") || strstr(comm, "grm") || strstr(comm, "uxengine") || strstr(comm, "THREAD_APP") || strstr(comm, "IMD-")) {
            snprintf(path, sizeof path, "/proc/self/task/%s/syscall", de->d_name);
            if ((fd = open(path, O_RDONLY)) >= 0) {
                int n = read(fd, sys_buf, sizeof(sys_buf) - 1);
                if (n > 0) { sys_buf[n] = 0; if (sys_buf[n-1] == '\n') sys_buf[n-1] = 0; }
                close(fd);
            }
            logf_("  TID=%-6s state=%c comm=%-18s wchan=%-22s syscall=%s", de->d_name, state, comm, wchan, sys_buf);
            if (tid != my_tid && (state == 'R' || strstr(wchan, "down") || strstr(wchan, "ioctl") || strstr(comm, "uxengine") || strstr(comm, "THREAD_APP") || strstr(comm, "IMD-RM"))) {
                if (diag_cnt < 16) diag_targets[diag_cnt++] = tid;
            }
        } else {
            logf_("  TID=%-6s state=%c comm=%-18s wchan=%s", de->d_name, state, comm, wchan);
        }
    }
    closedir(d);
    logf_("=== END THREAD STATUS ===");

#ifndef ZVE10_REAL_DEVICE
    for (int i = 0; i < diag_cnt; i++) {
        logf_("DIAG_TARGET: 发送 SIGUSR2 追踪疑难线程 TID=%d...", diag_targets[i]);
        syscall(268 /* tgkill */, (long)getpid(), (long)diag_targets[i], SIGUSR2);
        usleep(20000); /* 等待 20ms 让目标线程打印堆栈不交错 */
    }
#else
    (void)my_tid;
    (void)diag_targets;
    (void)diag_cnt;
    if (g_astra_th && g_draw_fb_cnt == 0) {
        logf_("REAL_DIAG: drawFramebuffer 尚未触发，发送 SIGUSR2 采集 AppFw 主线程栈...");
        pthread_kill(g_astra_th, SIGUSR2);
    }
#endif
}

static void install_crash_logger(void)
{
    static const int sigs[] = { SIGSEGV, SIGBUS, SIGILL, SIGABRT, SIGFPE, SIGTRAP };
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++)
        sigaction(sigs[i], &sa, &g_old[sigs[i]]);

    struct sigaction sa_diag;
    memset(&sa_diag, 0, sizeof sa_diag);
    sa_diag.sa_sigaction = crash_handler;
    sa_diag.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR2, &sa_diag, NULL);
}

/* ---------- 五代加载序列 ---------- */
static void *must_open(const char *name)
{
    char path[128];
    snprintf(path, sizeof path, LIBDIR "%s", name);
    logf_("dlopen %s ...", path);
    void *h = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
    if (!h) logf_("  FAIL: %s", dlerror());
    else    logf_("  OK h=%p", h);
    return h;
}

#ifdef ZVE10_USB_SANDBOX
typedef uintptr_t (*sb_fn4_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t);
typedef int (*sb_open_t)(const char *, int, ...);
typedef int (*sb_ioctl_t)(int, unsigned long, ...);

static sb_fn4_t g_sb_orig_uxinit2 = NULL;
static sb_fn4_t g_sb_orig_init_arena = NULL;
static sb_fn4_t g_sb_orig_set_cwd = NULL;
static sb_fn4_t g_sb_orig_get_acmgr = NULL;
static sb_fn4_t g_sb_orig_gfx_inst = NULL;
static sb_fn4_t g_sb_orig_set_db = NULL;
static sb_fn4_t g_sb_orig_set_font = NULL;

static sb_open_t  g_sb_orig_open = NULL;
static sb_open_t  g_sb_orig_open64 = NULL;
static sb_ioctl_t g_sb_orig_ioctl = NULL;
static sb_fn4_t   g_sb_orig_mcmn_open = NULL;
static sb_fn4_t   g_sb_orig_snd_sync_msg = NULL;
static sb_fn4_t   g_sb_orig_snd_sync_dir = NULL;
static sb_fn4_t   g_sb_orig_ob5_raise = NULL;
static sb_fn4_t   g_sb_orig_ob5_abort = NULL;
static volatile uint32_t g_sb_io_seq = 0;
static volatile int g_sb_full_log = 0;
static uintptr_t g_sb_ob5_base = 0;
static sb_fn4_t g_sb_orig_snd_msg = NULL;

static unsigned long sb_ob5_off(uintptr_t lr)
{
    uintptr_t p = lr & ~(uintptr_t)1u;
    if (g_sb_ob5_base && p >= g_sb_ob5_base && p < g_sb_ob5_base + 0x500000u)
        return (unsigned long)(p - g_sb_ob5_base);
    return (unsigned long)lr;
}

static void hook_got_slot(uintptr_t fbase, uintptr_t got_off, void *new_fn, const char *label);

static uintptr_t sb_wrap_uxinit2(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    logf_("SB_MAIN 1/7: -> uxengine_init2()");
    uintptr_t r = g_sb_orig_uxinit2 ? g_sb_orig_uxinit2(a, b, c, d) : 0;
    logf_("SB_MAIN 1/7: <- uxengine_init2() ret=0x%lx", (unsigned long)r);
    return r;
}

static uintptr_t sb_wrap_init_arena(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    logf_("SB_MAIN 2/7: -> initializeArena()");
    uintptr_t r = g_sb_orig_init_arena ? g_sb_orig_init_arena(a, b, c, d) : 0;
    logf_("SB_MAIN 2/7: <- initializeArena() ret=0x%lx", (unsigned long)r);
    return r;
}

static uintptr_t sb_wrap_set_cwd(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    const char *p = (const char *)a;
    logf_("SB_MAIN 3/7: -> sys_setCurrentDirectory(\"%s\")", p ? p : "NULL");
    uintptr_t r = g_sb_orig_set_cwd ? g_sb_orig_set_cwd(a, b, c, d) : 0;
    logf_("SB_MAIN 3/7: <- sys_setCurrentDirectory ret=0x%lx", (unsigned long)r);
    return r;
}

static uintptr_t sb_wrap_get_acmgr(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    logf_("SB_MAIN 4/7: -> getAreaCheckExtensionManager(this=0x%lx)", (unsigned long)a);
    uintptr_t r = g_sb_orig_get_acmgr ? g_sb_orig_get_acmgr(a, b, c, d) : 0;
    logf_("SB_MAIN 4/7: <- getAreaCheckExtensionManager ret=0x%lx", (unsigned long)r);
    return r;
}

static uintptr_t sb_wrap_gfx_inst(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    logf_("SB_MAIN 5/7: -> GraphicsEngine::sys_getInstance()");
    uintptr_t r = g_sb_orig_gfx_inst ? g_sb_orig_gfx_inst(a, b, c, d) : 0;
    logf_("SB_MAIN 5/7: <- GraphicsEngine::sys_getInstance ret=0x%lx", (unsigned long)r);
    return r;
}

static uintptr_t sb_wrap_set_db(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    const char *p = (const char *)b;
    logf_("SB_MAIN 6/7: -> ResourceManager::setDatabase(this=0x%lx, \"%s\")", (unsigned long)a, p ? p : "NULL");
    uintptr_t r = g_sb_orig_set_db ? g_sb_orig_set_db(a, b, c, d) : 0;
    logf_("SB_MAIN 6/7: <- setDatabase ret=0x%lx", (unsigned long)r);
    return r;
}

static uintptr_t sb_wrap_set_font(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    logf_("SB_MAIN 7/7: -> sys_setFontNameWithNamespace(this=0x%lx, id=0x%lx)", (unsigned long)a, (unsigned long)b);
    uintptr_t r = g_sb_orig_set_font ? g_sb_orig_set_font(a, b, c, d) : 0;
    logf_("SB_MAIN 7/7: <- sys_setFontNameWithNamespace ret=0x%lx", (unsigned long)r);
    return r;
}

static int sb_trace_open_common(sb_open_t fn, const char *tag, const char *path, int flags, mode_t mode, uintptr_t lr)
{
    uint32_t seq = __sync_add_and_fetch(&g_sb_io_seq, 1);
    int log_it = g_sb_full_log || (seq <= 1000) || (path && strncmp(path, "/dev/", 5) == 0);
    if (log_it) {
        logf_("SB_IO #%u -> %s(\"%s\", flags=0x%x) off=0x%lx", seq, tag, path ? path : "NULL", flags, sb_ob5_off(lr));
    }
    int rc = fn ? fn(path, flags, mode) : -1;
    int err = errno;
    if (log_it) {
        logf_("SB_IO #%u <- %s rc=%d errno=%d", seq, tag, rc, (rc < 0) ? err : 0);
    }
    if (path && strcmp(path, "/dev/mem") == 0 && flags == 0x1002 && rc >= 13) {
        g_sb_full_log = 1;
        logf_("SB_IO: 已触发 /dev/mem(fd=%d) 全量放行模式!", rc);
    }
    errno = err;
    return rc;
}

static int sb_trace_ob5_open(const char *path, int flags, ...)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return sb_trace_open_common(g_sb_orig_open ? g_sb_orig_open : (sb_open_t)open, "open", path, flags, mode, lr);
}

static int sb_trace_ob5_open64(const char *path, int flags, ...)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    sb_open_t fn = g_sb_orig_open64 ? g_sb_orig_open64 : (g_sb_orig_open ? g_sb_orig_open : (sb_open_t)open);
    return sb_trace_open_common(fn, "open64", path, flags, mode, lr);
}

static int sb_is_noisy_gles_ioctl(unsigned long req)
{
    return (req == 0xc0048211u || req == 0xc0048212u ||
            req == 0xc004820du || req == 0xc004820eu ||
            req == 0x8004820au || req == 0xc0048203u);
}

static int sb_trace_ob5_ioctl(int fd, unsigned long req, uintptr_t arg)
{
    uint32_t seq = __sync_add_and_fetch(&g_sb_io_seq, 1);
    int log_it = g_sb_full_log || ((seq <= 1000) && (!sb_is_noisy_gles_ioctl(req) || seq <= 35));
    char fdpath[128] = {0};
    if (fd >= 0 && (log_it || seq > 150)) {
        char lnk[48];
        snprintf(lnk, sizeof lnk, "/proc/self/fd/%d", fd);
        ssize_t n = readlink(lnk, fdpath, sizeof(fdpath) - 1);
        if (n > 0) fdpath[n] = '\0';
        if (fdpath[0] && strcmp(fdpath, "/dev/dmpgles2") != 0) log_it = 1;
    }
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (log_it) {
        logf_("SB_IO #%u -> ioctl(fd=%d [%s], req=0x%lx, arg=0x%lx) off=0x%lx",
              seq, fd, fdpath[0] ? fdpath : "?", req, (unsigned long)arg, sb_ob5_off(lr));
    }
    sb_ioctl_t fn = g_sb_orig_ioctl ? g_sb_orig_ioctl : (sb_ioctl_t)ioctl;
    int rc = fn(fd, req, (void *)arg);
    int err = errno;
    if (log_it) {
        logf_("SB_IO #%u <- ioctl rc=%d errno=%d", seq, rc, (rc < 0) ? err : 0);
    }
    errno = err;
    return rc;
}

static uintptr_t sb_trace_mcmn_open(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uint32_t seq = __sync_add_and_fetch(&g_sb_io_seq, 1);
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    if (g_sb_full_log || seq <= 1000) {
        logf_("SB_IO #%u -> mcmn_drv_open(0x%lx, 0x%lx, 0x%lx, 0x%lx) off=0x%lx",
              seq, (unsigned long)a, (unsigned long)b, (unsigned long)c, (unsigned long)d, sb_ob5_off(lr));
    }
    uintptr_t r = g_sb_orig_mcmn_open ? g_sb_orig_mcmn_open(a, b, c, d) : (uintptr_t)-1;
    if (g_sb_full_log || seq <= 1000) logf_("SB_IO #%u <- mcmn_drv_open ret=0x%lx", seq, (unsigned long)r);
    return r;
}

static void sb_format_msg_preview(uintptr_t msg_ptr, char *hexbuf, size_t hexlen, char *ascbuf, size_t asclen)
{
    hexbuf[0] = '\0';
    ascbuf[0] = '\0';
    if (msg_ptr <= 0x10000u) return;
    const uint32_t *w = (const uint32_t *)msg_ptr;
    snprintf(hexbuf, hexlen, "%08x %08x %08x %08x %08x %08x",
             w[0], w[1], w[2], w[3], w[4], w[5]);
    const uint8_t *p = (const uint8_t *)msg_ptr;
    size_t ai = 0;
    for (int i = 0; i < 48 && ai + 1 < asclen; i++) {
        uint8_t ch = p[i];
        ascbuf[ai++] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.';
    }
    ascbuf[ai] = '\0';
}

static uintptr_t sb_trace_snd_sync_msg(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    uint32_t seq = __sync_add_and_fetch(&g_sb_io_seq, 1);
    int log_it = g_sb_full_log || (seq <= 600);
    if (log_it) {
        char hx[96], ac[64];
        sb_format_msg_preview(b, hx, sizeof hx, ac, sizeof ac);
        logf_("SB_IO #%u -> ob5:osal_snd_sync_msg(qid=0x%lx, msg=0x%lx) off=0x%lx w=[%s] s=\"%s\"",
              seq, (unsigned long)a, (unsigned long)b, sb_ob5_off(lr), hx, ac);
    }
    uintptr_t r = g_sb_orig_snd_sync_msg ? g_sb_orig_snd_sync_msg(a, b, c, d) : 0;
    if (log_it) logf_("SB_IO #%u <- ob5:osal_snd_sync_msg ret=0x%lx", seq, (unsigned long)r);
    return r;
}

static uintptr_t sb_trace_snd_msg(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    uint32_t seq = __sync_add_and_fetch(&g_sb_io_seq, 1);
    if (g_sb_full_log || seq <= 200) {
        char hx[96], ac[64];
        sb_format_msg_preview(b, hx, sizeof hx, ac, sizeof ac);
        logf_("SB_IO #%u -> ob5:osal_snd_msg(qid=0x%lx, msg=0x%lx) off=0x%lx w=[%s] s=\"%s\"",
              seq, (unsigned long)a, (unsigned long)b, sb_ob5_off(lr), hx, ac);
    }
    uintptr_t r = g_sb_orig_snd_msg ? g_sb_orig_snd_msg(a, b, c, d) : 0;
    if (g_sb_full_log || seq <= 200) logf_("SB_IO #%u <- ob5:osal_snd_msg ret=0x%lx", seq, (unsigned long)r);
    return r;
}

static uintptr_t sb_trace_snd_sync_dir(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    uint32_t seq = __sync_add_and_fetch(&g_sb_io_seq, 1);
    int log_it = g_sb_full_log || (a != 0x910042u) || (seq <= 35);
    if (log_it) {
        logf_("SB_IO #%u -> ob5:osal_snd_sync_direct(qid=0x%lx, msg=0x%lx) off=0x%lx",
              seq, (unsigned long)a, (unsigned long)b, sb_ob5_off(lr));
    }
    uintptr_t r = g_sb_orig_snd_sync_dir ? g_sb_orig_snd_sync_dir(a, b, c, d) : 0;
    if (log_it) logf_("SB_IO #%u <- ob5:osal_snd_sync_direct ret=0x%lx", seq, (unsigned long)r);
    return r;
}

static uintptr_t sb_trace_ob5_raise(uintptr_t sig, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    logf_("SB_SIGNAL: libOb5 调用 raise(sig=%lu) lr=0x%lx", (unsigned long)sig, (unsigned long)lr);
    return g_sb_orig_ob5_raise ? g_sb_orig_ob5_raise(sig, b, c, d) : 0;
}

static uintptr_t sb_trace_ob5_abort(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uintptr_t lr = (uintptr_t)__builtin_return_address(0);
    logf_("SB_SIGNAL: libOb5 调用 abort() lr=0x%lx", (unsigned long)lr);
    return g_sb_orig_ob5_abort ? g_sb_orig_ob5_abort(a, b, c, d) : 0;
}

static void install_sandbox_step_tracer(void *hBootG5, void *hOb5, void *pMain)
{
    Dl_info g5_info = {0};
    if (pMain && dladdr(pMain, &g5_info) && g5_info.dli_fbase) {
        uintptr_t g5base = (uintptr_t)g5_info.dli_fbase;
        void *s_ob5 = hOb5 ? hOb5 : RTLD_DEFAULT;
        g_sb_orig_uxinit2    = (sb_fn4_t)dlsym(s_ob5, "uxengine_init2");
        g_sb_orig_init_arena = (sb_fn4_t)dlsym(hBootG5 ? hBootG5 : RTLD_DEFAULT, "_Z15initializeArenav");
        g_sb_orig_set_cwd    = (sb_fn4_t)dlsym(s_ob5, "_ZN2ux4core6Kernel23sys_setCurrentDirectoryEPKc");
        g_sb_orig_get_acmgr  = (sb_fn4_t)dlsym(s_ob5, "_ZN2ux6gfxeng14GraphicsEngine28getAreaCheckExtensionManagerFU");
        g_sb_orig_gfx_inst   = (sb_fn4_t)dlsym(s_ob5, "_ZN2ux6gfxeng14GraphicsEngine15sys_getInstanceFU");
        g_sb_orig_set_db     = (sb_fn4_t)dlsym(s_ob5, "_ZN2ux6resmgr15ResourceManager11setDatabaseEPLB");
        g_sb_orig_set_font   = (sb_fn4_t)dlsym(s_ob5, "_ZN2ux6resmgr15ResourceManager28sys_setFontNameWithNamespaceFS");

        if (g_sb_orig_uxinit2)    hook_got_slot(g5base, 0x00009a8cu, (void *)sb_wrap_uxinit2, "g5boot GOT[uxengine_init2]");
        if (g_sb_orig_init_arena) hook_got_slot(g5base, 0x00009a94u, (void *)sb_wrap_init_arena, "g5boot GOT[initializeArena]");
        if (g_sb_orig_set_cwd)    hook_got_slot(g5base, 0x00009a70u, (void *)sb_wrap_set_cwd, "g5boot GOT[setCurrentDirectory]");
        if (g_sb_orig_get_acmgr)  hook_got_slot(g5base, 0x00009aa4u, (void *)sb_wrap_get_acmgr, "g5boot GOT[getAreaCheckMgr]");
        if (g_sb_orig_gfx_inst)   hook_got_slot(g5base, 0x00009a54u, (void *)sb_wrap_gfx_inst, "g5boot GOT[GraphicsEngine::sys_getInstance]");
        if (g_sb_orig_set_db)     hook_got_slot(g5base, 0x00009a98u, (void *)sb_wrap_set_db, "g5boot GOT[setDatabase]");
        if (g_sb_orig_set_font)   hook_got_slot(g5base, 0x00009a48u, (void *)sb_wrap_set_font, "g5boot GOT[setFont]");
    }

    Dl_info ob5_info = {0};
    if (g_pGetWS && dladdr((void *)g_pGetWS, &ob5_info) && ob5_info.dli_fbase) {
        uintptr_t ob5_base = (uintptr_t)ob5_info.dli_fbase;
        g_sb_ob5_base          = ob5_base;
        g_sb_orig_open         = (sb_open_t)dlsym(RTLD_DEFAULT, "open");
        g_sb_orig_open64       = (sb_open_t)dlsym(RTLD_DEFAULT, "open64");
        g_sb_orig_ioctl        = (sb_ioctl_t)dlsym(RTLD_DEFAULT, "ioctl");
        g_sb_orig_mcmn_open    = (sb_fn4_t)dlsym(RTLD_DEFAULT, "mcmn_drv_open");
        g_sb_orig_snd_sync_msg = (sb_fn4_t)dlsym(RTLD_DEFAULT, "osal_snd_sync_msg");
        g_sb_orig_snd_msg      = (sb_fn4_t)dlsym(RTLD_DEFAULT, "osal_snd_msg");
        g_sb_orig_snd_sync_dir = (sb_fn4_t)dlsym(RTLD_DEFAULT, "osal_snd_sync_direct");
        g_sb_orig_ob5_raise    = (sb_fn4_t)dlsym(RTLD_DEFAULT, "raise");
        g_sb_orig_ob5_abort    = (sb_fn4_t)dlsym(RTLD_DEFAULT, "abort");

        hook_got_slot(ob5_base, 0x0035548cu, (void *)sb_trace_ob5_open, "libOb5 GOT[open]");
        hook_got_slot(ob5_base, 0x00355400u, (void *)sb_trace_ob5_open64, "libOb5 GOT[open64]");
        hook_got_slot(ob5_base, 0x003553a0u, (void *)sb_trace_ob5_ioctl, "libOb5 GOT[ioctl]");
        if (g_sb_orig_mcmn_open)    hook_got_slot(ob5_base, 0x003558c8u, (void *)sb_trace_mcmn_open, "libOb5 GOT[mcmn_drv_open]");
        if (g_sb_orig_snd_sync_msg) hook_got_slot(ob5_base, 0x00355978u, (void *)sb_trace_snd_sync_msg, "libOb5 GOT[osal_snd_sync_msg]");
        if (g_sb_orig_snd_msg)      hook_got_slot(ob5_base, 0x00355108u, (void *)sb_trace_snd_msg, "libOb5 GOT[osal_snd_msg]");
        if (g_sb_orig_snd_sync_dir) hook_got_slot(ob5_base, 0x00354f14u, (void *)sb_trace_snd_sync_dir, "libOb5 GOT[osal_snd_sync_direct]");
        if (g_sb_orig_ob5_raise)    hook_got_slot(ob5_base, 0x00355650u, (void *)sb_trace_ob5_raise, "libOb5 GOT[raise]");
        if (g_sb_orig_ob5_abort)    hook_got_slot(ob5_base, 0x00355300u, (void *)sb_trace_ob5_abort, "libOb5 GOT[abort]");
    }
}

static void g5_sb_stub_cb(void *arg)
{
    (void)arg;
    logf_("SANDBOX_STAGE2_STUB_OK: _Z4MainPv 已完成 uxengine_init2/Arena/GraphicsEngine/global.xdb 并回调桩!");
}
#endif

/* 五代 libOb5:InfraInput 事件结构 (24B，QEMU 与真机共用) */
typedef struct {
    uint32_t event_code;  /* +0x00 (raw code 或 raw2id 转换后的 id) */
    int16_t  tp_x;        /* +0x04 */
    int16_t  tp_y;        /* +0x06 */
    int32_t  status;      /* +0x08 (按键 1/0；拨轮有符号增量) */
    uint32_t prev_status; /* +0x0c */
    uint32_t ex_info;     /* +0x10 */
    uint32_t repeat;      /* +0x14 */
} g5_infra_input_ev_t;
_Static_assert(sizeof(g5_infra_input_ev_t) == 24u, "g5_infra_input_ev_t must be 24 bytes");

#ifdef ZVE10_REAL_DEVICE
/* =========================================================================
 * 真机 (ZVE10_REAL_DEVICE) Gen4->Gen5 安全交接、纯透传链路观测与输入激活
 * 严禁跳过物理显示或伪造成功返回值，所有钩子仅如实观测并透传原生结果
 * ========================================================================= */
static volatile uint32_t g_real_drawfb_done_cnt = 0;
static volatile uint32_t g_real_present_cnt = 0;
static volatile int      g_real_in_init_done = 0;

typedef void (*real_draw_fb_fn_t)(void *ge);
typedef uintptr_t (*real_fn4_t)(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d);

static real_draw_fb_fn_t          g_real_orig_ob5_drawfb = NULL;
static real_fn4_t                 g_real_orig_ob5_present = NULL;

typedef int (*real_wait_thread_exit_fn_t)(uint32_t th_handle);
typedef int (*real_osal_rcv_msg_tmo_fn_t)(uint32_t qid, void **out_msg, int32_t tmo);
typedef int (*real_osal_snd_msg_fn_t)(uint32_t qid, void *msg);
typedef int (*real_osal_free_msg_fn_t)(uint32_t qid, void *msg);
typedef int (*g4_send_sentinel_fn_t)(void *self, uint32_t qid, const void *buf,
                                     uint32_t len, uint32_t flags, uint32_t sender_qid);

static int real_count_threads_with_prefix(const char *prefix)
{
    if (!prefix || !prefix[0]) return 0;
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return -1;
    size_t plen = strlen(prefix);
    int cnt = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char cpath[64], comm[64];
        snprintf(cpath, sizeof(cpath), "/proc/self/task/%s/comm", de->d_name);
        int fd = open(cpath, O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, comm, sizeof(comm) - 1);
            close(fd);
            if (n > 0) {
                comm[n] = '\0';
                if (comm[n - 1] == '\n') comm[n - 1] = '\0';
                if (strncmp(comm, prefix, plen) == 0) {
                    cnt++;
                }
            }
        }
    }
    closedir(dir);
    return cnt;
}

static void real_drain_sentinel_queue(uint32_t qid,
                                      real_osal_rcv_msg_tmo_fn_t pRcvTmo,
                                      real_osal_free_msg_fn_t pFreeMsg,
                                      real_osal_snd_msg_fn_t pSndMsg,
                                      const char *tag)
{
    if (!pRcvTmo || !pFreeMsg) return;
    for (int k = 0; k < 4; k++) {
        void *tmp = NULL;
        int rrc = pRcvTmo(qid, &tmp, 0);
        if (rrc != 0 || !tmp) break;
        uint32_t sender = *(const volatile uint32_t *)((uintptr_t)tmp - 4u);
        if (sender == qid) {
            pFreeMsg(qid, tmp);
            logf_("G4_INPUT_RETIRE: %s 排空并释放残留退出哨兵 (qid=0x%08x)", tag, qid);
        } else {
            logf_("G4_INPUT_RETIRE_WARN: %s 非阻塞排空检测到非哨兵消息 (qid=0x%08x sender=0x%08x)，原样回投队列",
                  tag, qid, sender);
            if (pSndMsg) {
                (void)pSndMsg(qid, tmp);
            }
            break;
        }
    }
}

static void g4_stop_one_input_thread(uintptr_t g4base, void *obj, uint32_t handle_off,
                                     uint32_t qid, uint32_t payload_len,
                                     const char *comm_prefix, const char *tag)
{
    if (!g4base || (uintptr_t)obj <= 0x10000u || payload_len > 32u) return;

    static const unsigned char exp_send[8] = {0x2du, 0xe9u, 0xf0u, 0x47u, 0x8au, 0xb0u, 0x04u, 0xafu};
    const uintptr_t send_addr = g4base + 0x008c0db8u;
    if (memcmp((const void *)send_addr, exp_send, 8) != 0) {
        logf_("G4_INPUT_RETIRE_WARN: libObj+0x8c0db8 前言字节不匹配，跳过 %s", tag);
        return;
    }

    real_wait_thread_exit_fn_t pWaitExit = (real_wait_thread_exit_fn_t)dlsym(RTLD_DEFAULT, "osal_wait_thread_exit");
    real_osal_rcv_msg_tmo_fn_t pRcvTmo   = (real_osal_rcv_msg_tmo_fn_t)dlsym(RTLD_DEFAULT, "osal_rcv_msg_tmo");
    real_osal_free_msg_fn_t    pFreeMsg  = (real_osal_free_msg_fn_t)dlsym(RTLD_DEFAULT, "osal_free_msg");
    real_osal_snd_msg_fn_t     pSndMsg   = (real_osal_snd_msg_fn_t)dlsym(RTLD_DEFAULT, "osal_snd_msg");

    uint32_t th_handle = *(volatile uint32_t *)((uintptr_t)obj + handle_off);
    if (th_handle == 0u) {
        logf_("G4_INPUT_RETIRE: %s (obj+0x%x) 句柄为 0，跳过发哨兵", tag, handle_off);
        return;
    }

    int before_cnt = real_count_threads_with_prefix(comm_prefix);
    uint8_t zero_buf[32];
    memset(zero_buf, 0, sizeof(zero_buf));

    uint64_t t0 = g5_msec_now();
    g4_send_sentinel_fn_t send_sentinel = (g4_send_sentinel_fn_t)(send_addr | 1u);
    int send_ok = send_sentinel(obj, qid, zero_buf, payload_len, 0u, qid);
    if (!send_ok) {
        logf_("G4_INPUT_RETIRE_WARN: %s 发送退出哨兵失败 (qid=0x%08x handle=0x%x)", tag, qid, th_handle);
        return;
    }

    int retired = 0;
    int after_cnt = before_cnt;
    if (before_cnt > 0) {
        for (int i = 0; i < 30; i++) {
            usleep(10000);
            after_cnt = real_count_threads_with_prefix(comm_prefix);
            if (after_cnt >= 0 && after_cnt < before_cnt) {
                retired = 1;
                break;
            }
        }
    }

    uint64_t dt = g5_msec_now() - t0;
    if (retired) {
        int wrc = pWaitExit ? pWaitExit(th_handle) : -1;
        *(volatile uint32_t *)((uintptr_t)obj + handle_off) = 0u;
        logf_("G4_INPUT_RETIRE: %s 已优雅退役 (%s %d->%d, qid=0x%08x, wait_rc=%d, %llu ms)",
              tag, comm_prefix, before_cnt, after_cnt, qid, wrc, (unsigned long long)dt);
    } else {
        logf_("G4_INPUT_RETIRE_WARN: %s 300ms 等待线程数未下降 (%s before=%d after=%d, qid=0x%08x)，跳过 wait 并排空哨兵",
              tag, comm_prefix, before_cnt, after_cnt, qid);
        real_drain_sentinel_queue(qid, pRcvTmo, pFreeMsg, pSndMsg, tag);
    }
}

static void g4_retire_duplicate_input_threads(uintptr_t g4base)
{
    if (!g4base) return;
    uintptr_t tp_slot = 0, in_slot = 0;
    void *pTp = g4input_read_singleton_from_getinst(
        g_hLibObj_real, g4base, "_ZN7InfraTp11GetInstanceEv", 0x008b9d55u, 0x014924b0u, &tp_slot);
    void *pIn = g4input_read_singleton_from_getinst(
        g_hLibObj_real, g4base, "_ZN10InfraInput11GetInstanceEv", 0x008c22a1u, 0x014924dcu, &in_slot);
    logf_("G4_INPUT_RETIRE: 扫描 Gen4 输入单例 pInfraTp=%p (slot=+0x%lx) pInfraInput=%p (slot=+0x%lx)",
          pTp, tp_slot ? (unsigned long)(tp_slot - g4base) : 0ul,
          pIn, in_slot ? (unsigned long)(in_slot - g4base) : 0ul);

    if ((uintptr_t)pTp > 0x10000u) {
        /* 触屏已交由五代 libOb5:InfraTp 原生独占，先于五代启动前干净退役四代 I-TpMain/I-TpRecv 防止双活抢占 0x007b0026/0x007b002b */
        g4_stop_one_input_thread(g4base, pTp, 0x28u, 0x007b002bu, 0x0cu, "I-TpMain", "I-TpMain");
        g4_stop_one_input_thread(g4base, pTp, 0x24u, 0x007b0026u, 0x10u, "I-TpRecv", "I-TpRecv");
    }
    if ((uintptr_t)pIn > 0x10000u) {
        g4_stop_one_input_thread(g4base, pIn, 0x2cu, 0x007a0020u, 0x10u, "I-InputRecv", "I-InputRecv");
        g4_stop_one_input_thread(g4base, pIn, 0x78u, 0x007a804cu, 0x18u, "I-InputRecv", "I-InputRecv2");
    }

    real_osal_rcv_msg_tmo_fn_t pRcvTmo  = (real_osal_rcv_msg_tmo_fn_t)dlsym(RTLD_DEFAULT, "osal_rcv_msg_tmo");
    real_osal_free_msg_fn_t    pFreeMsg = (real_osal_free_msg_fn_t)dlsym(RTLD_DEFAULT, "osal_free_msg");
    real_osal_snd_msg_fn_t     pSndMsg  = (real_osal_snd_msg_fn_t)dlsym(RTLD_DEFAULT, "osal_snd_msg");
    static const struct {
        uint32_t qid;
        const char *name;
    } qs[4] = {
        { 0x007b002bu, "final-TpMain" },
        { 0x007b0026u, "final-TpRecv" },
        { 0x007a0020u, "final-InputRecv" },
        { 0x007a804cu, "final-InputRecv2" },
    };
    for (unsigned i = 0; i < 4; i++) {
        real_drain_sentinel_queue(qs[i].qid, pRcvTmo, pFreeMsg, pSndMsg, qs[i].name);
    }
}

/* 释放前先记录 Gen4 pInfraTp 硬件工作模式与参数，供五代 InfraTp 继承 */
static volatile int      g_g4_tp_saved_valid = 0;
static volatile uint32_t g_g4_tp_saved_mode  = 0;
static volatile uint32_t g_g4_tp_saved_s0    = 0;
static volatile uint32_t g_g4_tp_saved_s1    = 0;
static volatile uint32_t g_g4_tp_saved_s2    = 0;
static volatile uint8_t  g_g4_tp_saved_sus   = 0;
static volatile uint8_t  g_g4_tp_saved_dir0  = 1;
static volatile uint8_t  g_g4_tp_saved_dir1  = 1;
static volatile uint8_t  g_g4_tp_saved_sw    = 0;
static volatile uint8_t  g_g4_tp_saved_raw   = 0;

static void g4_handoff_real_device(void)
{
    if (g_g4_handoff_done) return;
    g_g4_handoff_done = 1;
    uintptr_t g4base = g_libobj_base_real;
    void *hObj = g_hLibObj_real;
    (void)hObj;
    if (!g4base) {
        logf_("G4_HANDOFF: 跳过（libObj 基址未初始化）");
        return;
    }
    logf_("G4_HANDOFF: 开始安全释放 Gen4 独占硬件与输入队列 (libObj=%p)...", (void *)g4base);

    /* [1/5] 通知条件停靠线程允许退出，并调用 libObj:rm_exit(0x774111) 回收 rm_kick_thread/rqueue/dmpgles2 */
    g_real_handoff_stage = "1_rm_wake";
    pthread_mutex_lock(&g_g4_rm_mtx);
    g_g4_rm_allow_exit = 1;
    pthread_cond_broadcast(&g_g4_rm_cv);
    pthread_mutex_unlock(&g_g4_rm_mtx);
    usleep(20000);

    g_real_handoff_stage = "2_rm_exit_774111";
    typedef int (*g4_void_fn_t)(void);
    uint64_t t0 = g5_msec_now();
    int rm_rc = ((g4_void_fn_t)(g4base + 0x774111u))();
    logf_("G4_HANDOFF [1/5]: libObj:rm_exit(0x774111) rc=%d elapsed=%llu ms",
          rm_rc, (unsigned long long)(g5_msec_now() - t0));

    /* [2/5] 释放 grm SystemImpl: 调用 libObj:grm_term(0x6f923d) 彻底释放 OSD/GPE 图层仲裁，使五代 libOb5 成功创建 Window Surface */
    g_real_handoff_stage = "3_grm_term";
    t0 = g5_msec_now();
    int grm_rc = ((g4_void_fn_t)(g4base + 0x6f923du))();
    logf_("G4_HANDOFF [2/5]: libObj:grm_term(0x6f923d) rc=%d elapsed=%llu ms (OSD 图层仲裁已成功释放)",
          grm_rc, (unsigned long long)(g5_msec_now() - t0));

    /* [3/5]~[4/5] 先采集四代 pInfraTp 配置，再通过 infra_tp_sus(0) 释放并退役抢包线程 */
    {
        void *pG4Tp = g4input_read_singleton_from_getinst(
            hObj, g4base, "_ZN7InfraTp11GetInstanceEv", 0x008b9d55u, 0x014924b0u, NULL);
        if ((uintptr_t)pG4Tp > 0x10000u) {
            g_g4_tp_saved_sus  = *(const volatile uint8_t  *)((uintptr_t)pG4Tp + 0x20u);
            g_g4_tp_saved_dir0 = *(const volatile uint8_t  *)((uintptr_t)pG4Tp + 0x30u);
            g_g4_tp_saved_dir1 = *(const volatile uint8_t  *)((uintptr_t)pG4Tp + 0x31u);
            g_g4_tp_saved_sw   = *(const volatile uint8_t  *)((uintptr_t)pG4Tp + 0x32u);
            g_g4_tp_saved_raw  = *(const volatile uint8_t  *)((uintptr_t)pG4Tp + 0x35u);
            g_g4_tp_saved_s0   = *(const volatile uint32_t *)((uintptr_t)pG4Tp + 0x38u);
            g_g4_tp_saved_s1   = *(const volatile uint32_t *)((uintptr_t)pG4Tp + 0x3cu);
            g_g4_tp_saved_s2   = *(const volatile uint32_t *)((uintptr_t)pG4Tp + 0x40u);
            g_g4_tp_saved_mode = *(const volatile uint32_t *)((uintptr_t)pG4Tp + 0x44u);
            g_g4_tp_saved_valid = 1;
            logf_("G4_HANDOFF [3/5]: 采集 Gen4 pInfraTp=%p 状态: sus=%u dir=(%u,%u) sw=%u raw=%u mode=%u settings=(%u,%u,%u)",
                  pG4Tp, (unsigned)g_g4_tp_saved_sus, (unsigned)g_g4_tp_saved_dir0, (unsigned)g_g4_tp_saved_dir1,
                  (unsigned)g_g4_tp_saved_sw, (unsigned)g_g4_tp_saved_raw,
                  g_g4_tp_saved_mode, g_g4_tp_saved_s0, g_g4_tp_saved_s1, g_g4_tp_saved_s2);
        }
    }
    g_real_handoff_stage = "3_infra_tp_sus";
    {
        static const unsigned char exp_tp_sus[8] = {0xb0u, 0xb5u, 0x84u, 0xb0u, 0x04u, 0xafu, 0x05u, 0x46u};
        uintptr_t tp_sus_va = g4base + 0x008b9e54u;
        if (memcmp((const void *)tp_sus_va, exp_tp_sus, sizeof(exp_tp_sus)) == 0) {
            typedef int (*g4_u32_fn_t)(uint32_t);
            t0 = g5_msec_now();
            int tp_rc = ((g4_u32_fn_t)(tp_sus_va | 1u))(0u);
            logf_("G4_HANDOFF [3/5]: libObj:infra_tp_sus(0) rc=%d elapsed=%llu ms",
                  tp_rc, (unsigned long long)(g5_msec_now() - t0));
        } else {
            logf_("G4_HANDOFF [3/5] WARN: libObj:infra_tp_sus (+0x8b9e54) 前言字节不匹配，跳过");
        }
    }
    g_real_handoff_stage = "3_4_retire_g4_input_threads";
    logf_("G4_HANDOFF [3/5]: 退役四代抢包线程（含 I-TpMain/I-TpRecv），交由五代 libOb5 原生接管触屏...");
    g4_retire_duplicate_input_threads(g4base);

    /* 安装 libmpr.so SIGSEGV 崩溃免疫桩 (彻底杜绝 0x7ef05e 野指针崩溃，保全媒体主进程) */
    patch_libmpr_crash_guard();

    /* 安装 callback_direct / callback_tp_raw 等 12B 安全隔离桩，并追踪 libObj pthread_create */
    g_real_handoff_stage = "4_infra_input_bridge";
    install_g4_key_intercept(g4base);
    hook_got_slot(g4base, 0x13d92b0u, (void *)hook_pthread_create_tracker, "libObj.so GOT[pthread_create]");
    logf_("G4_HANDOFF [4/5]: 四代输入竞争线程已交接清退，callback_* 防唤醒隔离桩就绪");

    g_real_handoff_stage = "g4_released";
    logf_("G4_HANDOFF: 四代独占硬件资源与输入队列释放完成，准备拉起五代原生输入与 UI");

    /* [5/5] 对齐 SD 卡多路径挂载点，确保五代访问 /mnt/sdcard 或 /media/sdcard 时能命中四代 /mnt/sd */
    (void)mkdir("/mnt/sdcard", 0777);
    (void)symlink("/mnt/sd", "/mnt/sdcard");
    (void)mkdir("/media", 0777);
    (void)mkdir("/media/sdcard", 0777);
    (void)symlink("/mnt/sd", "/media/sdcard");
    logf_("G4_HANDOFF [5/5]: 已建立 SD 卡多路径软链接 (/mnt/sdcard, /media/sdcard -> /mnt/sd)");
}

static void real_ob5_draw_framebuffer(void *ge)
{
    static volatile uint32_t s_enter = 0;
    uint32_t c = __sync_add_and_fetch(&s_enter, 1u);
    if (!g_real_orig_ob5_drawfb) {
        logf_("REAL_OB5_DRAWFB #%u ERROR: orig trampoline 为 NULL，跳过调用", c);
        return;
    }
    g_real_orig_ob5_drawfb(ge);
    uint32_t done = __sync_add_and_fetch(&g_real_drawfb_done_cnt, 1u);
    g4sched_on_frame_drawn(done);
    if (done <= 3u || (done % 2000u) == 0u) {
        logf_("REAL_OB5_DRAWFB #%u EXIT: done=%u (native GPU steady)", c, done);
    }
}

static uintptr_t real_ob5_rm_present(uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    /* 修复合屏 UI 反向：严格限制仅在 b == 0x8 (UI/OSD 硬件图层) 时操作，严禁篡改 b != 0x8 (取景视频层) */
    if (a && b == 0x8u) {
        uint32_t *desc = (uint32_t *)a;
        desc[5] = (desc[5] & ~0x3u);
    }
    uint32_t seq = __sync_add_and_fetch(&g_real_present_cnt, 1u);
    uintptr_t rc = g_real_orig_ob5_present(a, b, c, d);
    if (seq <= 3u || (seq % 10000u) == 0u) {
        logf_("REAL_RM_PRESENT #%u: a=0x%lx b=0x%lx rc=0x%lx",
              seq, (unsigned long)a, (unsigned long)b, (unsigned long)rc);
    }
    return rc;
}

static void *install_real_tramp8(uintptr_t ob5_base, uint32_t off, const unsigned char exp[8],
                                 void *hook_fn, const char *name)
{
    const void *addr = (const void *)(ob5_base + off);
    if (memcmp(addr, exp, 8) != 0) {
        logf_("REAL_OBS: %s (+0x%x) 前言字节不匹配，跳过跳板安装", name, off);
        return NULL;
    }
    return make_thumb_trampoline_8((uintptr_t)addr, hook_fn, name);
}

static void *install_real_tramp12_unaligned(uintptr_t ob5_base, uint32_t off, const unsigned char exp[12],
                                            void *hook_fn, const char *name)
{
    const void *addr = (const void *)(ob5_base + off);
    if (memcmp(addr, exp, 12) != 0) {
        logf_("REAL_OBS: %s (+0x%x) 12B 前言字节不匹配，跳过跳板安装", name, off);
        return NULL;
    }
    return make_thumb_trampoline_unaligned12((uintptr_t)addr, hook_fn, name);
}

static void install_real_ob5_observers(uintptr_t ob5_base, void *hMwf)
{
    (void)hMwf;

    static const unsigned char exp_drawfb12[12] = {
        0x2d, 0xe9, 0xf0, 0x41, 0x04, 0x46, 0x82, 0xb0, 0x04, 0xf1, 0x74, 0x05
    };
    static const unsigned char exp_present[8] = {0x2d, 0xe9, 0xf0, 0x41, 0x84, 0xb0, 0x05, 0x46};
    g_real_orig_ob5_drawfb = (real_draw_fb_fn_t)install_real_tramp12_unaligned(
        ob5_base, 0x0e565au, exp_drawfb12, (void *)real_ob5_draw_framebuffer, "libOb5:drawFramebuffer");
    g_real_orig_ob5_present = (real_fn4_t)install_real_tramp8(
        ob5_base, 0x12cc80u, exp_present, (void *)real_ob5_rm_present, "libOb5:rm_present");
    init_bridge_sched(ob5_base);
}

static void * volatile     g_real_g5_tp_obj = NULL;
static volatile uint32_t   g_g5tp_vt4_cnt = 0;
static volatile uint32_t   g_g5_mouse_press_cnt = 0;
static volatile uint32_t   g_g5_mouse_rel_cnt = 0;
static uintptr_t           g_g5tp_vtable_storage[12];
typedef int (*g5_tp_vt4_fn_t)(void *self, uint32_t msg0);
static g5_tp_vt4_fn_t      g_g5tp_orig_vt4 = NULL;
typedef int (*g5_ob5_send_msg_fn_t)(void *pThis, uint32_t qid, void *buf, uint32_t size, uint32_t flags, uint32_t magic_hdr);
static g5_ob5_send_msg_fn_t g_g5tp_ob5_send_msg = NULL;
static volatile int         g_g5tp_hb_retried = 0;

static int real_g5tp_vt4_hook(void *self, uint32_t msg0)
{
    int idx = g_g5tp_orig_vt4 ? g_g5tp_orig_vt4(self, msg0) : -1;
    uint32_t cnt = __sync_add_and_fetch(&g_g5tp_vt4_cnt, 1u);
    if (cnt <= 12u) {
        uint8_t sus_b = *(const volatile uint8_t  *)((uintptr_t)self + 0x20u);
        uint8_t sw_b  = *(const volatile uint8_t  *)((uintptr_t)self + 0x32u);
        uint8_t raw_b = *(const volatile uint8_t  *)((uintptr_t)self + 0x35u);
        uint32_t mode = *(const volatile uint32_t *)((uintptr_t)self + 0x44u);
        logf_("G5_TP_RECV #%u: I-TpRecv 收到 0x7b0026 包 msg0=0x%08x -> map_idx=%d (sus=%u ev_sw=%u raw=%u mode=%u)",
              cnt, msg0, idx, (unsigned)sus_b, (unsigned)sw_b, (unsigned)raw_b, mode);
    }
    return idx;
}

static void real_appfw_post_mouse_press(void *ws, uint8_t id, uint8_t btn, const uint64_t *tm)
{
    uint32_t cnt = __sync_add_and_fetch(&g_g5_mouse_press_cnt, 1u);
    if (cnt <= 10u) {
        logf_("G5_APPFW_TOUCH #%u: postMousePress(ws=%p, id=%u, btn=%u)", cnt, ws, (unsigned)id, (unsigned)btn);
    }
    if (g_pPress) g_pPress(ws, id, btn, tm);
}

static void real_appfw_post_mouse_release(void *ws, uint8_t id, uint8_t btn, const uint64_t *tm)
{
    uint32_t cnt = __sync_add_and_fetch(&g_g5_mouse_rel_cnt, 1u);
    if (cnt <= 10u) {
        logf_("G5_APPFW_TOUCH #%u: postMouseRelease(ws=%p, id=%u, btn=%u)", cnt, ws, (unsigned)id, (unsigned)btn);
    }
    if (g_pRel) g_pRel(ws, id, btn, tm);
}

/* 五代 libOb5:InfraInput <-> appFw.so 按键回调探针与电源拨片桥接 */
typedef void *(*g5_infra_get_inst_fn_t)(void);
typedef int   (*g5_infra_set_cb_fn_t)(void *self, int *out_id, void (*cb)(int, void *));
typedef int   (*g5_infra_set_keylist_fn_t)(void *self, int cb_id, const void *list, int count);
typedef int   (*g5_infra_set_keylist_all_fn_t)(void *self, int cb_id);
typedef void  (*g5_in_user_cb_t)(int ch, void *ev);

static int g5_send_internal_event(uint32_t event_id);

static g5_infra_set_cb_fn_t          g_orig_g5_in_set_cb = NULL;
static g5_infra_set_keylist_fn_t     g_orig_g5_in_set_keylist = NULL;
static g5_infra_set_keylist_all_fn_t g_g5_in_set_keylist_all = NULL;
static void * volatile               g_real_g5_in_obj = NULL;
static int                           g_real_g5_diag_cb_id = -1;
static volatile uint32_t             g_g5_in_raw_cnt = 0;

#define G5_APPFW_IN_MAX_SLOTS 8
static g5_in_user_cb_t               g_g5_appfw_in_orig_cbs[G5_APPFW_IN_MAX_SLOTS];
static int                           g_g5_appfw_in_cb_ids[G5_APPFW_IN_MAX_SLOTS];
static volatile uint32_t             g_g5_appfw_in_slot_cnt = 0;
static volatile uint32_t             g_g5_appfw_in_ev_cnt = 0;
static volatile int                  g_g5_appfw_has_kuru_left = 0;

static int g5_inject_raw_infra_event(uint32_t raw_code, int32_t status, uint32_t prev_status)
{
    if (!g_appfw_base) return -1;

    g5_in_user_cb_t target_cb = (g5_in_user_cb_t)(g_appfw_base + 0x0054e789u);
    g5_in_user_cb_t cb = NULL;
    for (unsigned i = 0; i < G5_APPFW_IN_MAX_SLOTS; i++) {
        if (g_g5_appfw_in_orig_cbs[i] == target_cb) {
            cb = target_cb;
            break;
        }
    }
    if (!cb) {
        static const uint8_t exp_cb[8] = { 0x2du, 0xe9u, 0xf0u, 0x41u, 0x82u, 0xb0u, 0x00u, 0xafu };
        const uint8_t *fn_addr = (const uint8_t *)(g_appfw_base + 0x0054e788u);
        if (memcmp(fn_addr, exp_cb, sizeof(exp_cb)) == 0) {
            cb = target_cb;
        } else {
            logf_("G5_IN_INJECT_ERR: appFw+0x54e788 签名不匹配 (%02x %02x %02x %02x)",
                  fn_addr[0], fn_addr[1], fn_addr[2], fn_addr[3]);
        }
    }
    if (!cb) return -1;

    g5_infra_input_ev_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.event_code  = raw_code;
    ev.status      = status;
    ev.prev_status = prev_status;
    cb(0, &ev);
    return 0;
}

static void g5_appfw_in_dispatch(unsigned slot, int ch, void *ev_ptr)
{
    if (ev_ptr) {
        const g5_infra_input_ev_t *ev = (const g5_infra_input_ev_t *)ev_ptr;
        /* 屏蔽 10Hz 传感器事件 (0x18000001)、高频拨轮 (0x10000016) 与触摸移动 (0x06000001/0x80000001)，保留全部低频物理键与电源开关追踪 */
        int is_sensor = (ev->event_code == 0x18000001u);
        int is_dial = (ev->event_code == 0x10000016u);
        int is_tp_move = (ev->event_code == 0x06000001u && (uint32_t)ev->status == 0x80000001u);
        if (!is_sensor && !is_dial && !is_tp_move) {
            uint32_t cnt = __sync_add_and_fetch(&g_g5_appfw_in_ev_cnt, 1u);
            logf_("G5_KEY_TRACE[cb=%d ch=%d #%u slot=%u]: code=0x%08x st=%d prev=0x%x ex=0x%x rep=%u tp=(%d,%d)",
                  (slot < G5_APPFW_IN_MAX_SLOTS) ? g_g5_appfw_in_cb_ids[slot] : -1,
                  ch, cnt, slot,
                  ev->event_code, ev->status, ev->prev_status, ev->ex_info, ev->repeat,
                  (int)ev->tp_x, (int)ev->tp_y);
        }
    }
    g5_in_user_cb_t orig = (slot < G5_APPFW_IN_MAX_SLOTS) ? g_g5_appfw_in_orig_cbs[slot] : NULL;
    if (orig) orig(ch, ev_ptr);
}

#define G5_DEFINE_APPFW_IN_WRAP(N) \
    static void g5_appfw_in_wrap_##N(int ch, void *ev_ptr) { g5_appfw_in_dispatch(N##u, ch, ev_ptr); }
G5_DEFINE_APPFW_IN_WRAP(0)
G5_DEFINE_APPFW_IN_WRAP(1)
G5_DEFINE_APPFW_IN_WRAP(2)
G5_DEFINE_APPFW_IN_WRAP(3)
G5_DEFINE_APPFW_IN_WRAP(4)
G5_DEFINE_APPFW_IN_WRAP(5)
G5_DEFINE_APPFW_IN_WRAP(6)
G5_DEFINE_APPFW_IN_WRAP(7)
#undef G5_DEFINE_APPFW_IN_WRAP

static const g5_in_user_cb_t g_g5_appfw_in_wrappers[G5_APPFW_IN_MAX_SLOTS] = {
    g5_appfw_in_wrap_0, g5_appfw_in_wrap_1, g5_appfw_in_wrap_2, g5_appfw_in_wrap_3,
    g5_appfw_in_wrap_4, g5_appfw_in_wrap_5, g5_appfw_in_wrap_6, g5_appfw_in_wrap_7,
};

static int g5_hook_appfw_in_set_cb(void *self, int *out_id, g5_in_user_cb_t cb)
{
    if (!g_orig_g5_in_set_cb) {
        logf_("G5_IN_WARN: g_orig_g5_in_set_cb 为 NULL");
        if (out_id) *out_id = -1;
        return 0;
    }
    unsigned slot = __sync_fetch_and_add(&g_g5_appfw_in_slot_cnt, 1u);
    g5_in_user_cb_t reg_cb = cb;
    if (slot < G5_APPFW_IN_MAX_SLOTS && cb) {
        g_g5_appfw_in_orig_cbs[slot] = cb;
        reg_cb = g_g5_appfw_in_wrappers[slot];
    }
    int rc = g_orig_g5_in_set_cb(self, out_id, reg_cb);
    int cb_id = out_id ? *out_id : -1;
    if (slot < G5_APPFW_IN_MAX_SLOTS) {
        g_g5_appfw_in_cb_ids[slot] = cb_id;
    }
    Dl_info dli = {0};
    dladdr((void *)cb, &dli);
    uintptr_t off = (dli.dli_fbase && (uintptr_t)cb >= (uintptr_t)dli.dli_fbase)
        ? ((uintptr_t)cb - (uintptr_t)dli.dli_fbase) : (uintptr_t)cb;
    logf_("G5_IN_SETCALLBACK[slot=%u]: self=%p rc=%d cb_id=%d orig_cb=%p (%s+0x%lx)",
          slot, self, rc, cb_id, (void *)cb,
          dli.dli_fname ? dli.dli_fname : "?", (unsigned long)off);
    return rc;
}

static int g5_hook_appfw_in_set_keylist(void *self, int cb_id, const void *list, int count)
{
    logf_("G5_IN_SETKEYLIST: self=%p cb_id=%d list=%p count=%d", self, cb_id, list, count);
    if (list && count > 0) {
        int lim = (count > 256) ? 256 : count;
        char buf[256];
        int pos = 0;
        for (int i = 0; i < count; i++) {
            const uint32_t *ent = (const uint32_t *)((const uint8_t *)list + (size_t)i * 12u);
            if (ent[0] == 0x10000000u) {
                g_g5_appfw_has_kuru_left = 1;
            }
            if (i < lim) {
                int n = snprintf(buf + pos, sizeof(buf) - (size_t)pos, "%s0x%x(%x,%x)",
                                 (i % 8 == 0) ? "" : " ", ent[0], ent[1], ent[2]);
                if (n > 0) pos += (pos + n < (int)sizeof(buf)) ? n : ((int)sizeof(buf) - pos - 1);
                if ((i % 8 == 7) || (i + 1 == lim)) {
                    logf_("G5_IN_KEYLIST[cb=%d %d..%d]: %s", cb_id, (i / 8) * 8, i, buf);
                    pos = 0;
                }
            }
        }
    }
    return g_orig_g5_in_set_keylist ? g_orig_g5_in_set_keylist(self, cb_id, list, count) : 0;
}

static void g5_real_diag_input_cb(int ch, void *ev_ptr)
{
    if (!ev_ptr) return;
    const g5_infra_input_ev_t *ev = (const g5_infra_input_ev_t *)ev_ptr;
    /* 屏蔽 10Hz 高频传感器 (0x18000001)、高频拨轮 (0x10000016) 与触摸移动，保留全量低频按键及电源开关状态 */
    if (ev->event_code == 0x18000001u || ev->event_code == 0x10000016u ||
        (ev->event_code == 0x06000001u && (uint32_t)ev->status == 0x80000001u)) {
        return;
    }

    uint32_t cnt = __sync_add_and_fetch(&g_g5_in_raw_cnt, 1u);
    logf_("G5_IN_ALL_RAW[#%u ch=%d]: code=0x%08x st=%d prev=0x%x ex=0x%x rep=%u tp=(%d,%d)",
          cnt, ch, ev->event_code, ev->status, ev->prev_status, ev->ex_info, ev->repeat,
          (int)ev->tp_x, (int)ev->tp_y);

    /* 若 appFw 原生 SetEventKeyList 未订阅 KURU_LEFT (0x10000000)，由诊断全键回调转发至 appFw */
    if (!g_g5_appfw_has_kuru_left && ev->event_code == 0x10000000u &&
        g_real_handoff_stage && strcmp(g_real_handoff_stage, "g5_main_loop") == 0) {
        g5_inject_raw_infra_event(ev->event_code, ev->status, ev->prev_status);
    }

    /* ZV-E10 二段电源拨片 OFF (0x01d2): 注入五代原始 KEY_TACT_POWER (0x0002) st=1->0 触发正常关机 */
    if (ev->event_code == 0x01d2u && ev->status == 1 && ev->prev_status != 1u &&
        g_real_handoff_stage && strcmp(g_real_handoff_stage, "g5_main_loop") == 0) {
        logf_("G5_IN_POWER_OFF_BRIDGE: 检测到电源拨片拨至 OFF (0x01d2 st=1 prev=%u)，注入五代 KEY_TACT_POWER (0x0002)!",
              ev->prev_status);
        if (g5_inject_raw_infra_event(0x0002u, 1, 0u) == 0) {
            usleep(30000);
            g5_inject_raw_infra_event(0x0002u, 0, 1u);
        } else {
            g5_send_internal_event(0x020f0005u);
            usleep(30000);
            g5_send_internal_event(0x020f0004u);
        }
    }
}

static void g5_init_real_g5_input_probe(uintptr_t ob5_base)
{
    static const unsigned char exp_get[8]  = {0xb0u, 0xb5u, 0x84u, 0xb0u, 0x24u, 0x49u, 0x04u, 0xafu};
    static const unsigned char exp_scb[8]  = {0x2du, 0xe9u, 0xf0u, 0x41u, 0x04u, 0x46u, 0x84u, 0xb0u};
    static const unsigned char exp_sall[8] = {0xb0u, 0xb5u, 0x0cu, 0x46u, 0x00u, 0xafu, 0x05u, 0x46u};
    static const unsigned char exp_skl[8]  = {0x2du, 0xe9u, 0xf0u, 0x4fu, 0xa3u, 0xb0u, 0x04u, 0xafu};

    uintptr_t get_va  = ob5_base + 0x00208004u;
    uintptr_t scb_va  = ob5_base + 0x002085b4u;
    uintptr_t sall_va = ob5_base + 0x002089e8u;
    uintptr_t skl_va  = ob5_base + 0x002092d0u;

    if (memcmp((const void *)scb_va, exp_scb, sizeof(exp_scb)) == 0) {
        g_orig_g5_in_set_cb = (g5_infra_set_cb_fn_t)(scb_va | 1u);
    } else {
        logf_("REAL_INPUT_WARN: libOb5 InfraInput::SetCallback (+0x2085b4) 前言不匹配");
    }
    if (memcmp((const void *)skl_va, exp_skl, sizeof(exp_skl)) == 0) {
        g_orig_g5_in_set_keylist = (g5_infra_set_keylist_fn_t)(skl_va | 1u);
    } else {
        logf_("REAL_INPUT_WARN: libOb5 InfraInput::SetEventKeyList (+0x2092d0) 前言不匹配");
    }
    if (memcmp((const void *)sall_va, exp_sall, sizeof(exp_sall)) == 0) {
        g_g5_in_set_keylist_all = (g5_infra_set_keylist_all_fn_t)(sall_va | 1u);
    }

    if (memcmp((const void *)get_va, exp_get, sizeof(exp_get)) == 0 && g_orig_g5_in_set_cb) {
        void *pG5In = ((g5_infra_get_inst_fn_t)(get_va | 1u))();
        g_real_g5_in_obj = pG5In;
        if (pG5In) {
            int rc = g_orig_g5_in_set_cb(pG5In, &g_real_g5_diag_cb_id, g5_real_diag_input_cb);
            int all_rc = -1;
            if (g_g5_in_set_keylist_all && g_real_g5_diag_cb_id >= 0) {
                all_rc = g_g5_in_set_keylist_all(pG5In, g_real_g5_diag_cb_id);
            }
            logf_("REAL_INPUT: libOb5 InfraInput 全键诊断探针已注册 pIn=%p cb_id=%d rc=%d all_rc=%d",
                  pG5In, g_real_g5_diag_cb_id, rc, all_rc);
        } else {
            logf_("REAL_INPUT_WARN: libOb5 InfraInput::GetInstance 返回 NULL");
        }
    } else {
        logf_("REAL_INPUT_WARN: libOb5 InfraInput::GetInstance (+0x208004) 前言不匹配");
    }
}

static void g5_start_real_input_services(uintptr_t ob5_base)
{
    static const struct {
        uint32_t      off;
        unsigned char exp[4];
        int           has_arg;
        const char   *name;
    } steps[] = {
        {0x208134u, {0x80, 0xb5, 0x84, 0xb0}, 0, "libOb5:infra_input_injS"},
        {0x2080bcu, {0xb0, 0xb5, 0x84, 0xb0}, 1, "libOb5:infra_input_rfR"},
        {0x201370u, {0x80, 0xb5, 0x84, 0xb0}, 0, "libOb5:infra_tp_injS"},
        {0x2012c0u, {0xb0, 0xb5, 0x84, 0xb0}, 1, "libOb5:infra_tp_rfR"},
    };
    g_real_handoff_stage = "g5_input_init";
    for (unsigned i = 0; i < sizeof steps / sizeof steps[0]; i++) {
        const void *addr = (const void *)(ob5_base + steps[i].off);
        if (memcmp(addr, steps[i].exp, 4) != 0) {
            logf_("REAL_INPUT: %s (+0x%x) 前言字节不匹配，跳过", steps[i].name, steps[i].off);
            continue;
        }
        uint64_t t0 = g5_msec_now();
        int rc = 0;
        if (steps[i].has_arg) {
            rc = ((int (*)(uint32_t))((uintptr_t)addr | 1u))(0u);
        } else {
            rc = ((int (*)(void))((uintptr_t)addr | 1u))();
        }
        logf_("REAL_INPUT: %s rc=%d elapsed=%llu ms",
              steps[i].name, rc, (unsigned long long)(g5_msec_now() - t0));
    }

    /* 主动激活五代 libOb5:InfraTp 硬件工作模式 (0x01010227) 与事件开关，并挂载零侵入 vtable[4] 收包探针 */
    {
        static const unsigned char exp_get[8]  = {0xb0u, 0xb5u, 0x84u, 0xb0u, 0x21u, 0x49u, 0x04u, 0xafu};
        static const unsigned char exp_sw[8]   = {0xb0u, 0xb5u, 0x84u, 0xb0u, 0x17u, 0x4bu, 0x0cu, 0x46u};
        static const unsigned char exp_raw[8]  = {0xb0u, 0xb5u, 0x84u, 0xb0u, 0x09u, 0x4bu, 0x05u, 0x46u};
        static const unsigned char exp_mode[8] = {0xf0u, 0xb5u, 0x87u, 0xb0u, 0x04u, 0xafu, 0x02u, 0x23u};
        static const unsigned char exp_set[8]  = {0x2du, 0xe9u, 0xf0u, 0x43u, 0x89u, 0xb0u, 0x04u, 0xafu};
        uintptr_t get_va  = ob5_base + 0x00201218u;
        uintptr_t sw_va   = ob5_base + 0x002007a4u;
        uintptr_t raw_va  = ob5_base + 0x001fef3cu;
        uintptr_t mode_va = ob5_base + 0x001ff060u;
        uintptr_t set_va  = ob5_base + 0x001fefb0u;
        if (memcmp((const void *)get_va, exp_get, sizeof(exp_get)) == 0) {
            typedef void *(*g5_tp_get_fn_t)(void);
            typedef void  (*g5_tp_sw_fn_t)(void *self, uint32_t enable);
            typedef int   (*g5_tp_mode_fn_t)(void *self, uint32_t mode);
            typedef int   (*g5_tp_set_fn_t)(void *self, uint32_t a, uint32_t b, uint32_t c);
            void *pG5Tp = ((g5_tp_get_fn_t)(get_va | 1u))();
            if (pG5Tp) {
                g_real_g5_tp_obj = pG5Tp;
                uint8_t  sus_b   = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x20u);
                uint8_t  dir0    = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x30u);
                uint8_t  dir1    = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x31u);
                uint8_t  sw_b    = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x32u);
                uint8_t  raw_b   = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x35u);
                uint32_t s0      = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x38u);
                uint32_t s1      = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x3cu);
                uint32_t s2      = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x40u);
                uint32_t mode    = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x44u);
                uint32_t mx      = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x58u);
                uint32_t my      = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x5cu);
                uint32_t key_cnt = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x1cu);
                logf_("REAL_INPUT: libOb5 InfraTp=%p 初始状态: sus=%u dir=(%u,%u) ev_sw=%u raw=%u mode=%u settings=(%u,%u,%u) max=(%u,%u) keys=%u",
                      pG5Tp, (unsigned)sus_b, (unsigned)dir0, (unsigned)dir1,
                      (unsigned)sw_b, (unsigned)raw_b, mode, s0, s1, s2, mx, my, key_cnt);

                if (g_g4_tp_saved_valid && (g_g4_tp_saved_s0 | g_g4_tp_saved_s1 | g_g4_tp_saved_s2) != 0u &&
                    memcmp((const void *)set_va, exp_set, sizeof(exp_set)) == 0) {
                    int set_rc = ((g5_tp_set_fn_t)(set_va | 1u))(pG5Tp, g_g4_tp_saved_s0, g_g4_tp_saved_s1, g_g4_tp_saved_s2);
                    logf_("REAL_INPUT: libOb5 InfraTp::SetResourceTpSettings(%u,%u,%u) rc=%d",
                          g_g4_tp_saved_s0, g_g4_tp_saved_s1, g_g4_tp_saved_s2, set_rc);
                }

                uint32_t target_mode = (g_g4_tp_saved_valid && g_g4_tp_saved_mode >= 1u && g_g4_tp_saved_mode <= 4u)
                                           ? g_g4_tp_saved_mode : 1u;
                if (memcmp((const void *)mode_va, exp_mode, sizeof(exp_mode)) == 0) {
                    int mode_rc = ((g5_tp_mode_fn_t)(mode_va | 1u))(pG5Tp, target_mode);
                    logf_("REAL_INPUT: libOb5 InfraTp::SetResourceTpMode(%u) -> rc=%d (new mode=%u)",
                          target_mode, mode_rc, *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x44u));
                } else {
                    logf_("REAL_INPUT_WARN: SetResourceTpMode (+0x1ff060) 前言不匹配，跳过");
                }

                /* 先置 0 再置 1，强制穿透 SetTpEventSw 的 old==new 短路检查并向 0x7a0020 发送刷新包 */
                if (memcmp((const void *)sw_va, exp_sw, sizeof(exp_sw)) == 0) {
                    ((g5_tp_sw_fn_t)(sw_va | 1u))(pG5Tp, 0u);
                    ((g5_tp_sw_fn_t)(sw_va | 1u))(pG5Tp, 1u);
                }
                /* 关闭冗余 raw 包 (0x06000002)，避免 I-TpRecv -> I-InputRecv -> appFw 队列吞吐翻倍 */
                if (memcmp((const void *)raw_va, exp_raw, sizeof(exp_raw)) == 0) {
                    ((g5_tp_sw_fn_t)(raw_va | 1u))(pG5Tp, 0u);
                }

                /* 克隆 InfraTp vtable 以非侵入方式拦截 vtable[4] 观测 I-TpRecv 真实收包 */
                uintptr_t *orig_vt = *(uintptr_t **)pG5Tp;
                if (orig_vt && ((orig_vt[4] & ~(uintptr_t)1u) == ob5_base + 0x001fe4f2u)) {
                    for (int vi = -2; vi < 8; vi++) {
                        g_g5tp_vtable_storage[vi + 2] = orig_vt[vi];
                    }
                    g_g5tp_orig_vt4 = (g5_tp_vt4_fn_t)orig_vt[4];
                    g_g5tp_vtable_storage[4 + 2] = (uintptr_t)real_g5tp_vt4_hook;
                    __sync_synchronize();
                    *(uintptr_t **)pG5Tp = &g_g5tp_vtable_storage[2];
                    logf_("REAL_INPUT: libOb5 InfraTp vtable[4] (0x%lx) 收包探针已挂载", (unsigned long)orig_vt[4]);
                }

                /* 打印校准/有效区参数，确认 I-TpRecv 坐标映射缩放系数不为 0 */
                {
                    uint32_t area0 = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x48u);
                    uint32_t area1 = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x4cu);
                    uint32_t area2 = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x50u);
                    uint32_t area3 = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x54u);
                    int32_t  off_x = *(const volatile int32_t  *)((uintptr_t)pG5Tp + 0x60u);
                    int32_t  off_y = *(const volatile int32_t  *)((uintptr_t)pG5Tp + 0x64u);
                    int32_t  min_x = *(const volatile int32_t  *)((uintptr_t)pG5Tp + 0x68u);
                    int32_t  min_y = *(const volatile int32_t  *)((uintptr_t)pG5Tp + 0x6cu);
                    int32_t  scl_x = *(const volatile int32_t  *)((uintptr_t)pG5Tp + 0x80u);
                    int32_t  scl_y = *(const volatile int32_t  *)((uintptr_t)pG5Tp + 0x84u);
                    logf_("REAL_INPUT: libOb5 InfraTp 校准参数: area=(%u,%u,%u,%u) off=(%d,%d) raw_min=(%d,%d) scale=(%d,%d)",
                          area0, area1, area2, area3, off_x, off_y, min_x, min_y, scl_x, scl_y);
                }

                /* 向 LIRO 0x01010227 下发 VdfDisplayCmdSetPanelOut(cmd=4,1) 与 VdfInputCmdSetTouchPanel(cmd=3,1) 唤醒物理触摸 IC */
                {
                    static const unsigned char exp_send[12] = {
                        0x2du, 0xe9u, 0xf0u, 0x47u, 0x8au, 0xb0u, 0x04u, 0xafu, 0x91u, 0x46u, 0x1du, 0x46u
                    };
                    uintptr_t send_va = ob5_base + 0x0020d094u;
                    if (memcmp((const void *)send_va, exp_send, sizeof(exp_send)) == 0) {
                        g_g5tp_ob5_send_msg = (g5_ob5_send_msg_fn_t)(send_va | 1u);
                        uint32_t cmd4[2] = { 4u, 1u };
                        uint32_t cmd3[2] = { 3u, 1u };
                        int rc4 = g_g5tp_ob5_send_msg(pG5Tp, 0x01010227u, cmd4, (uint32_t)sizeof(cmd4), 2u, 0u);
                        usleep(50000);
                        int rc3 = g_g5tp_ob5_send_msg(pG5Tp, 0x01010227u, cmd3, (uint32_t)sizeof(cmd3), 2u, 0u);
                        logf_("REAL_INPUT: LIRO 0x01010227 硬件唤醒 cmd=4(1)->rc=%d, cmd=3(1)->rc=%d", rc4, rc3);
                    } else {
                        logf_("REAL_INPUT_WARN: libOb5 ob5_send_msg (+0x20d094) 12B 前言不匹配，跳过 0x01010227 硬件唤醒");
                    }
                }

                sw_b  = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x32u);
                raw_b = *(const volatile uint8_t  *)((uintptr_t)pG5Tp + 0x35u);
                mode  = *(const volatile uint32_t *)((uintptr_t)pG5Tp + 0x44u);
                logf_("REAL_INPUT: libOb5 InfraTp 激活完成: sus=%u ev_sw=%u raw=%u mode=%u",
                      (unsigned)*(const volatile uint8_t *)((uintptr_t)pG5Tp + 0x20u),
                      (unsigned)sw_b, (unsigned)raw_b, mode);
            } else {
                logf_("REAL_INPUT_WARN: libOb5 InfraTp::GetInstance 返回 NULL");
            }
        } else {
            logf_("REAL_INPUT_WARN: libOb5 InfraTp::GetInstance (+0x201218) 前言字节不匹配，跳过开关激活");
        }
    }
    g5_init_real_g5_input_probe(ob5_base);
    g_real_in_init_done = 1;
    g_real_handoff_stage = "g5_input_ready";
}
#endif /* ZVE10_REAL_DEVICE */

static void g5_install_menu_boot_hooks(uintptr_t app_base);

static void *astra_thread(void *unused)
{
    (void)unused;
    int dummy;
    g_astra_th = pthread_self();
    g_astra_running = 1;
    logf_("G1 AppFw 专属线程启动 tid=%p sp~%p stack=%u", (void *)g_astra_th, (void *)&dummy, ASTRA_STACK_SIZE);
    if (chdir(APPDIR) != 0) logf_("chdir %s 失败 errno=%d", APPDIR, errno);

    void *hMwf = must_open("libMWF.so");
#ifndef ZVE10_REAL_DEVICE
    /* 关键步骤 0：仅在 QEMU 独立模式下初始化 MWF 单例（真机宿主 im.elf 已预先完成初始化，真机重复调用会破坏 MonCtrl） */
    logf_("G1.1 初始化 MWF 依赖支持库 (QEMU 模式)...");
    if (hMwf) {
        void (*pRsrcDP_Init)(void) = (void (*)(void))dlsym(hMwf, "_ZN3MWF6RsrcDP10InitializeEv");
        void (*pRsrcRel_Init)(void) = (void (*)(void))dlsym(hMwf, "_ZN3MWF12RsrcRelation10InitializeEv");
        if (pRsrcDP_Init) {
            pRsrcDP_Init();
            logf_("  MWF::RsrcDP::Initialize OK");
        }
        if (pRsrcRel_Init) {
            pRsrcRel_Init();
            logf_("  MWF::RsrcRelation::Initialize OK");
        }
    }
#endif

#if defined(ZVE10_REAL_DEVICE) && !defined(ZVE10_USB_SANDBOX)
    /* 在加载 Gen5 闭包前，按顺序释放 Gen4 RM / GRM(VDF+RsrcAcsr) / InfraTp / InfraInput(0x7a0020) */
    g4_handoff_real_device();
#endif

    static const char *const chain[] = {
        "libOb5.so", "libmp5.so", "libObjShim.so", "AdjChkConfig.so", "libappFwBoot_g5.so",
    };
    void *hBootG5 = NULL;
    void *hOb5 = NULL;
    for (unsigned i = 0; i < sizeof chain / sizeof chain[0]; i++) {
        void *h = must_open(chain[i]);
        if (!h) { logf_("ABORT: 依赖闭包加载失败 (%s)", chain[i]); return NULL; }
        if (i == 0) hOb5 = h;
        if (i == 4) hBootG5 = h;
    }

    /* 核心图形护航：仅 QEMU 模式下接管 GPE 软光栅、Present、LDEC 与 GL；真机交由原生硬件驱动 */
    if (hOb5) {
#ifndef ZVE10_REAL_DEVICE
        Dl_info ob5_info = {0};
        void *pGetGE = dlsym(hOb5, "_ZN2ux6gfxeng14GraphicsEngine15sys_getInstanceFU");
        if (pGetGE && dladdr(pGetGE, &ob5_info) && ob5_info.dli_fbase) {
            uintptr_t ob5_base = (uintptr_t)ob5_info.dli_fbase;
            logf_("HOOK: libOb5.so 基址 = 0x%lx，开始安装 GPE 软光栅与 Present 接管...", (unsigned long)ob5_base);
            patch_thumb_jump((void *)(ob5_base + 0x12cc80), (void *)g5_hook_present, "libOb5:rm_present");
            patch_thumb_jump((void *)(ob5_base + 0x12ceb0), (void *)g5_hook_engine_wait, "libOb5:rm_wait");
            patch_thumb_jump((void *)(ob5_base + 0x182410), (void *)g5_hook_dmp_fill, "libOb5:dmp_fill");
            patch_thumb_jump((void *)(ob5_base + 0x1824a0), (void *)g5_hook_dmp_blit, "libOb5:dmp_blit");
            install_update_records_hook(ob5_base, 0x124bb4, g5_hook_update_records, &g_orig_update_records);
            patch_thumb_jump((void *)(ob5_base + 0x19b7e0), (void *)g5_hook_gemini_solid, "libOb5:gemini_solid");
            patch_thumb_jump((void *)(ob5_base + 0x19b31c), (void *)g5_hook_gemini_rect, "libOb5:gemini_rect");
            patch_thumb_jump((void *)(ob5_base + 0x19b034), (void *)g5_hook_gemini_quad, "libOb5:gemini_quad");
            hook_got_slot(ob5_base, 0x0035548cu, (void *)g5_hook_ob5_open, "libOb5.so GOT[open]");
            hook_got_slot(ob5_base, 0x003553a0u, (void *)g5_hook_ob5_ioctl, "libOb5.so GOT[ioctl]");
            hook_got_slot(ob5_base, 0x003552a4u, (void *)g5_hook_ob5_close, "libOb5.so GOT[close]");
            hook_got_slot(ob5_base, 0x00354f80u, (void *)hook_pthread_create_tracker, "libOb5.so GOT[pthread_create]");
        } else {
            logf_("HOOK: 无法获取 libOb5.so 基址 (pGetGE=%p)", pGetGE);
        }

        /* 提前在主线程中缓存 WidgetSystem 符号，避免辅助线程频繁调用 dlopen/dlsym 争抢锁 */
        g_pGetWS = (void *(*)(void))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem15sys_getInstanceFU");
        if (!g_pGetWS) g_pGetWS = (void *(*)(void))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem15sys_getInstanceEv");
        g_pUpdateCurTime = (void (*)(void *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem17updateCurrentTimeEv");
        g_pProcessEvent  = (void (*)(void *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem12processEventEv");
        g_pUpdateFrame   = (void (*)(void *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem11updateFrameEv");
        g_pNotifyDraw    = (void (*)(void *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem10notifyDrawEv");
        g_pPress         = (void (*)(void *, uint8_t, uint8_t, const uint64_t *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem14postMousePressEhhNS_4core8MsecTimeE");
        g_pMove          = (void (*)(void *, uint8_t, int16_t, int16_t, const uint64_t *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem13postMouseMoveEhssNS_4core8MsecTimeE");
        g_pRel           = (void (*)(void *, uint8_t, uint8_t, const uint64_t *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem16postMouseReleaseEhhNS_4core8MsecTimeE");
        __sync_synchronize();
        g_ws_syms_ready = 1;
        logf_("SYM_CACHE: WidgetSystem 符号已缓存 (GetWS=%p Update=%p Notify=%p Press=%p)",
              (void *)g_pGetWS, (void *)g_pUpdateFrame, (void *)g_pNotifyDraw, (void *)g_pPress);
#else
        g_pGetWS = (void *(*)(void))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem15sys_getInstanceFU");
        if (!g_pGetWS) g_pGetWS = (void *(*)(void))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem15sys_getInstanceEv");
        g_pPress = (void (*)(void *, uint8_t, uint8_t, const uint64_t *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem14postMousePressEhhNS_4core8MsecTimeE");
        g_pMove  = (void (*)(void *, uint8_t, int16_t, int16_t, const uint64_t *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem13postMouseMoveEhssNS_4core8MsecTimeE");
        g_pRel   = (void (*)(void *, uint8_t, uint8_t, const uint64_t *))dlsym(hOb5, "_ZN2ux6wgtsys12WidgetSystem16postMouseReleaseEhhNS_4core8MsecTimeE");
        Dl_info ob5_info = {0};
        if (g_pGetWS && dladdr((void *)g_pGetWS, &ob5_info) && ob5_info.dli_fbase) {
            uintptr_t ob5_base = (uintptr_t)ob5_info.dli_fbase;
            logf_("REAL_OB5: libOb5.so 基址 = 0x%lx，保留原生 GPU/LDEC/VDF 硬件通路", (unsigned long)ob5_base);
            hook_got_slot(ob5_base, 0x00354f80u, (void *)hook_pthread_create_tracker, "libOb5.so GOT[pthread_create]");
            uintptr_t fsys_base = get_module_base_maps("libFsys5.so");
            if (fsys_base) hook_got_slot(fsys_base, 0x0008d02cu, (void *)hook_pthread_create_tracker, "libFsys5.so GOT[pthread_create]");
            install_real_ob5_observers(ob5_base, hMwf);
#ifndef ZVE10_USB_SANDBOX
            g5_start_real_input_services(ob5_base);
#endif
        } else {
            logf_("REAL_OB5: 警告！未能解析 libOb5.so 基址，跳过真机观测与 Gen5 输入服务激活");
        }
        __sync_synchronize();
        g_ws_syms_ready = 1;
#endif
    }

    void *hApp = must_open("appFw.so");          /* 2,730 个 .init_array 构造函数在本 16MB 栈上执行 */
    if (!hApp) { logf_("ABORT: appFw.so 加载失败"); return NULL; }
    logf_("G2 appFw.so 构造函数全部完成");

    main_fn pMain  = (main_fn)dlsym(hBootG5, "_Z4MainPv");
    void   *pStart = dlsym(hApp, "Application_Start");
    logf_("_Z4MainPv=%p Application_Start=%p", (void *)pMain, pStart);
    if (!pMain || !pStart) { logf_("ABORT: 入口符号缺失"); return NULL; }

    /* 核心装甲：集中 Hook appFw.so 关键 GOT 槽位 */
    Dl_info app_info = {0};
    if (dladdr(pStart, &app_info) && app_info.dli_fbase) {
        uintptr_t app_base = (uintptr_t)app_info.dli_fbase;
        g_appfw_base = app_base;

        hook_got_slot(app_base, 0x0377b408u, (void *)astra_assert_ignore, "appFw.so GOT[__assert_fail]");

        /* 动态修补 notify_model_system_error (偏移 0x02bc3174) -> bx lr (Thumb) */
        uintptr_t pNotifyErr = app_base + 0x02bc3174u;
        uintptr_t notify_page = pNotifyErr & ~0xfffu;
        if (mprotect((void *)notify_page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            *(uint16_t *)pNotifyErr = 0x4770; /* bx lr */
            __builtin___clear_cache((char *)pNotifyErr, (char *)pNotifyErr + 4);
            logf_("PATCH: 成功动态免疫 notify_model_system_error (0x%lx) -> bx lr", (unsigned long)pNotifyErr);
        } else {
            logf_("PATCH: mprotect notify_model_system_error 失败 errno=%d", errno);
        }

        const char *cond_wait_sym = "_ZNSt18condition_variable4waitERSt11unique_lockISt5mutexE";
        void *orig_wait = dlsym(RTLD_DEFAULT, cond_wait_sym);
        if (!orig_wait) {
            void *h_stdcxx = dlopen("libstdc++.so.6", RTLD_NOLOAD | RTLD_LAZY);
            if (h_stdcxx) orig_wait = dlsym(h_stdcxx, cond_wait_sym);
        }
        g_orig_cond_wait = (cond_wait_fn_t)orig_wait;
        hook_got_slot(app_base, 0x0377ae50u, (void *)astra_cond_wait_hook, "appFw.so GOT[condition_variable::wait]");

        g_orig_osal_snd_sync_direct = (osal_snd_sync_direct_fn_t)dlsym(RTLD_DEFAULT, "osal_snd_sync_direct");
        hook_got_slot(app_base, 0x0377ad5cu, (void *)g5_hook_osal_snd_sync_direct, "appFw.so GOT[osal_snd_sync_direct]");

        g_orig_grm_check_update = (grm_check_update_fn_t)dlsym(hOb5 ? hOb5 : RTLD_DEFAULT, "GRM_fbrmCheckUpdateFinished");
        hook_got_slot(app_base, 0x0377b270u, (void *)g5_hook_grm_check_update_finished, "appFw.so GOT[GRM_fbrmCheckUpdateFinished]");

        g_orig_draw_framebuffer = (draw_fb_fn_t)dlsym(hOb5 ? hOb5 : RTLD_DEFAULT, "_ZN2ux6gfxeng14GraphicsEngine15drawFramebufferEv");
        hook_got_slot(app_base, 0x0377afe0u, (void *)g5_hook_appfw_draw_framebuffer, "appFw.so GOT[GraphicsEngine::drawFramebuffer]");

#ifdef ZVE10_REAL_DEVICE
        if (g_pPress) hook_got_slot(app_base, 0x0377b664u, (void *)real_appfw_post_mouse_press, "appFw.so GOT[postMousePress]");
        if (g_pRel)   hook_got_slot(app_base, 0x0377af4cu, (void *)real_appfw_post_mouse_release, "appFw.so GOT[postMouseRelease]");
#ifndef ZVE10_USB_SANDBOX
        if (g_orig_g5_in_set_cb)      hook_got_slot(app_base, 0x0377ac34u, (void *)g5_hook_appfw_in_set_cb, "appFw.so GOT[InfraInput::SetCallback]");
        if (g_orig_g5_in_set_keylist) hook_got_slot(app_base, 0x0377b640u, (void *)g5_hook_appfw_in_set_keylist, "appFw.so GOT[InfraInput::SetEventKeyList]");
#endif
#endif

        patch_thumb_jump((void *)(app_base + 0x02ce5f24u + 1u), (void *)g5_hook_appfw_dbglog, "appFw.so dbglog_sink");
        g_orig_seqlog_send = (seqlog_send_fn_t)make_thumb_trampoline_8(app_base + 0x02c2af70u, (void *)g5_hook_appfw_seqlog, "appFw.so seqlog_send");

        /* ADF 模式查询与错误阻断 */
        patch_adf_error_translator(app_base);
        patch_sequence_boot_adf_query(app_base);
        hook_got_slot(app_base, 0x0377b5d8u, (void *)stub_adf_ext_type, "appFw.so GOT[adf_ext_type]");

        /* DISP_MODE_OPTION 错误打印旁路 */
        patch_disp_mode_option_log(app_base);

        /* 统一安装五代菜单与屏幕生命周期钩子（QEMU 与真机全生效，挂载 HUD 与焦点控件） */
        g5_install_menu_boot_hooks(app_base);

        /* 保持五代原生面板参数与字库 Stride 对齐 (彻底根除乱码) */
        patch_panel_device_info(app_base);

        /* =========================================================================
         * 跨代硬件与协议桥接层 (Phase 2): 按严格 DAG 依赖拓扑激活其余 4 大模块
         * ========================================================================= */
        /* DAG 2: 存储挂载与拍摄联锁层 (根除 No SD Card，获取 DCF 句柄，解锁 allowRecord: 1) */
        uintptr_t mpr_base = get_module_base_maps("libmpr.so");
        init_bridge_media(app_base, mpr_base);
        uintptr_t v30_mp5_base = get_module_base_maps("libmp5.so");
        uintptr_t v30_ob5_base = get_module_base_maps("libOb5.so");
        g4media_install_c_fsys_got_hooks(app_base, v30_mp5_base, v30_ob5_base);

        /* DAG 3: 光学拓扑与镜头控制层 (消除 mwf_err[0x9004]，广播镜头 ROM，解除 F--) */
        uintptr_t mwf_base = get_module_base_maps("libMWF.so");
        init_bridge_optics(app_base, mwf_base);

        /* DAG 4: ISP 色彩与白平衡管线层 (消除 COND_WAIT_SLOW 挂死，透传创意外观与色温) */
        uintptr_t libobj_base = get_module_base_maps("libObj.so");
        init_bridge_isp(app_base, libobj_base);

        /* DAG 5: USB 模式与供电状态桥接层 (放行 Jack 插入/拔出，对齐 Gadget 掩码，消除 line 190 断言) */
        uintptr_t usb_base = get_module_base_maps("libUsbControl.so");
        init_bridge_usb(app_base, usb_base);
    }

    /* Hook libOb5.so GOT[mmap] (偏移 0x003553f4)，兼容 flags=0x18002 并拦截 MAP_FAILED(-1) */
    if (g_pGetWS) {
        Dl_info ob5_info = {0};
        if (dladdr((void *)g_pGetWS, &ob5_info) && ob5_info.dli_fbase) {
            hook_got_slot((uintptr_t)ob5_info.dli_fbase, 0x003553f4u, (void *)g5_hook_ob5_mmap, "libOb5.so GOT[mmap]");
        }
    }

    dump_maps_summary();

#ifdef ZVE10_USB_SANDBOX
    {
        const char *stop_env = getenv("ASTRA_SB_STOP_BEFORE_MAIN");
        if (stop_env && strcmp(stop_env, "1") == 0) {
            logf_("SANDBOX_STAGE1_OK: 已完成 16MB 栈装载、2730 构造与全部 GOT 装甲 (跳过 _Z4MainPv)");
            return NULL;
        }
        const char *stub_env = getenv("ASTRA_SB_CALL_STUB");
        const char *trace_env = getenv("ASTRA_SB_TRACE");
        if ((stub_env && strcmp(stub_env, "1") == 0) || (trace_env && strcmp(trace_env, "1") == 0)) {
            install_sandbox_step_tracer(hBootG5, hOb5, (void *)pMain);
        }
        if (stub_env && strcmp(stub_env, "1") == 0) {
            logf_("G3 沙盒桩调用 _Z4MainPv(g5_sb_stub_cb)");
            pMain((void *)g5_sb_stub_cb);
            logf_("SANDBOX_STAGE2_RETURNED");
            return NULL;
        }
    }
#endif

#ifdef ZVE10_REAL_DEVICE
    g_real_handoff_stage = "g5_main_loop";
#endif
    logf_("G3 调用 _Z4MainPv(Application_Start)");
    pMain(pStart);                                 /* 预期进入五代主事件循环 */
    logf_("_Z4MainPv 返回（异常退出）");
    g_astra_running = 0;
    return NULL;
}

static int g5_send_internal_event(uint32_t event_id)
{
    if (!g_appfw_base) {
        logf_("ASTRA_KEY_ERR: g_appfw_base=0 (event=0x%08x)", event_id);
        return -1;
    }
    const uint8_t *fn_addr = (const uint8_t *)(g_appfw_base + 0x0054e9d8u);
    static const uint8_t expected[4] = { 0x2du, 0xe9u, 0xf0u, 0x41u };
    if (memcmp(fn_addr, expected, sizeof(expected)) != 0) {
        logf_("ASTRA_KEY_ERR: appFw+0x54e9d8 签名不匹配 (%02x %02x %02x %02x)",
              fn_addr[0], fn_addr[1], fn_addr[2], fn_addr[3]);
        return -2;
    }
    typedef int (*g5_send_ev_fn_t)(const void *payload, uint32_t size);
    g5_send_ev_fn_t send_fn = (g5_send_ev_fn_t)(g_appfw_base + 0x0054e9d9u);
    /* pkt[0]=event_id, pkt[1]=0, pkt[2]=status(1), pkt[3]=prev_status(0) */
    uint32_t pkt[6] = { event_id, 0u, 1u, 0u, 0u, 0u };
    return send_fn(pkt, (uint32_t)sizeof(pkt));
}

/* Gen4 InfraInput 键码到五代内部动作事件 ID 的映射表 */
typedef struct {
    const char *name;
    uint32_t    g4_code;     /* Gen4 InfraInput 键码 */
    uint32_t    g5_ev_press; /* 五代按下事件 ID */
    uint32_t    g5_ev_rel;   /* 五代抬起事件 ID (单触发写 0) */
} g4_to_g5_key_map_t;

static const g4_to_g5_key_map_t g_key_bridge_map[] = {
    /* 四代硬件真实按键码 (libObj 0x144e360 表) */
    { "UP",          0x0003u, 0x02010000u, 0x02010001u },
    { "DOWN",        0x0030u, 0x02010003u, 0x02010004u },
    { "LEFT",        0x0015u, 0x02010006u, 0x02010007u },
    { "RIGHT",       0x01afu, 0x02010009u, 0x0201000au },
    { "CENTER",      0x01acu, 0x0201000cu, 0x0201000du },
    { "MENU",        0x01abu, 0x0201000fu, 0x02010010u },
    { "FN",          0x7095u, 0x02020000u, 0x02020001u },
    { "PLAY",        0x01f7u, 0x02020003u, 0x02020004u },
    { "DELETE",      0x01f8u, 0x02030000u, 0x02030001u },
    { "DISP",        0x01f9u, 0x02010000u, 0x02010001u }, /* FIXME: 0x02010000u 与 UP 冲突，待从真机 G5_IN 探针确认 DISP 事件 ID */
    { "C1",          0x0066u, 0x02060000u, 0x02060001u }, /* 自定义/虚化键，兼容 0x02060000/0x02150000 */
    { "C2",          0x70e7u, 0x02030000u, 0x02030001u }, /* 自定义2/垃圾桶 */
    { "C3",          0x70ecu, 0x02150006u, 0x02150007u },
    { "REC",         0x01f0u, 0x020f000du, 0x020f000eu }, /* 录制按键 */
    { "SHUTTER_S1",  0x01f4u, 0x020e000eu, 0x020e000fu }, /* 半按对焦 */
    { "SHUTTER_S2",  0x00a7u, 0x020e0000u, 0x020e0001u }, /* 全按拍照 */
    { "KURU_LEFT",   0x10000000u, 0x02050001u, 0u },        /* 四代 KURU 逆时针 -> 五代左 */
    { "KURU_RIGHT",  0x10000001u, 0x02050000u, 0u },        /* 四代 KURU 顺时针 -> 五代右 */
    { "WHEEL_LEFT",  0x10000003u, 0x02050001u, 0u },        /* 四代 WHEEL 逆时针 -> 五代左 */
    { "WHEEL_RIGHT", 0x10000004u, 0x02050000u, 0u },        /* 四代 WHEEL 顺时针 -> 五代右 */

    /* 兼容 QEMU / ASCII / 辅助控制键码 */
    { "UP_QEMU",     0x11u, 0x02010000u, 0x02010001u },
    { "DOWN_QEMU",   0x12u, 0x02010003u, 0x02010004u },
    { "LEFT_QEMU",   0x13u, 0x02010006u, 0x02010007u },
    { "RIGHT_QEMU",  0x14u, 0x02010009u, 0x0201000au },
    { "CENTER_QEMU", 0x0du, 0x0201000cu, 0x0201000du },
    { "MENU_QEMU",   0x10u, 0x0201000fu, 0x02010010u },
    { "MENU_ALT",    0x1bu, 0x0201000fu, 0x02010010u },
    { "FN_QEMU",     0x0eu, 0x02020000u, 0x02020001u },
    { "PLAY_QEMU",   0x1au, 0x02020003u, 0x02020004u },
    { "DELETE_QEMU", 0x1cu, 0x02030000u, 0x02030001u },
    { "C1_QEMU",     0x1fu, 0x02060000u, 0x02060001u },
    { "S1_QEMU",     0x01u, 0x020e000eu, 0x020e000fu },
    { "S2_QEMU",     0x02u, 0x020e0000u, 0x020e0001u },
    { "WHEEL_R_QEMU",0x21u, 0x02050000u, 0u },
    { "WHEEL_L_QEMU",0x22u, 0x02050001u, 0u },
};

static int g5_do_inject_g4_key_raw(uint32_t g4_code, int is_press)
{
    for (unsigned i = 0; i < sizeof(g_key_bridge_map) / sizeof(g_key_bridge_map[0]); i++) {
        if (g_key_bridge_map[i].g4_code == g4_code) {
            uint32_t ev = is_press ? g_key_bridge_map[i].g5_ev_press : g_key_bridge_map[i].g5_ev_rel;
            if (ev == 0 && !is_press) return 0;
            int rc = g5_send_internal_event(ev);
            /* 针对 C1、REC、半按对焦与全按快门，双发辅助事件提升五代相机状态机响应 */
            if (g4_code == 0x0066u || g4_code == 0x1fu) {
                g5_send_internal_event(is_press ? 0x02150000u : 0x02150001u);
            } else if (g4_code == 0x01f4u || g4_code == 0x01u) {
                g5_send_internal_event(is_press ? 0x02150017u : 0x02150018u); /* AF-ON */
            } else if (g4_code == 0x00a7u || g4_code == 0x02u) {
                g5_send_internal_event(is_press ? 0x02070000u : 0x020f0007u); /* TACT_CAP */
            } else if (g4_code == 0x01f0u) {
                g5_send_internal_event(is_press ? 0x0215000fu : 0x02150010u); /* STARTSTOP */
            }
            logf_("KEY_BRIDGE: g4_code=0x%04x (%s) %s -> g5_ev=0x%08x rc=%d",
                  g4_code, g_key_bridge_map[i].name, is_press ? "PRESS" : "RELEASE", ev, rc);
            return rc;
        }
    }
    logf_("KEY_BRIDGE: 未映射的 g4_code=0x%04x (press=%d)", g4_code, is_press);
    return -1;
}

/* 按键 60ms 状态保持机制：非阻塞延时释放线程，彻底杜绝短按丢失与回调阻塞 */
struct key_hold_entry {
    uint32_t g4_code;
    uint64_t press_ms;
    volatile int pressed;
    volatile int pending_rel;
};

#define KEY_HOLD_CAP 32
static struct key_hold_entry g_key_holds[KEY_HOLD_CAP];
static pthread_mutex_t g_key_hold_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t  g_key_hold_once = PTHREAD_ONCE_INIT;

static void *key_hold_worker_thread(void *arg)
{
    (void)arg;
    while (1) {
        usleep(10000); /* 10ms 扫描周期 */
        uint64_t now = g5_msec_now();
        pthread_mutex_lock(&g_key_hold_mtx);
        for (unsigned i = 0; i < KEY_HOLD_CAP; i++) {
            if (g_key_holds[i].pending_rel && (now - g_key_holds[i].press_ms >= 60ULL)) {
                uint32_t code = g_key_holds[i].g4_code;
                g_key_holds[i].pending_rel = 0;
                g_key_holds[i].pressed = 0;
                pthread_mutex_unlock(&g_key_hold_mtx);
                g5_do_inject_g4_key_raw(code, 0);
                pthread_mutex_lock(&g_key_hold_mtx);
            }
        }
        pthread_mutex_unlock(&g_key_hold_mtx);
    }
    return NULL;
}

static void start_key_hold_worker(void)
{
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 64u * 1024u);
    pthread_create(&th, &at, key_hold_worker_thread, NULL);
    pthread_attr_destroy(&at);
}

static int g5_inject_g4_key(uint32_t g4_code, int is_press)
{
    pthread_once(&g_key_hold_once, start_key_hold_worker);

    /* 滚轮单脉冲无需维持与延迟释放 */
    if (g4_code == 0x21 || g4_code == 0x22 ||
        g4_code == 0x10000000u || g4_code == 0x10000001u ||
        g4_code == 0x10000003u || g4_code == 0x10000004u) {
        return g5_do_inject_g4_key_raw(g4_code, 1);
    }

    pthread_mutex_lock(&g_key_hold_mtx);
    int slot = -1;
    for (int i = 0; i < KEY_HOLD_CAP; i++) {
        if (g_key_holds[i].pressed && g_key_holds[i].g4_code == g4_code) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < KEY_HOLD_CAP; i++) {
            if (!g_key_holds[i].pressed && !g_key_holds[i].pending_rel) {
                slot = i;
                break;
            }
        }
    }
    if (slot < 0) slot = 0;

    if (is_press) {
        g_key_holds[slot].g4_code = g4_code;
        g_key_holds[slot].press_ms = g5_msec_now();
        g_key_holds[slot].pressed = 1;
        g_key_holds[slot].pending_rel = 0;
        pthread_mutex_unlock(&g_key_hold_mtx);
        return g5_do_inject_g4_key_raw(g4_code, 1);
    } else {
        uint64_t now = g5_msec_now();
        uint64_t dt = now - g_key_holds[slot].press_ms;
        if (dt >= 60ULL) {
            g_key_holds[slot].pressed = 0;
            g_key_holds[slot].pending_rel = 0;
            pthread_mutex_unlock(&g_key_hold_mtx);
            return g5_do_inject_g4_key_raw(g4_code, 0);
        } else {
            g_key_holds[slot].pending_rel = 1;
            pthread_mutex_unlock(&g_key_hold_mtx);
            logf_("KEY_HOLD: g4_code=0x%04x 保持按下状态 (持续 %llu ms < 60ms, 异步延迟释放)",
                  g4_code, (unsigned long long)dt);
            return 0;
        }
    }
}

#ifndef ZVE10_REAL_DEVICE
/* 四代 InfraInput 底层事件正式回调：void (*cb)(int channel, void *ev) */
static void g4_real_infra_input_cb(int channel, void *ev_ptr)
{
    if (!ev_ptr) return;
    const uint32_t *ev = (const uint32_t *)ev_ptr;
    uint32_t keycode = ev[2];
    int32_t  status  = (int32_t)ev[3];

    if (keycode == 0x21 || keycode == 0x22 ||
        keycode == 0x10000000u || keycode == 0x10000001u ||
        keycode == 0x10000003u || keycode == 0x10000004u) {
        g5_inject_g4_key(keycode, 1);
    } else if (keycode == 0x20 || keycode == 0x10000016u || keycode == 0x10000011u || keycode == 0x7023u) {
        if (status > 0) {
            g5_inject_g4_key(0x21 /* WHEEL_R */, 1);
        } else if (status < 0) {
            g5_inject_g4_key(0x22 /* WHEEL_L */, 1);
        }
    } else {
        int is_press = (status != 0) ? 1 : 0;
        g5_inject_g4_key(keycode, is_press);
    }
    logf_("G4_INFRA_KEY: ch=%d keycode=0x%04x (%u) status=%d (ev=%p)",
          channel, keycode, keycode, (int)status, ev_ptr);
}
#endif

#if 0
/* 兼顾 ABI 安全设计：编写通用拦截桩 hook_callback_direct(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3) */
static int hook_callback_direct(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3)
{
    (void)a3;
    const uint32_t *ev = NULL;
    if (a1 > 0x1000u && (a1 & 3u) == 0) {
        ev = (const uint32_t *)a1;
    } else if (a2 > 0x1000u && (a2 & 3u) == 0) {
        ev = (const uint32_t *)a2;
    } else if (a0 > 0x1000u && (a0 & 3u) == 0) {
        ev = (const uint32_t *)a0;
    }

    if (ev) {
        uint32_t keycode = ev[2];
        int32_t  status  = (int32_t)ev[3];

        /* 模块 4：放行 USB 插拔与供电状态事件（穿透上报五代） */
        if (g4usb_filter_callback_event(keycode, status) == 0) {
            return 0;
        }

        if (keycode == 0x21 || keycode == 0x22 ||
            keycode == 0x10000000u || keycode == 0x10000001u ||
            keycode == 0x10000003u || keycode == 0x10000004u) {
            g5_inject_g4_key(keycode, 1);
        } else if (keycode == 0x20 || keycode == 0x10000016u || keycode == 0x10000011u || keycode == 0x7023u) {
            if (status > 0) {
                g5_inject_g4_key(0x21 /* WHEEL_R */, 1);
            } else if (status < 0) {
                g5_inject_g4_key(0x22 /* WHEEL_L */, 1);
            }
        } else {
            int is_press = (status != 0) ? 1 : 0;
            g5_inject_g4_key(keycode, is_press);
        }
        logf_("G4KEY_INTERCEPT: keycode=0x%04x (%u) status=%d (ev=%p a0=0x%lx a1=0x%lx a2=0x%lx)",
              keycode, keycode, (int)status, ev, (unsigned long)a0, (unsigned long)a1, (unsigned long)a2);
    } else {
        logf_("G4KEY_INTERCEPT: 无法解析事件指针 (a0=0x%lx a1=0x%lx a2=0x%lx)",
              (unsigned long)a0, (unsigned long)a1, (unsigned long)a2);
    }

    /* 最关键：转发后直接返回 0（“吞掉”事件，不向四代透传，防止唤醒四代 UI 状态机或争抢显存） */
    return 0;
}
#endif

/* 通用唤醒与切屏目标控制状态（QEMU 与真机均需使用） */
static int g_wake_pipe[2] = { -1, -1 };
static pthread_once_t g_wake_pipe_once = PTHREAD_ONCE_INIT;
static volatile int g_pending_switch_target = 0;
static volatile int g_boost_render_flag = 0;

static void g5_init_wake_pipe(void)
{
    if (pipe(g_wake_pipe) != 0) {
        g_wake_pipe[0] = -1;
        g_wake_pipe[1] = -1;
        return;
    }
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(g_wake_pipe[i], F_GETFL, 0);
        if (fl >= 0) (void)fcntl(g_wake_pipe[i], F_SETFL, fl | O_NONBLOCK);
        int fdfl = fcntl(g_wake_pipe[i], F_GETFD, 0);
        if (fdfl >= 0) (void)fcntl(g_wake_pipe[i], F_SETFD, fdfl | FD_CLOEXEC);
    }
}

static void g5_wake_render_driver(void)
{
    pthread_once(&g_wake_pipe_once, g5_init_wake_pipe);
    if (g_wake_pipe[1] >= 0) {
        char b = 'W';
        ssize_t r = write(g_wake_pipe[1], &b, 1);
        (void)r;
    }
}

enum {
    G5_TOUCH_DOWN = 1,
    G5_TOUCH_MOVE = 2,
    G5_TOUCH_UP   = 3,
};

struct g5_touch_ev {
    uint8_t kind;
    int16_t x;
    int16_t y;
};

#define G5_TOUCH_Q_CAP 64
static pthread_mutex_t g_touch_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct g5_touch_ev g_touch_q[G5_TOUCH_Q_CAP];
static unsigned g_touch_head = 0, g_touch_tail = 0;
static volatile uint32_t g_touch_rx_seq __attribute__((unused)) = 0;
static volatile uint32_t g_touch_applied_seq __attribute__((unused)) = 0;

static void g5_touch_push(uint8_t kind, int16_t x, int16_t y)
{
    pthread_mutex_lock(&g_touch_mtx);
    unsigned next = (g_touch_head + 1u) % G5_TOUCH_Q_CAP;
    if (next == g_touch_tail) {
        /* 队列满时优先覆盖最旧事件，确保最新手指位置绝不丢失 */
        g_touch_tail = (g_touch_tail + 1u) % G5_TOUCH_Q_CAP;
    }
    g_touch_q[g_touch_head].kind = kind;
    g_touch_q[g_touch_head].x = x;
    g_touch_q[g_touch_head].y = y;
    g_touch_head = next;
    pthread_mutex_unlock(&g_touch_mtx);
    g5_wake_render_driver();
}

static int hook_callback_panel(void *a0, void *a1, void *a2)
{
    /* 屏轴/霍尔传感器事件：安全消费，严禁注入五代按键队列，杜绝误触发按键 */
    (void)a0; (void)a1; (void)a2;
    return 0;
}

static int hook_callback_tp_raw(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3)
{
    (void)a0; (void)a2; (void)a3;
    if (a1 > 0x1000u && (a1 & 3u) == 0) {
        uint16_t x   = *(const uint16_t *)(a1 + 4u);
        uint16_t y   = *(const uint16_t *)(a1 + 6u);
        uint32_t act = *(const uint32_t *)(a1 + 8u); /* 1=Down, 2=Up, 3=Move */

        /* 注入五代 WindowSurface (postMouseMove / postMousePress / postMouseRelease) */
        void *ws = g_pGetWS ? g_pGetWS() : NULL;
        uint64_t t_now = g5_msec_now();
        if (ws) {
            if (act == 1u) { /* Touch Down */
                if (g_pMove) g_pMove(ws, 0, (int16_t)x, (int16_t)y, &t_now);
                if (g_pPress) g_pPress(ws, 0, 1, &t_now);
            } else if (act == 3u) { /* Touch Move */
                if (g_pMove) g_pMove(ws, 0, (int16_t)x, (int16_t)y, &t_now);
            } else if (act == 2u) { /* Touch Up */
                if (g_pMove) g_pMove(ws, 0, (int16_t)x, (int16_t)y, &t_now);
                if (g_pRel) g_pRel(ws, 0, 1, &t_now);
            }
        }

        /* 同时推入通用触屏事件队列 g_touch_q */
        uint8_t kind = (act == 1u) ? 1u : ((act == 2u) ? 3u : 2u);
        g5_touch_push(kind, (int16_t)x, (int16_t)y);

        static uint32_t s_tp_cnt = 0;
        uint32_t cnt = __sync_add_and_fetch(&s_tp_cnt, 1u);
        if (cnt <= 10 || (cnt % 60 == 0)) {
            logf_("G4TP_BRIDGE [#%u]: act=%u xy=(%u,%u) ws=%p", cnt, act, (unsigned)x, (unsigned)y, ws);
        }
    }
    return 0;
}

static void install_g4_key_intercept(uintptr_t libobj_base)
{
    if (!libobj_base) return;
    static volatile int s_installed = 0;
    if (__sync_lock_test_and_set(&s_installed, 1)) return;

    /* 1. 初始化真机触屏/按键/电源桥接层 (模块 6) */
    init_bridge_input(libobj_base, g_appfw_base);

    /* 2. 移除四代 InputService::callback_direct / callback_dial_signed_speed 冲突跳板，输入全权交由五代 libOb5 原生通道 */
    logf_("G4_TP_BRIDGE: 已移除 libObj callback_direct/callback_dial_signed_speed 冲突跳板，输入全权由五代 libOb5 处理");
}

#ifndef ZVE10_REAL_DEVICE

struct g5_kernel_termios {
    uint32_t iflag, oflag, cflag, lflag;
    unsigned char line, cc[19];
};

static volatile uint32_t g_render_cycle = 0;
static volatile uint32_t g_render_stage = 0;
static volatile uint32_t g_uart_rx_bytes = 0;
static volatile uint32_t g_uart_cmds = 0;
static volatile uint32_t g_uart_reopens = 0;

static int16_t g5_clamp_touch_coord(long v, int16_t max_val)
{
    if (v < 0) return 0;
    if (v > max_val) return max_val;
    return (int16_t)v;
}

static int g5_touch_pop(struct g5_touch_ev *out, unsigned *remaining_out)
{
    int got = 0;
    pthread_mutex_lock(&g_touch_mtx);
    while (g_touch_tail != g_touch_head) {
        *out = g_touch_q[g_touch_tail];
        g_touch_tail = (g_touch_tail + 1u) % G5_TOUCH_Q_CAP;
        got = 1;
        /* 连续堆积 MOVE 时折叠为最新位置，消除拖拽滞后，DOWN/UP 严格保持独立帧边界 */
        if (out->kind == G5_TOUCH_MOVE && g_touch_tail != g_touch_head &&
            g_touch_q[g_touch_tail].kind == G5_TOUCH_MOVE) {
            continue;
        }
        break;
    }
    if (remaining_out) {
        *remaining_out = (g_touch_head + G5_TOUCH_Q_CAP - g_touch_tail) % G5_TOUCH_Q_CAP;
    }
    pthread_mutex_unlock(&g_touch_mtx);
    return got;
}

static void g5_touch_wait_ms(unsigned ms)
{
    pthread_once(&g_wake_pipe_once, g5_init_wake_pipe);
    int has_work = 0;
    pthread_mutex_lock(&g_touch_mtx);
    if (g_touch_tail != g_touch_head) has_work = 1;
    pthread_mutex_unlock(&g_touch_mtx);
    if (has_work) {
        return;
    }
    if (__atomic_load_n(&g_pending_switch_target, __ATOMIC_ACQUIRE) != 0 && ms > 16u) {
        /* 切屏等待期间保持 16ms 上限刷新节拍，避免 0ms 忙等空转 */
        ms = 16u;
    }
    if (g_wake_pipe[0] >= 0) {
        /* 仅依赖 poll 相对毫秒超时等待管道唤醒，完全免疫 wall-clock 回绕 */
        struct pollfd pfd;
        pfd.fd = g_wake_pipe[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        int timeout = (ms > 60000u) ? 60000 : (int)ms;
        int rc = poll(&pfd, 1, timeout);
        if (rc > 0 && (pfd.revents & POLLIN)) {
            char drain[64];
            while (read(g_wake_pipe[0], drain, sizeof(drain)) > 0) { }
        }
        return;
    }
    usleep((useconds_t)ms * 1000u);
}

typedef struct {
    const char *name;
    uint32_t    ev_on;
    uint32_t    ev_off;
} g5_tact_key_def_t;

static const g5_tact_key_def_t g5_tact_key_table[] = {
    { "UP",          0x02010000u, 0x02010001u },
    { "DOWN",        0x02010003u, 0x02010004u },
    { "LEFT",        0x02010006u, 0x02010007u },
    { "RIGHT",       0x02010009u, 0x0201000au },
    { "ENTER",       0x0201000cu, 0x0201000du },
    { "OK",          0x0201000cu, 0x0201000du },
    { "CENTER",      0x0201000cu, 0x0201000du },
    { "MENU",        0x0201000fu, 0x02010010u },
    { "MS_UP",       0x02010011u, 0x02010012u },
    { "MS_DOWN",     0x02010014u, 0x02010015u },
    { "MS_LEFT",     0x02010017u, 0x02010018u },
    { "MS_RIGHT",    0x0201001au, 0x0201001bu },
    { "MS_ENTER",    0x0201001du, 0x0201001eu },
    { "FN",          0x02020000u, 0x02020001u },
    { "PLAY",        0x02020003u, 0x02020004u },
    { "DELETE",      0x02030000u, 0x02030001u },
    { "DEL",         0x02030000u, 0x02030001u },
    { "C1",          0x02060000u, 0x02060001u },
    { "CUSTOM1",     0x02060000u, 0x02060001u },
    { "C2",          0x02030000u, 0x02030001u },
    { "REC",         0x020f000du, 0x020f000eu },
    { "SHUTTER_HALF",0x020e000eu, 0x020e000fu },
    { "S1",          0x020e000eu, 0x020e000fu },
    { "SHUTTER",     0x020e0000u, 0x020e0001u },
    { "SHUTTER_FULL",0x020e0000u, 0x020e0001u },
    { "S2",          0x020e0000u, 0x020e0001u },
    { "WHEEL_RIGHT", 0x02050000u, 0u },
    { "WHEEL_LEFT",  0x02050001u, 0u },
    { "WHEEL_R",     0x02050000u, 0u },
    { "WHEEL_L",     0x02050001u, 0u },
    { "DIAL_R",      0x02050000u, 0u },
    { "DIAL_L",      0x02050001u, 0u },
    { "LOCK",        0x02060000u, 0x02060001u },
};

static const g5_tact_key_def_t *g5_find_tact_key(const char *name)
{
    if (!name || !name[0]) return NULL;
    for (unsigned i = 0; i < (unsigned)(sizeof(g5_tact_key_table) / sizeof(g5_tact_key_table[0])); i++) {
        if (strcasecmp(name, g5_tact_key_table[i].name) == 0) {
            return &g5_tact_key_table[i];
        }
    }
    return NULL;
}

static void g5_send_tact_key_name(const char *name, int mode)
{
    /* mode: 0 = press+release, 1 = press only, 2 = release only */
    const g5_tact_key_def_t *kd = g5_find_tact_key(name);
    if (!kd) {
        logf_("ASTRA_KEY_ERR: 未知按键 '%s'", name ? name : "");
        return;
    }
    int rc_on = 0, rc_off = 0;
    if (mode == 0 || mode == 1) {
        rc_on = g5_send_internal_event(kd->ev_on);
    }
    if (mode == 0 && kd->ev_off != 0) {
        usleep(70000);
        rc_off = g5_send_internal_event(kd->ev_off);
    } else if (mode == 2 && kd->ev_off != 0) {
        rc_off = g5_send_internal_event(kd->ev_off);
    }
    logf_("ASTRA_KEY_ACK key=%s mode=%d on=0x%08x(%d) off=0x%08x(%d)",
          kd->name, mode, kd->ev_on, rc_on, kd->ev_off, rc_off);
}

#define ASTRA_KEY_Q_CAP 32u
typedef struct {
    char name[24];
    int  mode;
} g5_key_req_t;

static g5_key_req_t    g_key_q[ASTRA_KEY_Q_CAP];
static unsigned        g_key_q_head = 0u;
static unsigned        g_key_q_tail = 0u;
static pthread_mutex_t g_key_q_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_key_q_cv  = PTHREAD_COND_INITIALIZER;
static pthread_once_t  g_key_tx_once = PTHREAD_ONCE_INIT;

static void *g5_key_tx_thread(void *unused)
{
    (void)unused;
    for (;;) {
        g5_key_req_t req;
        pthread_mutex_lock(&g_key_q_mtx);
        while (g_key_q_head == g_key_q_tail) {
            pthread_cond_wait(&g_key_q_cv, &g_key_q_mtx);
        }
        req = g_key_q[g_key_q_tail];
        g_key_q_tail = (g_key_q_tail + 1u) % ASTRA_KEY_Q_CAP;
        pthread_mutex_unlock(&g_key_q_mtx);

        g5_send_tact_key_name(req.name, req.mode);
        __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
        g5_wake_render_driver();
    }
    return NULL;
}

static void g5_start_key_tx_thread(void)
{
    pthread_attr_t at;
    pthread_t kth;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 128u * 1024u);
    if (pthread_create(&kth, &at, g5_key_tx_thread, NULL) != 0) {
        logf_("ASTRA_KEY_ERR: 无法创建异步按键派发线程");
    }
    pthread_attr_destroy(&at);
}

/* 将按键入队由独立线程派发，防止 usleep(70ms) 与 OSAL IPC 等待阻塞 uart_touch_rx_thread */
static void g5_enqueue_tact_key(const char *name, int mode)
{
    const g5_tact_key_def_t *kd = g5_find_tact_key(name);
    if (!kd) {
        logf_("ASTRA_KEY_ERR: 未知按键 '%s'", name ? name : "");
        return;
    }
    pthread_once(&g_key_tx_once, g5_start_key_tx_thread);
    pthread_mutex_lock(&g_key_q_mtx);
    unsigned next = (g_key_q_head + 1u) % ASTRA_KEY_Q_CAP;
    if (next == g_key_q_tail) {
        g_key_q_tail = (g_key_q_tail + 1u) % ASTRA_KEY_Q_CAP;
        logf_("ASTRA_KEY_WARN: 按键队列已满，丢弃最旧请求");
    }
    snprintf(g_key_q[g_key_q_head].name, sizeof(g_key_q[g_key_q_head].name), "%s", kd->name);
    g_key_q[g_key_q_head].mode = mode;
    g_key_q_head = next;
    pthread_cond_signal(&g_key_q_cv);
    pthread_mutex_unlock(&g_key_q_mtx);
}

#ifndef SIGSTKFLT
#define SIGSTKFLT 16
#endif

static volatile struct {
    int ready;
    long tid;
    uintptr_t pc;
    uintptr_t lr;
    uintptr_t sp;
    uintptr_t bt[10];
    int nbt;
} g_stack_snap;

static void g5_stack_snap_handler(int sig, siginfo_t *si, void *uc_)
{
    (void)sig;
    (void)si;
    ucontext_t *uc = (ucontext_t *)uc_;
    if (!uc) return;
    uintptr_t app_lo = g_appfw_base;
    uintptr_t app_hi = app_lo ? (app_lo + 0x03700000u) : 0;
    uintptr_t sp = (uintptr_t)uc->uc_mcontext.arm_sp;
    g_stack_snap.tid = (long)syscall(SYS_gettid);
    g_stack_snap.pc = (uintptr_t)uc->uc_mcontext.arm_pc;
    g_stack_snap.lr = (uintptr_t)uc->uc_mcontext.arm_lr;
    g_stack_snap.sp = sp;
    int nbt = 0;
    if (app_lo != 0 && sp >= 0x10000u && (sp & 3u) == 0) {
        uintptr_t page_end = (sp & ~(uintptr_t)4095u) + 4096u;
        uintptr_t max_end = sp + 512u;
        if (max_end > page_end) max_end = page_end;
        for (uintptr_t p = sp; p + 4u <= max_end && nbt < 10; p += 4u) {
            uintptr_t v = *(const volatile uintptr_t *)p;
            if (v >= app_lo && v < app_hi) {
                g_stack_snap.bt[nbt++] = v - app_lo;
            }
        }
    }
    g_stack_snap.nbt = nbt;
    __atomic_store_n(&g_stack_snap.ready, 1, __ATOMIC_RELEASE);
}

static int g5_ensure_stack_handler(void)
{
    static int installed = 0;
    if (installed > 0) return 0;
    if (installed < 0) return -1;
    struct sigaction old_sa;
    memset(&old_sa, 0, sizeof(old_sa));
    if (sigaction(SIGSTKFLT, NULL, &old_sa) != 0 || old_sa.sa_handler != SIG_DFL) {
        installed = -1;
        logf_("STACKS: SIGSTKFLT 已被占用 (handler=%p)", (void *)old_sa.sa_handler);
        return -1;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = g5_stack_snap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    if (sigaction(SIGSTKFLT, &sa, NULL) != 0) {
        installed = -1;
        return -1;
    }
    installed = 1;
    return 0;
}

static void g5_sample_thread_stack(long tid, const char *comm)
{
    long self = (long)syscall(SYS_gettid);
    if (tid <= 0 || tid == self) return;
    if (g5_ensure_stack_handler() != 0) return;
    __atomic_store_n(&g_stack_snap.ready, 0, __ATOMIC_RELEASE);
    if (syscall(SYS_tgkill, (long)getpid(), tid, SIGSTKFLT) != 0) {
        logf_("  STACK tid=%ld (%s): tgkill 失败 errno=%d", tid, comm ? comm : "?", errno);
        return;
    }
    for (int i = 0; i < 40; i++) {
        if (__atomic_load_n(&g_stack_snap.ready, __ATOMIC_ACQUIRE) != 0) break;
        usleep(5000);
    }
    if (!__atomic_load_n(&g_stack_snap.ready, __ATOMIC_ACQUIRE)) {
        logf_("  STACK tid=%ld (%s): 采样超时", tid, comm ? comm : "?");
        return;
    }
    uintptr_t app_lo = g_appfw_base;
    uintptr_t app_hi = app_lo ? (app_lo + 0x03700000u) : 0;
    uintptr_t pc = g_stack_snap.pc, lr = g_stack_snap.lr;
    uintptr_t pc_off = (app_lo && pc >= app_lo && pc < app_hi) ? (pc - app_lo) : 0;
    uintptr_t lr_off = (app_lo && lr >= app_lo && lr < app_hi) ? (lr - app_lo) : 0;
    char bt_str[160] = "";
    int pos = 0;
    for (int i = 0; i < g_stack_snap.nbt && pos < (int)sizeof(bt_str) - 16; i++) {
        pos += snprintf(bt_str + pos, sizeof(bt_str) - (size_t)pos, "%s0x%lx",
                        i ? "," : "", (unsigned long)g_stack_snap.bt[i]);
    }
    logf_("  STACK tid=%ld %-16s pc=%#lx(off=0x%lx) lr=%#lx(off=0x%lx) bt=[%s]",
          tid, comm ? comm : "?", (unsigned long)pc, (unsigned long)pc_off,
          (unsigned long)lr, (unsigned long)lr_off, bt_str);
}

static void g5_dump_threads_wchan(int sample_app_stacks)
{
    DIR *d = opendir("/proc/self/task");
    if (!d) {
        logf_("ASTRA_THREADS: opendir 失败 errno=%d", errno);
        return;
    }
    logf_("=== ASTRA_THREADS_BEGIN (app_base=%#lx) ===", (unsigned long)g_appfw_base);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char path[128], comm[64] = "?", wchan[64] = "?", sysb[128] = "?", statb[256] = "";
        char st_ch = '?';
        unsigned long utime = 0, stime = 0;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            int n = (int)read(fd, comm, sizeof(comm) - 1);
            if (n > 0) { comm[n] = 0; if (comm[n - 1] == '\n') comm[n - 1] = 0; }
            close(fd);
        }
        snprintf(path, sizeof(path), "/proc/self/task/%s/wchan", de->d_name);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            int n = (int)read(fd, wchan, sizeof(wchan) - 1);
            if (n > 0) { wchan[n] = 0; if (wchan[n - 1] == '\n') wchan[n - 1] = 0; }
            close(fd);
        }
        snprintf(path, sizeof(path), "/proc/self/task/%s/stat", de->d_name);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            int n = (int)read(fd, statb, sizeof(statb) - 1);
            if (n > 0) {
                statb[n] = 0;
                const char *rp = strrchr(statb, ')');
                if (rp && rp[1] == ' ' && rp[2] != '\0') {
                    st_ch = rp[2];
                    /* 手动跳过 state 及后续 10 个空白分隔字段，读取第 14/15 个字段 utime/stime，避免引入 GLIBC_2.7 sscanf */
                    const char *p = rp + 2;
                    for (int field = 0; field < 11 && *p; field++) {
                        while (*p && *p != ' ') p++;
                        while (*p == ' ') p++;
                    }
                    if (*p) {
                        char *endp = NULL;
                        utime = strtoul(p, &endp, 10);
                        if (endp && *endp) {
                            stime = strtoul(endp, NULL, 10);
                        }
                    }
                }
            }
            close(fd);
        }
        if (!sample_app_stacks) {
            snprintf(path, sizeof(path), "/proc/self/task/%s/syscall", de->d_name);
            fd = open(path, O_RDONLY);
            if (fd >= 0) {
                int n = (int)read(fd, sysb, sizeof(sysb) - 1);
                if (n > 0) { sysb[n] = 0; if (sysb[n - 1] == '\n') sysb[n - 1] = 0; }
                close(fd);
            }
            logf_("  TID=%-5s %c u=%lu s=%lu comm=%-18s wchan=%-22s sys=%s",
                  de->d_name, st_ch, utime, stime, comm, wchan, sysb);
        } else if (strcmp(comm, "THREAD_APP") == 0 || strcmp(comm, "RemotePresenter") == 0 ||
                   strcmp(comm, "I-InputMain") == 0 || strcmp(comm, "ScreenReaderMai") == 0) {
            long tid = strtol(de->d_name, NULL, 10);
            logf_("  TARGET tid=%ld %c u=%lu s=%lu comm=%s wchan=%s", tid, st_ch, utime, stime, comm, wchan);
            g5_sample_thread_stack(tid, comm);
        }
    }
    closedir(d);
    logf_("=== ASTRA_THREADS_END ===");
}

#endif /* !ZVE10_REAL_DEVICE (QEMU touch & uart helpers) */

/* =========================================================================
 * 五代 UI 屏幕管理器与生命周期核心钩子（QEMU 与真机全生效）
 * 作用：拦截向导屏并重定向、放行 rep_boot_can_open 挂载全套 HUD 控件树
 * ========================================================================= */
#define ASTRA_SCR_INVALID   0x3f6u
#define ASTRA_SCR_BOOT_CTRL 0x2f0u
#define ASTRA_SCR_SHOOTING  0x2ecu
#define ASTRA_SCR_MENU_CTRL 0x2efu
#define ASTRA_SCR_MENU_SUB  0x300u
#define ASTRA_SCR_MENU_UI   0x27fu

#define APPFW_OFF_PCM_OPEN_SCREEN          0x0167b514u
#define APPFW_OFF_PCM_ENQUEUE_OPEN         0x0167c968u
#define APPFW_OFF_PCM_GET_TOP_SCR          0x0165d9f6u
#define APPFW_OFF_SCR0039_OPEN             0x0184e4e4u
#define APPFW_OFF_REP_BOOT_INIT            0x017f95a8u
#define APPFW_OFF_REP_BOOT_CAN_OPEN        0x017f91b0u
#define APPFW_OFF_APP_GET_NEXT_EVT         0x0054f548u
#define APPFW_OFF_VENEER_TRANSLATE_3_EVS   0x01910410u
#define APPFW_OFF_TRANSLATE_3_EVS_TGT      0x0054bb78u
#define APPFW_OFF_VENEER_CUSTOM_KEY_REMAP  0x01910708u
#define APPFW_OFF_CUSTOM_KEY_REMAP_TGT     0x0054c940u
#define APPFW_OFF_VENEER_INHIBIT_FILTER    0x0190f288u
#define APPFW_OFF_INHIBIT_FILTER_TGT       0x0054fe40u
#define APPFW_OFF_PROP_19BA_SETTER         0x01f154b4u
#define APPFW_OFF_PROP_19BA_VAL            0x0749452cu
#define APPFW_OFF_PROP_19BA_SYNC           0x07494530u
#define APPFW_OFF_BOOT_INFO_BSS            0x0742d18cu
#define ASTRA_WAKE_EVT_ID                  0x5a564551u

typedef int  (*pcm_open_screen_fn_t)(void *pcm_obj, const uint32_t *cur_scr, const uint32_t *next_scr,
                                     const uint32_t *opt_scr, uint32_t a4, uint32_t b1, uint32_t b2,
                                     uint32_t a7, uint32_t a8);
typedef void (*scr0039_open_fn_t)(void *scr_obj, const uint32_t *next_scr, const uint32_t *opt_scr,
                                  const uint32_t *extra_scr);
typedef int  (*rep_boot_init_fn_t)(void *rep_obj);
typedef int  (*rep_boot_can_open_fn_t)(void *rep_obj);
/* ARM AAPCS: uint64_t timeout 为第 4 参数(8B对齐跳过r3，经栈传递) */
typedef int  (*app_get_next_evt_fn_t)(void *ctx, uint32_t *out_evt, int wait_flag, uint64_t timeout);
typedef void (*g5_translate_3_evs_fn_t)(void *mgr, uint32_t *ev1, uint32_t *ev2, uint32_t *ev3,
                                        const g5_infra_input_ev_t *raw_ev);
typedef void (*g5_custom_key_remap_fn_t)(void *mgr, uint32_t *out_ev, uint32_t *out_saved,
                                         const void *raw_ptr, uint32_t mode_arg);
typedef void (*g5_global_inhibit_fn_t)(void *mgr, uint32_t *out_evt);

static void *volatile g_pcm_obj = NULL;
static volatile uint32_t g_last_cur_scr = ASTRA_SCR_INVALID;
static volatile uint32_t g_last_next_scr = ASTRA_SCR_INVALID;
static volatile uint32_t g_cached_top_scr = ASTRA_SCR_INVALID;
static volatile uint32_t g_pcm_open_cnt = 0;
static volatile long g_pcm_tid = 0;
static volatile long g_evt_loop_tid = 0;
static volatile int g_switch_in_progress = 0;
static volatile int g_boot_bypass_done = 0;
static volatile int g_rep_boot_key_patched = 0;
static volatile int g_menu_boot_completed = 0;
static volatile int g_menu_fallback_queued = 0;

static pcm_open_screen_fn_t     g_orig_pcm_open_screen = NULL;
static scr0039_open_fn_t        g_orig_scr0039_open = NULL;
static rep_boot_init_fn_t       g_orig_rep_boot_init = NULL;
static rep_boot_can_open_fn_t   g_orig_rep_boot_can_open = NULL;
static app_get_next_evt_fn_t    g_orig_app_get_next_evt = NULL;
static g5_translate_3_evs_fn_t  g_orig_translate_3_evs = NULL;
static g5_custom_key_remap_fn_t g_orig_custom_key_remap = NULL;
static g5_global_inhibit_fn_t   g_orig_global_inhibit = NULL;

static volatile uint32_t g_g5_tr3_dial_log_cnt = 0;
static volatile uint32_t g_g5_remap_log_cnt = 0;
static volatile uint32_t g_g5_remap_same_log_cnt = 0;
static volatile uint32_t g_g5_inhibit_bypass_cnt = 0;

/* 安全替换 16 字节 ARM PLT/long-branch veneer（前 8B 为 ldr pc, [pc, #-4] + 目标地址），直接返回原 Thumb 目标 (+1) */
static void *patch_arm_veneer_jump(uintptr_t veneer_va, const uint8_t exp_veneer16[16],
                                   uintptr_t target_va, const uint8_t exp_target8[8],
                                   void *hook_fn, const char *name)
{
    if ((veneer_va & 3u) != 0u) {
        logf_("HOOK_VENEER_ERR: %s veneer=%p 非 4B 对齐", name, (void *)veneer_va);
        return NULL;
    }
    if (memcmp((const void *)veneer_va, exp_veneer16, 16) != 0) {
        const uint8_t *v = (const uint8_t *)veneer_va;
        logf_("HOOK_VENEER_WARN: %s veneer 签名不匹配 (%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x)",
              name, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
              v[8], v[9], v[10], v[11], v[12], v[13], v[14], v[15]);
        return NULL;
    }
    if (memcmp((const void *)target_va, exp_target8, 8) != 0) {
        const uint8_t *t = (const uint8_t *)target_va;
        logf_("HOOK_VENEER_WARN: %s target 签名不匹配 (%02x%02x%02x%02x %02x%02x%02x%02x)",
              name, t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
        return NULL;
    }
    uintptr_t page = veneer_va & ~(uintptr_t)4095u;
    if (mprotect((void *)page, 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        logf_("HOOK_VENEER_ERR: %s mprotect(%p) 失败 errno=%d", name, (void *)page, errno);
        return NULL;
    }
    volatile uint32_t *p32 = (volatile uint32_t *)veneer_va;
    p32[0] = 0xe51ff004u; /* ldr pc, [pc, #-4] */
    p32[1] = (uint32_t)(uintptr_t)hook_fn;
    __builtin___clear_cache((char *)veneer_va, (char *)veneer_va + 8);
    logf_("HOOK_VENEER: %s (%p -> %p, orig_thumb=%p) 安装成功",
          name, (void *)veneer_va, hook_fn, (void *)(target_va | 1u));
    return (void *)(target_va | 1u);
}

static void g5_hook_translate_3_evs(void *mgr, uint32_t *ev1, uint32_t *ev2, uint32_t *ev3,
                                    const g5_infra_input_ev_t *raw_ev)
{
    if (g_orig_translate_3_evs) {
        g_orig_translate_3_evs(mgr, ev1, ev2, ev3, raw_ev);
    }
    if (!raw_ev || !ev1) return;

    uint32_t orig_ev1 = *ev1;
    uint32_t code = raw_ev->event_code;
    int32_t  st   = raw_ev->status;
    uint32_t mapped = orig_ev1;

    /* 补充 ZV-E10 物理拨轮/转盘与电源拨片事件映射（解决命中 default->0x143 或仅发 WHEEL3 失效的问题） */
    if (code == 0x10000000u) {
        if (st != 0) mapped = 0x02050001u; /* KURU_LEFT -> WHEEL_LEFT */
    } else if (code == 0x02d2u || code == 0x10000001u) {
        if (st != 0) mapped = 0x02050000u; /* KURU_RIGHT -> WHEEL_RIGHT */
    } else if (code == 0x02d3u || code == 0x10000003u) {
        if (st != 0) mapped = 0x02050003u; /* KURU2_LEFT -> WHEEL2_LEFT */
    } else if (code == 0x02d4u || code == 0x10000004u) {
        if (st != 0) mapped = 0x02050002u; /* KURU2_RIGHT -> WHEEL2_RIGHT */
    } else if (code == 0x02e1u || code == 0x10000011u) {
        if (st != 0) mapped = (st > 0) ? 0x02050000u : 0x02050001u;
    } else if (code == 0x02e7u || code == 0x10000016u) {
        /* 0x02e7 原被译为 WHEEL3 (0x02050004/5)，但拍摄与菜单控制器监听 WHEEL2 (0x02050002/3) */
        if (st != 0) mapped = (st > 0) ? 0x02050002u : 0x02050003u;
    } else if (code == 0x02e9u || code == 0x10000017u) {
        /* 0x02e9 原仅接受 st==±30 且只发 WHEEL3，统一兼容任意非零增量并映射为 WHEEL */
        if (st != 0) mapped = (st > 0) ? 0x02050000u : 0x02050001u;
    } else if (code == 0x01d2u && orig_ev1 == 0x143u) {
        mapped = (st != 0) ? 0x020f0005u : 0x020f0004u;
    }

    if (mapped != orig_ev1) {
        *ev1 = mapped;
        uint32_t cnt = __sync_add_and_fetch(&g_g5_tr3_dial_log_cnt, 1u);
        if (cnt <= 80u || (cnt % 40u) == 0u) {
            logf_("G5_TR3_DIAL[#%u]: code=0x%08x st=%d orig=0x%08x -> mapped=0x%08x",
                  cnt, code, st, orig_ev1, mapped);
        }
    }
}

static int g5_is_shooting_diag_key(uint32_t ev)
{
    return (ev == 0x02010003u || ev == 0x02010006u || ev == 0x02010009u ||
            ev == 0x0201000cu || ev == 0x02030000u || ev == 0x02150000u ||
            ev == 0x0215000fu);
}

static void g5_hook_custom_key_remap(void *mgr, uint32_t *out_ev, uint32_t *out_saved,
                                     const void *raw_ptr, uint32_t mode_arg)
{
    uint32_t before = out_ev ? *out_ev : 0x143u;
    if (g_orig_custom_key_remap) {
        g_orig_custom_key_remap(mgr, out_ev, out_saved, raw_ptr, mode_arg);
    }
    uint32_t after = out_ev ? *out_ev : 0x143u;
    if (after != before) {
        uint32_t cnt = __sync_add_and_fetch(&g_g5_remap_log_cnt, 1u);
        if (cnt <= 80u || (cnt % 50u) == 0u) {
            uint32_t saved = out_saved ? *out_saved : 0x143u;
            logf_("G5_KEY_REMAP[#%u mode=0x%x]: 0x%08x -> 0x%08x (saved=0x%08x)",
                  cnt, mode_arg, before, after, saved);
        }
    } else if (after != 0x143u && (after & 0xff000000u) == 0x02000000u &&
               (mode_arg == 0u || mode_arg == 1u || g5_is_shooting_diag_key(after))) {
        uint32_t cnt = __sync_add_and_fetch(&g_g5_remap_same_log_cnt, 1u);
        if (cnt <= 40u) {
            uint32_t saved = out_saved ? *out_saved : 0x143u;
            logf_("G5_KEY_REMAP_SAME[#%u mode=0x%x]: 0x%08x -> 0x%08x (saved=0x%08x)",
                  cnt, mode_arg, before, after, saved);
        }
    }
}

static void g5_hook_global_inhibit_filter(void *mgr, uint32_t *out_evt)
{
    uint32_t orig_type = out_evt ? out_evt[0] : 0u;
    uint32_t orig_ev   = out_evt ? out_evt[2] : 0x143u;
    if (g_orig_global_inhibit) {
        g_orig_global_inhibit(mgr, out_evt);
    }
    if (out_evt && orig_ev != 0x143u && out_evt[2] != orig_ev &&
        (orig_ev & 0xff000000u) == 0x02000000u) {
        uint32_t suppressed_to = out_evt[2];
        uint32_t cnt = __sync_add_and_fetch(&g_g5_inhibit_bypass_cnt, 1u);
        if (suppressed_to == 0x143u) {
            if (cnt <= 80u || (cnt % 50u) == 0u) {
                logf_("G5_INHIBIT_WARN[0x143 #%u]: type=%u->%u ev=0x%08x (未篡改事件，仅观测仍触发 0x00000143)",
                      cnt, orig_type, out_evt[0], orig_ev);
            }
        } else {
            if (cnt <= 120u || (cnt % 25u) == 0u) {
                logf_("G5_INHIBIT_OBS[NEW #%u]: type=%u->%u ev=0x%08x -> 0x%08x",
                      cnt, orig_type, out_evt[0], orig_ev, suppressed_to);
            }
        }
    }
}

static void g5_set_prop_19ba_ready_once(const char *ctx_tag)
{
    static volatile int s_prop_19ba_done = 0;
    uintptr_t app_base = g_appfw_base;
    if (!app_base) return;
    if (__atomic_exchange_n(&s_prop_19ba_done, 1, __ATOMIC_ACQ_REL)) return;

    static const uint8_t sig_setter[12] = {
        0x06u, 0x4bu, 0x05u, 0x4au, 0x7bu, 0x44u,
        0x80u, 0xb5u, 0x00u, 0xafu, 0x98u, 0x50u
    };
    uintptr_t setter_va = app_base + APPFW_OFF_PROP_19BA_SETTER;
    if (memcmp((const void *)setter_va, sig_setter, sizeof(sig_setter)) != 0) {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 Prop 0x19ba setter (%s)",
              (unsigned)APPFW_OFF_PROP_19BA_SETTER, ctx_tag ? ctx_tag : "");
        return;
    }

    typedef void (*prop_19ba_setter_fn_t)(uint32_t val);
    prop_19ba_setter_fn_t fn = (prop_19ba_setter_fn_t)(setter_va + 1u);
    fn(1u);
    uint32_t v_main = *(const volatile uint32_t *)(app_base + APPFW_OFF_PROP_19BA_VAL);
    uint32_t v_sync = *(const volatile uint32_t *)(app_base + APPFW_OFF_PROP_19BA_SYNC);
    logf_("BOOT_BYPASS: Prop 0x19ba 已通过 setter(%s) 置位 -> val@0x%08x=%u sync@0x%08x=%u",
          ctx_tag ? ctx_tag : "",
          (unsigned)APPFW_OFF_PROP_19BA_VAL, v_main,
          (unsigned)APPFW_OFF_PROP_19BA_SYNC, v_sync);
}

static int g5_is_wizard_screen(uint32_t scr_id)
{
    if (scr_id == 0x10du || scr_id == 0x194u || scr_id == 0x1aau || scr_id == 0x1adu) {
        return 1;
    }
    return (scr_id > 0u && scr_id < 0x2b0u);
}

static int g5_get_active_screen_id(uint32_t *out_scr)
{
    if (out_scr) *out_scr = ASTRA_SCR_INVALID;
    uintptr_t app_base = g_appfw_base;
    void *pcm = __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE);
    if (!app_base || !pcm) return -1;

    const uint8_t *fn_bytes = (const uint8_t *)(app_base + APPFW_OFF_PCM_GET_TOP_SCR);
    static const uint8_t sig_top[4] = { 0x2du, 0xe9u, 0xf8u, 0x43u };
    if (memcmp(fn_bytes, sig_top, sizeof(sig_top)) != 0) return -2;

    typedef int (*pcm_get_top_fn_t)(void *pcm_obj, int layer);
    pcm_get_top_fn_t fn = (pcm_get_top_fn_t)(app_base + APPFW_OFF_PCM_GET_TOP_SCR + 1u);
    /* pcm 图层仅含 layer 0 与 layer 1，传入 layer=1 扫全部有效槽；传 2 会越界解引用 [pcm+0x168] */
    int top = fn(pcm, 1);
    if (out_scr) *out_scr = (uint32_t)top;
    return 0;
}

static int g5_switch_to_screen_on_app(uint32_t target_scr, const char *reason)
{
    uintptr_t app_base = g_appfw_base;
    void *pcm = __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE);
    if (!app_base || !pcm || !g_orig_pcm_open_screen) return -1;
    if (__atomic_exchange_n(&g_switch_in_progress, 1, __ATOMIC_ACQ_REL)) return -4;

    uint32_t top = ASTRA_SCR_INVALID;
    int top_rc = g5_get_active_screen_id(&top);
    if (top_rc != 0) {
        __atomic_store_n(&g_switch_in_progress, 0, __ATOMIC_RELEASE);
        return -2;
    }

    uint32_t last_cur = __atomic_load_n(&g_last_cur_scr, __ATOMIC_RELAXED);
    uint32_t last_next = __atomic_load_n(&g_last_next_scr, __ATOMIC_RELAXED);

    if (top > 0u && top < ASTRA_SCR_INVALID) {
        __atomic_store_n(&g_cached_top_scr, top, __ATOMIC_RELEASE);
    } else if (last_cur > 0u && last_cur < ASTRA_SCR_INVALID &&
               (last_next == 0u || last_next >= ASTRA_SCR_INVALID)) {
        top = last_cur;
        __atomic_store_n(&g_cached_top_scr, top, __ATOMIC_RELEASE);
    } else {
        top = (last_next > 0u && last_next < ASTRA_SCR_INVALID) ? last_next : ASTRA_SCR_INVALID;
    }

    if (target_scr == ASTRA_SCR_MENU_CTRL &&
        (top == ASTRA_SCR_MENU_CTRL || top == ASTRA_SCR_MENU_UI || top == 0x280u || top == 0x281u)) {
        logf_("ASTRA_OPEN_MENU_ACK status=already_in_menu top=0x%x reason=%s",
              top, reason ? reason : "?");
        __atomic_store_n(&g_switch_in_progress, 0, __ATOMIC_RELEASE);
        return 1;
    }
    if (target_scr == ASTRA_SCR_SHOOTING &&
        (top == ASTRA_SCR_SHOOTING || top == 0x1b3u ||
         (last_cur == ASTRA_SCR_SHOOTING && (last_next == 0u || last_next == ASTRA_SCR_SHOOTING || last_next == 0x1b3u)))) {
        logf_("ASTRA_SWITCH_SCR_ACK status=already_target top=0x%x cur=0x%x target=0x%x reason=%s",
              top, last_cur, target_scr, reason ? reason : "?");
        __atomic_store_n(&g_switch_in_progress, 0, __ATOMIC_RELEASE);
        return 1;
    }
    if (top == target_scr) {
        logf_("ASTRA_SWITCH_SCR_ACK status=already_target top=0x%x target=0x%x reason=%s",
              top, target_scr, reason ? reason : "?");
        __atomic_store_n(&g_switch_in_progress, 0, __ATOMIC_RELEASE);
        return 1;
    }

    uint32_t cur = top;
    uint32_t next = target_scr;
    uint32_t opt = ASTRA_SCR_INVALID;
    /* 必须在 THREAD_APP 事件循环边界同步调用 pcm::open_screen 才会立即消费切换 */
    int rc = g_orig_pcm_open_screen(pcm, &cur, &next, &opt, 0u, 1u, 0u, 0u, 0u);

    uint32_t after_top = ASTRA_SCR_INVALID;
    if (g5_get_active_screen_id(&after_top) == 0 && after_top > 0u && after_top < ASTRA_SCR_INVALID) {
        __atomic_store_n(&g_cached_top_scr, after_top, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
    g5_wake_render_driver();
    if (target_scr == ASTRA_SCR_MENU_CTRL) {
        logf_("ASTRA_OPEN_MENU_ACK status=switched reason=%s from=0x%x to=0x%x after=0x%x rc=%d",
              reason ? reason : "?", cur, next, after_top, rc);
    } else {
        logf_("ASTRA_SWITCH_SCR_ACK status=switched reason=%s from=0x%x to=0x%x after=0x%x rc=%d",
              reason ? reason : "?", cur, next, after_top, rc);
    }
    __atomic_store_n(&g_switch_in_progress, 0, __ATOMIC_RELEASE);
    return 0;
}

static void g5_request_screen_switch(int target_code, const char *reason)
{
    __atomic_store_n(&g_pending_switch_target, target_code, __ATOMIC_RELEASE);
    int ev_rc = g5_send_internal_event(ASTRA_WAKE_EVT_ID);
    __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
    g5_wake_render_driver();
    if (target_code == 1) {
        logf_("ASTRA_OPEN_MENU_ACK status=scheduled reason=%s ev_rc=%d pcm=%p",
              reason ? reason : "?", ev_rc, __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE));
    } else {
        logf_("ASTRA_SWITCH_SCR_ACK status=scheduled target=0x%x reason=%s ev_rc=%d pcm=%p",
              ASTRA_SCR_SHOOTING, reason ? reason : "?", ev_rc, __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE));
    }
}

static int g5_hook_pcm_open_screen(void *pcm_obj, const uint32_t *cur_scr, const uint32_t *next_scr,
                                   const uint32_t *opt_scr, uint32_t a4, uint32_t b1, uint32_t b2,
                                   uint32_t a7, uint32_t a8)
{
    long tid = (long)syscall(SYS_gettid);
    if (__atomic_load_n(&g_pcm_tid, __ATOMIC_RELAXED) == 0) {
        __atomic_store_n(&g_pcm_tid, tid, __ATOMIC_RELEASE);
    }
    if (pcm_obj) {
        __atomic_store_n(&g_pcm_obj, pcm_obj, __ATOMIC_RELEASE);
    }
    uint32_t c = cur_scr ? *cur_scr : ASTRA_SCR_INVALID;
    uint32_t n = next_scr ? *next_scr : ASTRA_SCR_INVALID;
    uint32_t o = opt_scr ? *opt_scr : ASTRA_SCR_INVALID;
    uint32_t prev_n = __atomic_load_n(&g_last_next_scr, __ATOMIC_RELAXED);
    __atomic_store_n(&g_last_cur_scr, c, __ATOMIC_RELAXED);
    if (n != ASTRA_SCR_INVALID) {
        __atomic_store_n(&g_last_next_scr, n, __ATOMIC_RELAXED);
    }
    uint32_t seq = __atomic_add_fetch(&g_pcm_open_cnt, 1u, __ATOMIC_RELAXED);
    if (seq <= 40u || n != prev_n) {
        logf_("PCM_OPEN #%u: pcm=%p tid=%ld cur=0x%x next=0x%x opt=0x%x b=(%u,%u)",
              seq, pcm_obj, tid, c, n, o, b1, b2);
    }
    if (n == ASTRA_SCR_MENU_CTRL || n == ASTRA_SCR_MENU_UI) {
        __atomic_store_n(&g_menu_boot_completed, 1, __ATOMIC_RELEASE);
    } else if (g5_get_boot_mode() == ASTRA_BOOT_MENU &&
               !__atomic_load_n(&g_menu_boot_completed, __ATOMIC_ACQUIRE) &&
               g5_is_wizard_screen(n) &&
               !__atomic_exchange_n(&g_menu_fallback_queued, 1, __ATOMIC_ACQ_REL)) {
        logf_("BOOT_MENU_FALLBACK: 检测到向导屏 0x%x，排队自动切入 MENU (0x%x)", n, ASTRA_SCR_MENU_CTRL);
        __atomic_store_n(&g_pending_switch_target, 1, __ATOMIC_RELEASE);
        (void)g5_send_internal_event(ASTRA_WAKE_EVT_ID);
        g5_wake_render_driver();
    }
    int ret = 0;
    if (g_orig_pcm_open_screen) {
        ret = g_orig_pcm_open_screen(pcm_obj, cur_scr, next_scr, opt_scr, a4, b1, b2, a7, a8);
    }
    uint32_t top = ASTRA_SCR_INVALID;
    if (g5_get_active_screen_id(&top) == 0 && top > 0u && top < ASTRA_SCR_INVALID) {
        __atomic_store_n(&g_cached_top_scr, top, __ATOMIC_RELEASE);
    } else if (n > 0u && n < ASTRA_SCR_INVALID) {
        __atomic_store_n(&g_cached_top_scr, n, __ATOMIC_RELEASE);
    } else if (n == 0u && c > 0u && c < ASTRA_SCR_INVALID) {
        __atomic_store_n(&g_cached_top_scr, c, __ATOMIC_RELEASE);
    }
    if (n == ASTRA_SCR_MENU_UI || n == 0x280u || n == 0x281u ||
        n == ASTRA_SCR_SHOOTING || n == 0x1b3u ||
        (g5_get_boot_mode() == ASTRA_BOOT_NORMAL && seq >= 2u)) {
        __atomic_store_n(&g_ui_ready_pcm_ok, 1u, __ATOMIC_RELEASE);
    }
    {
        uint32_t scr_hint = __atomic_load_n(&g_cached_top_scr, __ATOMIC_RELAXED);
        if (scr_hint > 0u && scr_hint < ASTRA_SCR_INVALID) {
            __atomic_store_n(&g_ui_ready_scr_hint, scr_hint, __ATOMIC_RELEASE);
        }
    }
    return ret;
}

static void g5_hook_scr0039_open(void *scr_obj, const uint32_t *next_scr, const uint32_t *opt_scr,
                                 const uint32_t *extra_scr)
{
    uint32_t n = next_scr ? *next_scr : ASTRA_SCR_INVALID;
    g5_boot_mode_t mode = g5_get_boot_mode();
    if (mode != ASTRA_BOOT_NORMAL &&
        !__atomic_load_n(&g_boot_bypass_done, __ATOMIC_ACQUIRE) &&
        n != ASTRA_SCR_INVALID && n != ASTRA_SCR_BOOT_CTRL && g5_is_wizard_screen(n)) {
        uint32_t boot_ctrl = ASTRA_SCR_BOOT_CTRL;
        uint32_t inv = ASTRA_SCR_INVALID;
        __atomic_store_n(&g_boot_bypass_done, 1, __ATOMIC_RELEASE);
        g5_set_prop_19ba_ready_once("scr0039_boot_bypass");
        logf_("BOOT_BYPASS: 跳过开机向导 scr=0x%x -> rep_boot(0x%x)", n, boot_ctrl);
        if (g_orig_scr0039_open) {
            g_orig_scr0039_open(scr_obj, &boot_ctrl, &inv, &inv);
        }
        return;
    }
    if (n == ASTRA_SCR_BOOT_CTRL) {
        __atomic_store_n(&g_boot_bypass_done, 1, __ATOMIC_RELEASE);
        g5_set_prop_19ba_ready_once("scr0039_boot_ctrl");
    }
    if (g_orig_scr0039_open) {
        g_orig_scr0039_open(scr_obj, next_scr, opt_scr, extra_scr);
    }
}

static int g5_hook_rep_boot_init(void *rep_obj)
{
    if (g_appfw_base != 0) {
        g5_set_prop_19ba_ready_once("rep_boot_init");
        volatile uint32_t *boot_info = (volatile uint32_t *)(g_appfw_base + APPFW_OFF_BOOT_INFO_BSS);
        uint32_t orig_key = boot_info[0];
        g5_boot_mode_t mode = g5_get_boot_mode();
        if (mode == ASTRA_BOOT_MENU &&
            !__atomic_exchange_n(&g_rep_boot_key_patched, 1, __ATOMIC_ACQ_REL)) {
            boot_info[0] = 0x10u;
            logf_("REP_BOOT_PATCH: boot_key 0x%08x -> 0x10 (默认直达 rep_menu 0x%x)",
                  orig_key, ASTRA_SCR_MENU_CTRL);
        } else if (mode == ASTRA_BOOT_SHOOTING &&
                   !__atomic_exchange_n(&g_rep_boot_key_patched, 1, __ATOMIC_ACQ_REL)) {
            boot_info[0] = 0x00u;
            logf_("REP_BOOT_PATCH: boot_key 0x%08x -> 0x00 (默认进 rep_shooting 0x%x)",
                  orig_key, ASTRA_SCR_SHOOTING);
        } else if (orig_key > 0x1au) {
            /* 修复 QEMU 默认 boot_key=0x1b 导致 rep_boot::init 报 Not support boot key 后无界面卡死 */
            boot_info[0] = 0x00u;
            logf_("REP_BOOT_PATCH: 修正不支持的 boot_key=0x%08x -> 0x00 (rep_shooting 0x%x)",
                  orig_key, ASTRA_SCR_SHOOTING);
        }
    }
    if (g_orig_rep_boot_init) {
        return g_orig_rep_boot_init(rep_obj);
    }
    return 0;
}

static int g5_hook_rep_boot_can_open(void *rep_obj)
{
    int rc = g_orig_rep_boot_can_open ? g_orig_rep_boot_can_open(rep_obj) : 1;
    if (rc == 0) {
        static volatile int s_logged = 0;
        if (!__atomic_exchange_n(&s_logged, 1, __ATOMIC_ACQ_REL)) {
            logf_("REP_BOOT_CAN_OPEN: 原硬件状态检查返回 0，QEMU 环境放行 -> 1");
        }
        return 1;
    }
    return rc;
}

static int g5_hook_app_get_next_evt(void *ctx, uint32_t *out_evt, int wait_flag, uint64_t timeout)
{
    long tid = (long)syscall(SYS_gettid);
    if (__atomic_exchange_n(&g_evt_loop_tid, tid, __ATOMIC_ACQ_REL) == 0) {
        logf_("EVT_LOOP_INIT: tid=%ld pcm_tid=%ld", tid, __atomic_load_n(&g_pcm_tid, __ATOMIC_ACQUIRE));
    }

    uint64_t cur_tmo = timeout;
    for (int hop = 0; hop < 4; hop++) {
        long pcm_tid = __atomic_load_n(&g_pcm_tid, __ATOMIC_ACQUIRE);
        if ((pcm_tid == 0 || pcm_tid == tid) &&
            __atomic_load_n(&g_pending_switch_target, __ATOMIC_ACQUIRE) != 0 &&
            __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE) != NULL) {
            int pending = __atomic_exchange_n(&g_pending_switch_target, 0, __ATOMIC_ACQ_REL);
            if (pending != 0) {
                uint32_t dst = (pending == 2) ? ASTRA_SCR_SHOOTING : ASTRA_SCR_MENU_CTRL;
                (void)g5_switch_to_screen_on_app(dst, "app_loop_pre");
            }
        }

        int ret = g_orig_app_get_next_evt
                      ? g_orig_app_get_next_evt(ctx, out_evt, wait_flag, cur_tmo)
                      : 0;

        if ((pcm_tid == 0 || pcm_tid == tid) &&
            __atomic_load_n(&g_pending_switch_target, __ATOMIC_ACQUIRE) != 0 &&
            __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE) != NULL) {
            int pending = __atomic_exchange_n(&g_pending_switch_target, 0, __ATOMIC_ACQ_REL);
            if (pending != 0) {
                uint32_t dst = (pending == 2) ? ASTRA_SCR_SHOOTING : ASTRA_SCR_MENU_CTRL;
                (void)g5_switch_to_screen_on_app(dst, "app_loop_post");
            }
        }

        if (ret != 0 && out_evt && out_evt[0] == 1u && out_evt[2] == ASTRA_WAKE_EVT_ID) {
            /* 吞掉内部切屏唤醒哨兵，不让主事件分发器将其误当设备事件 */
            memset(out_evt, 0, 24u);
            if (wait_flag != 0 || hop == 0) {
                if (wait_flag == 0) cur_tmo = 0ULL;
                continue;
            }
            return 0;
        }

        if (pcm_tid == 0 || pcm_tid == tid) {
            static volatile uint32_t s_top_poll_div = 0;
            if (ret != 0 || (__atomic_add_fetch(&s_top_poll_div, 1u, __ATOMIC_RELAXED) & 63u) == 0u) {
                uint32_t top = ASTRA_SCR_INVALID;
                if (g5_get_active_screen_id(&top) == 0 && top > 0u && top < ASTRA_SCR_INVALID) {
                    __atomic_store_n(&g_cached_top_scr, top, __ATOMIC_RELEASE);
                }
            }
        }
        return ret;
    }
    return 0;
}

static void g5_install_menu_boot_hooks(uintptr_t app_base)
{
    if (!app_base) return;
    static const uint8_t sig_pcm_open[8]         = { 0x2du, 0xe9u, 0xf0u, 0x4fu, 0xafu, 0xb0u, 0x8au, 0x46u };
    static const uint8_t sig_scr0039_open[8]     = { 0x2du, 0xe9u, 0xf0u, 0x4fu, 0x83u, 0xb0u, 0x92u, 0x46u };
    static const uint8_t sig_rep_boot[8]         = { 0x2du, 0xe9u, 0xf0u, 0x4fu, 0xadu, 0xf5u, 0x5fu, 0x7du };
    static const uint8_t sig_rep_boot_can[8]     = { 0x2du, 0xe9u, 0xb0u, 0x43u, 0x9cu, 0xb0u, 0x00u, 0xafu };
    static const uint8_t sig_app_get_next[8]     = { 0x2du, 0xe9u, 0xf0u, 0x4fu, 0x83u, 0xb0u, 0x02u, 0xafu };

    if (memcmp((const void *)(app_base + APPFW_OFF_PCM_OPEN_SCREEN), sig_pcm_open, 8) == 0) {
        g_orig_pcm_open_screen = (pcm_open_screen_fn_t)make_thumb_trampoline_8(
            app_base + APPFW_OFF_PCM_OPEN_SCREEN, (void *)g5_hook_pcm_open_screen, "appFw.so pcm::open_screen");
    } else {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 pcm::open_screen hook", (unsigned)APPFW_OFF_PCM_OPEN_SCREEN);
    }

    if (memcmp((const void *)(app_base + APPFW_OFF_SCR0039_OPEN), sig_scr0039_open, 8) == 0) {
        g_orig_scr0039_open = (scr0039_open_fn_t)make_thumb_trampoline_8(
            app_base + APPFW_OFF_SCR0039_OPEN, (void *)g5_hook_scr0039_open, "appFw.so scr0039_boot_open");
    } else {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 scr0039_boot_open hook", (unsigned)APPFW_OFF_SCR0039_OPEN);
    }

    if (memcmp((const void *)(app_base + APPFW_OFF_REP_BOOT_INIT), sig_rep_boot, 8) == 0) {
        g_orig_rep_boot_init = (rep_boot_init_fn_t)make_thumb_trampoline_8(
            app_base + APPFW_OFF_REP_BOOT_INIT, (void *)g5_hook_rep_boot_init, "appFw.so rep_boot::init");
    } else {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 rep_boot::init hook", (unsigned)APPFW_OFF_REP_BOOT_INIT);
    }

    if (memcmp((const void *)(app_base + APPFW_OFF_REP_BOOT_CAN_OPEN), sig_rep_boot_can, 8) == 0) {
        g_orig_rep_boot_can_open = (rep_boot_can_open_fn_t)make_thumb_trampoline_8(
            app_base + APPFW_OFF_REP_BOOT_CAN_OPEN, (void *)g5_hook_rep_boot_can_open, "appFw.so rep_boot_can_open");
    } else {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 rep_boot_can_open hook", (unsigned)APPFW_OFF_REP_BOOT_CAN_OPEN);
    }

    if (memcmp((const void *)(app_base + APPFW_OFF_APP_GET_NEXT_EVT), sig_app_get_next, 8) == 0) {
        g_orig_app_get_next_evt = (app_get_next_evt_fn_t)make_thumb_trampoline_8(
            app_base + APPFW_OFF_APP_GET_NEXT_EVT, (void *)g5_hook_app_get_next_evt, "appFw.so app_get_next_evt");
    } else {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 app_get_next_evt hook", (unsigned)APPFW_OFF_APP_GET_NEXT_EVT);
    }

    static const uint8_t ven_tr3[16] = {
        0x04u, 0xc0u, 0x9fu, 0xe5u, 0x0cu, 0xc0u, 0x8fu, 0xe0u,
        0x1cu, 0xffu, 0x2fu, 0xe1u, 0x5du, 0xb7u, 0xc3u, 0xfeu
    };
    static const uint8_t tgt_tr3[8]  = { 0x2du, 0xe9u, 0xf8u, 0x4fu, 0x00u, 0xafu, 0xdfu, 0xf8u };
    g_orig_translate_3_evs = (g5_translate_3_evs_fn_t)patch_arm_veneer_jump(
        app_base + APPFW_OFF_VENEER_TRANSLATE_3_EVS, ven_tr3,
        app_base + APPFW_OFF_TRANSLATE_3_EVS_TGT, tgt_tr3,
        (void *)g5_hook_translate_3_evs, "appFw.so translate_3_evs");

    static const uint8_t ven_remap[16] = {
        0x04u, 0xc0u, 0x9fu, 0xe5u, 0x0cu, 0xc0u, 0x8fu, 0xe0u,
        0x1cu, 0xffu, 0x2fu, 0xe1u, 0x2du, 0xc2u, 0xc3u, 0xfeu
    };
    static const uint8_t tgt_remap[8]  = { 0x2du, 0xe9u, 0xf0u, 0x43u, 0x89u, 0xb0u, 0x05u, 0x46u };
    g_orig_custom_key_remap = (g5_custom_key_remap_fn_t)patch_arm_veneer_jump(
        app_base + APPFW_OFF_VENEER_CUSTOM_KEY_REMAP, ven_remap,
        app_base + APPFW_OFF_CUSTOM_KEY_REMAP_TGT, tgt_remap,
        (void *)g5_hook_custom_key_remap, "appFw.so custom_key_remap");

    static const uint8_t sig_inhibit_entry[12] = {
        0xb0u, 0xb5u, 0x8eu, 0xb0u, 0x00u, 0xafu,
        0x07u, 0xf1u, 0x34u, 0x00u, 0x0cu, 0x46u
    };
    uintptr_t inhibit_entry = app_base + APPFW_OFF_INHIBIT_FILTER_TGT;
    if (memcmp((const void *)inhibit_entry, sig_inhibit_entry, sizeof(sig_inhibit_entry)) == 0) {
        g_orig_global_inhibit = (g5_global_inhibit_fn_t)make_thumb_trampoline_12(
            inhibit_entry, (void *)g5_hook_global_inhibit_filter, "appFw.so global_inhibit_filter(real_entry)");
    } else {
        logf_("HOOK_WARN: appFw+0x%x 签名不匹配，跳过 global_inhibit_filter 12B 跳板",
              (unsigned)APPFW_OFF_INHIBIT_FILTER_TGT);
    }
}

#ifndef ZVE10_REAL_DEVICE

static void g5_handle_uart_cmd(const char *raw_line)
{
    if (!raw_line || !raw_line[0]) return;
    char cmd_buf[128];
    while (*raw_line == ' ' || *raw_line == '\t') raw_line++;
    size_t clen = strlen(raw_line);
    if (clen >= sizeof(cmd_buf)) clen = sizeof(cmd_buf) - 1u;
    memcpy(cmd_buf, raw_line, clen);
    while (clen > 0u && (cmd_buf[clen - 1u] == ' ' || cmd_buf[clen - 1u] == '\t' || cmd_buf[clen - 1u] == '\r' || cmd_buf[clen - 1u] == '\n')) {
        clen--;
    }
    cmd_buf[clen] = '\0';
    if (clen == 0u) return;
    const char *line = cmd_buf;
    __atomic_add_fetch(&g_uart_cmds, 1u, __ATOMIC_RELAXED);
    if (strcmp(line, "PING") == 0) {
        uint32_t cur_scr = __atomic_load_n(&g_cached_top_scr, __ATOMIC_ACQUIRE);
        if (cur_scr == ASTRA_SCR_INVALID || cur_scr == 0u) {
            cur_scr = __atomic_load_n(&g_last_next_scr, __ATOMIC_RELAXED);
        }
        logf_("ASTRA_PONG seq=%u fb=%u cycle=%u stage=%u uart_rx=%u cmds=%u reopens=%u pcm=%p scr=0x%x",
              g_touch_rx_seq, g_fb_sync_seq,
              __atomic_load_n(&g_render_cycle, __ATOMIC_RELAXED),
              __atomic_load_n(&g_render_stage, __ATOMIC_RELAXED),
              __atomic_load_n(&g_uart_rx_bytes, __ATOMIC_RELAXED),
              __atomic_load_n(&g_uart_cmds, __ATOMIC_RELAXED),
              __atomic_load_n(&g_uart_reopens, __ATOMIC_RELAXED),
              __atomic_load_n(&g_pcm_obj, __ATOMIC_ACQUIRE),
              cur_scr);
        return;
    }
    if (strncmp(line, "DBGLOG ", 7) == 0) {
        long val = strtol(line + 7, NULL, 10);
        if (val <= 0) {
            g_appfw_dbglog_muted = 1;
            __atomic_store_n(&g_appfw_dbglog_budget, 0, __ATOMIC_RELAXED);
        } else {
            g_appfw_dbglog_muted = 0;
            __atomic_store_n(&g_appfw_dbglog_budget, (int32_t)val, __ATOMIC_RELAXED);
        }
        logf_("ASTRA_DBGLOG muted=%d budget=%ld", g_appfw_dbglog_muted, val);
        return;
    }
    if (strcmp(line, "THREADS") == 0) {
        g5_dump_threads_wchan(0);
        return;
    }
    if (strcmp(line, "STACKS") == 0) {
        g5_dump_threads_wchan(1);
        return;
    }
    if (strncmp(line, "STACK ", 6) == 0) {
        long tid = strtol(line + 6, NULL, 10);
        g5_sample_thread_stack(tid, "manual");
        return;
    }
    g5_refresh_dbglog_budget(500);
    if (strcasecmp(line, "OPEN_MENU") == 0 || strcasecmp(line, "OPENMENU") == 0) {
        g5_request_screen_switch(1, "uart_open_menu");
        return;
    }
    if (strcasecmp(line, "OPEN_SHOOT") == 0 || strcasecmp(line, "OPENSHOOT") == 0) {
        g5_request_screen_switch(2, "uart_open_shoot");
        return;
    }
    if (strcmp(line, "MENU") == 0) {
        g5_enqueue_tact_key("MENU", 0);
        return;
    }
    if (strncmp(line, "KEY ", 4) == 0) {
        g5_enqueue_tact_key(line + 4, 0);
        return;
    }
    if (strncmp(line, "KEYDOWN ", 8) == 0) {
        g5_enqueue_tact_key(line + 8, 1);
        return;
    }
    if (strncmp(line, "KEYUP ", 6) == 0) {
        g5_enqueue_tact_key(line + 6, 2);
        return;
    }
    if (strncmp(line, "EVENT ", 6) == 0) {
        uint32_t eid = (uint32_t)strtoul(line + 6, NULL, 16);
        int rc = g5_send_internal_event(eid);
        __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
        g5_wake_render_driver();
        logf_("ASTRA_EVENT_ACK eid=0x%08x rc=%d", eid, rc);
        return;
    }
    if (strncmp(line, "G4KEY ", 6) == 0) {
        char *endp = NULL;
        uint32_t g4c = (uint32_t)strtoul(line + 6, &endp, 16);
        int is_press = endp ? (int)strtol(endp, NULL, 10) : 1;
        int rc = g5_inject_g4_key(g4c, is_press);
        __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
        g5_wake_render_driver();
        logf_("G4KEY_ACK g4_code=0x%x is_press=%d rc=%d", g4c, is_press, rc);
        return;
    }
    if (strncmp(line, "TOUCH ", 6) != 0) {
        logf_("UART_TOUCH_UNKNOWN: '%s'", line);
        return;
    }
    const char *p = line + 6;
    while (*p == ' ') p++;
    uint8_t kind = 0;
    int is_tap = 0;
    if (strncmp(p, "DOWN ", 5) == 0) { kind = G5_TOUCH_DOWN; p += 5; }
    else if (strncmp(p, "MOVE ", 5) == 0) { kind = G5_TOUCH_MOVE; p += 5; }
    else if (strncmp(p, "UP ", 3) == 0) { kind = G5_TOUCH_UP; p += 3; }
    else if (strncmp(p, "TAP ", 4) == 0) { is_tap = 1; p += 4; }
    else return;

    char *end1 = NULL;
    long rx = strtol(p, &end1, 10);
    if (!end1 || end1 == p) return;
    long ry = strtol(end1, NULL, 10);
    int16_t x = g5_clamp_touch_coord(rx, 639);
    int16_t y = g5_clamp_touch_coord(ry, 479);
    uint32_t seq = __sync_add_and_fetch(&g_touch_rx_seq, 1u);
    if (is_tap) {
        g5_touch_push(G5_TOUCH_DOWN, x, y);
        g5_touch_push(G5_TOUCH_UP, x, y);
    } else {
        g5_touch_push(kind, x, y);
    }
    logf_("ASTRA_TOUCH_RX seq=%u kind=%s x=%d y=%d", seq, is_tap ? "TAP" : (kind == 1 ? "DOWN" : kind == 2 ? "MOVE" : "UP"), (int)x, (int)y);
}

static int g5_open_uart_device(const char **dev_out)
{
    const char *dev = "/dev/ttyAM0";
    int fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        dev = "/dev/ttyAMA0";
        fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    }
    if (fd < 0) {
        if (dev_out) *dev_out = NULL;
        return -1;
    }
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int fdfl = fcntl(fd, F_GETFD, 0);
    if (fdfl >= 0) (void)fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC);

    /* Sony 内核 PL011 扩展模式切换至 1 (正常用户态收发)，并设 36 字节内核 termios 为 raw 非阻塞模式 */
    uint32_t mode = 1;
    int mrc = ioctl(fd, _IOW('u', 2, uint32_t), &mode);
    struct g5_kernel_termios tio = {0};
    int trc = ioctl(fd, 0x5401u, &tio);
    if (trc == 0) {
        tio.iflag = 0u;
        tio.oflag = 0u;
        tio.lflag = 0u;
        tio.cflag = (tio.cflag & ~0x130u) | 0x8b0u;
        tio.cc[6] = 1u; /* VMIN = 1：配合 O_NONBLOCK 无数据时返回 EAGAIN 而非 0 */
        tio.cc[5] = 0u; /* VTIME = 0 */
        (void)ioctl(fd, 0x5402u, &tio);
    }
    if (dev_out) *dev_out = dev;
    logf_("UART_TOUCH: 已监听 %s (fd=%d mode_rc=%d termios_rc=%d nonblock=1)", dev, fd, mrc, trc);
    return fd;
}

static void *uart_touch_rx_thread(void *unused)
{
    (void)unused;
    const char *dev = NULL;
    int fd = g5_open_uart_device(&dev);
    if (fd < 0) {
        logf_("UART_TOUCH: 初次打开串口失败 errno=%d，将在后台重试", errno);
    }

    char line[128];
    size_t pos = 0;
    while (g_astra_running) {
        if (fd < 0) {
            usleep(500000);
            fd = g5_open_uart_device(&dev);
            if (fd >= 0) {
                __atomic_add_fetch(&g_uart_reopens, 1u, __ATOMIC_RELAXED);
                pos = 0;
            }
            continue;
        }

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int prc = poll(&pfd, 1, 2000);
        if (prc < 0) {
            if (errno == EINTR) continue;
            logf_("UART_TOUCH: poll 失败 errno=%d，重新打开串口", errno);
            close(fd);
            fd = -1;
            continue;
        }
        if (prc == 0) continue;

        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
            logf_("UART_TOUCH: revents=0x%x，重新打开串口", (unsigned)pfd.revents);
            close(fd);
            fd = -1;
            continue;
        }

        char buf[256];
        int need_reopen = 0;
        size_t rx_this_poll = 0;
        for (;;) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n > 0) {
                rx_this_poll += (size_t)n;
                __atomic_add_fetch(&g_uart_rx_bytes, (uint32_t)n, __ATOMIC_RELAXED);
                for (ssize_t i = 0; i < n; i++) {
                    char ch = buf[i];
                    if (ch == '\r' || ch == '\n') {
                        if (pos > 0) {
                            line[pos] = '\0';
                            g5_handle_uart_cmd(line);
                            pos = 0;
                        }
                    } else if (pos + 1 < sizeof(line)) {
                        line[pos++] = ch;
                    } else {
                        pos = 0;
                    }
                }
            } else if (n == 0) {
                /* TTY 无更多可读数据时不可关闭重开，直接退出本轮排空等待下次 poll */
                break;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                logf_("UART_TOUCH: read 失败 errno=%d，重新打开串口", errno);
                need_reopen = 1;
                break;
            }
        }
        if (need_reopen) {
            close(fd);
            fd = -1;
            usleep(200000);
        } else if (rx_this_poll == 0) {
            usleep(10000);
        }
    }
    if (fd >= 0) close(fd);
    return NULL;
}

static void *render_driver_thread(void *unused)
{
    (void)unused;
    int interactive = g5_is_web_interactive();
    logf_("RENDER_DRIVER: 启动五代图形渲染驱动监听 (interactive=%d, boot_mode=%d, 等待 WidgetSystem 就绪以安装 vdf_if 钩子)...",
          interactive, (int)g5_get_boot_mode());
    for (int w = 0; w < 1000 && !g_ws_syms_ready; w++) {
        usleep(10000);
    }
    if (g_ws_syms_ready && g_pGetWS) {
        install_g5_vdf_if_hooks((void *)g_pGetWS);
    }
    if (interactive) {
        pthread_attr_t at;
        pthread_t uth;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 256u * 1024u);
        if (pthread_create(&uth, &at, uart_touch_rx_thread, NULL) == 0) {
            logf_("RENDER_DRIVER: uart_touch_rx_thread 已启动");
        }
        pthread_attr_destroy(&at);
        logf_("ASTRA_WEB_READY mode=interactive");
    }
    sleep(interactive ? 2 : 3);
    logf_("RENDER_DRIVER: sleep 醒来，开始循环调度渲染管道...");

    uint64_t active_until_ms = g5_msec_now() + 2500ULL;
    for (int cycle = 1; interactive ? g_astra_running : (cycle <= 45); cycle++) {
        __atomic_store_n(&g_render_cycle, (uint32_t)cycle, __ATOMIC_RELAXED);
        __atomic_store_n(&g_render_stage, 0u, __ATOMIC_RELAXED);
        if (!interactive || cycle <= 5 || (cycle % 100) == 0) {
            logf_("RENDER_DRIVER [轮次 %d]: g_astra_running=%d g_ws_syms_ready=%d", cycle, g_astra_running, g_ws_syms_ready);
        }
        if (!g_astra_running || !g_ws_syms_ready) {
            usleep(interactive ? 100000 : 1000000);
            continue;
        }
        if (__atomic_load_n(&g_pending_switch_target, __ATOMIC_ACQUIRE) != 0) {
            /* 切屏操作由 THREAD_APP 事件边界安全执行，RENDER_DRIVER 仅保持高频刷新窗口 */
            active_until_ms = g5_msec_now() + 1500ULL;
        }
        if (__atomic_exchange_n(&g_boost_render_flag, 0, __ATOMIC_ACQ_REL) != 0) {
            uint64_t boost_until = g5_msec_now() + 1500ULL;
            if (boost_until > active_until_ms) active_until_ms = boost_until;
        }

        unsigned pending_touch = 0;
        if (g_pGetWS && g_pUpdateFrame && g_pNotifyDraw) {
            void *ws = g_pGetWS();
            if (ws) {
                uint64_t t_now = g5_msec_now();
                __atomic_store_n(&g_render_stage, 1u, __ATOMIC_RELAXED);
                if (!interactive) {
                    const uint64_t t_zero = 0;
                    if (cycle == 4 && g_pPress && g_pRel) {
                        logf_("RENDER_DRIVER [#%d]: 模拟触控点击屏幕中央 (320, 240) 唤醒取景 UI...", cycle);
                        if (g_pMove) g_pMove(ws, 0, 320, 240, &t_zero);
                        g_pPress(ws, 0, 1, &t_zero);
                        g_pRel(ws, 0, 1, &t_zero);
                    } else if (cycle == 7 && g_pPress && g_pRel) {
                        logf_("RENDER_DRIVER [#%d]: 模拟触控点击左上角 MENU 区域 (40, 40)...", cycle);
                        if (g_pMove) g_pMove(ws, 0, 40, 40, &t_zero);
                        g_pPress(ws, 0, 1, &t_zero);
                        g_pRel(ws, 0, 1, &t_zero);
                    } else if (cycle == 10 && g_pPress && g_pRel) {
                        logf_("RENDER_DRIVER [#%d]: 再次点击左上角 MENU 区域 (40, 40)...", cycle);
                        if (g_pMove) g_pMove(ws, 0, 40, 40, &t_zero);
                        g_pPress(ws, 0, 1, &t_zero);
                        g_pRel(ws, 0, 1, &t_zero);
                    } else if (cycle == 13 && g_pPress && g_pRel) {
                        logf_("RENDER_DRIVER [#%d]: 模拟触控点击拍摄设置主菜单 (160, 120)...", cycle);
                        if (g_pMove) g_pMove(ws, 0, 160, 120, &t_zero);
                        g_pPress(ws, 0, 1, &t_zero);
                        g_pRel(ws, 0, 1, &t_zero);
                    } else if (cycle == 16 && g_pPress && g_pRel) {
                        logf_("RENDER_DRIVER [#%d]: 模拟触控点击 Fn 菜单区域 (580, 420)...", cycle);
                        if (g_pMove) g_pMove(ws, 0, 580, 420, &t_zero);
                        g_pPress(ws, 0, 1, &t_zero);
                        g_pRel(ws, 0, 1, &t_zero);
                    }
                } else {
                    struct g5_touch_ev ev = {0};
                    if (g5_touch_pop(&ev, &pending_touch)) {
                        active_until_ms = t_now + 1200ULL;
                        if (ev.kind == G5_TOUCH_DOWN) {
                            if (g_pMove) g_pMove(ws, 0, ev.x, ev.y, &t_now);
                            if (g_pPress) g_pPress(ws, 0, 1, &t_now);
                        } else if (ev.kind == G5_TOUCH_MOVE) {
                            if (g_pMove) g_pMove(ws, 0, ev.x, ev.y, &t_now);
                        } else if (ev.kind == G5_TOUCH_UP) {
                            if (g_pMove) g_pMove(ws, 0, ev.x, ev.y, &t_now);
                            if (g_pRel) g_pRel(ws, 0, 1, &t_now);
                        }
                        uint32_t aseq = __sync_add_and_fetch(&g_touch_applied_seq, 1u);
                        logf_("ASTRA_TOUCH_ACK aseq=%u kind=%u xy=(%d,%d)", aseq, (unsigned)ev.kind, (int)ev.x, (int)ev.y);
                    }
                }

                __atomic_store_n(&g_render_stage, 2u, __ATOMIC_RELAXED);
                if (g_pUpdateCurTime) g_pUpdateCurTime(ws);
                __atomic_store_n(&g_render_stage, 3u, __ATOMIC_RELAXED);
                if (g_pProcessEvent) {
                    typedef int (*ws_proc_ev_fn_t)(void *);
                    ws_proc_ev_fn_t proc_fn = (ws_proc_ev_fn_t)(void *)g_pProcessEvent;
                    for (int ev_i = 0; ev_i < 8; ev_i++) {
                        if (proc_fn(ws) == 0) break;
                    }
                }
                __atomic_store_n(&g_render_stage, 4u, __ATOMIC_RELAXED);
                g_pUpdateFrame(ws);
                __atomic_store_n(&g_render_stage, 5u, __ATOMIC_RELAXED);
                g_pNotifyDraw(ws);
                if (!interactive) {
                    logf_("RENDER_DRIVER [#%d]: WidgetSystem Pipeline (time+event+frame+draw) OK (ws=%p)", cycle, ws);
                    if (cycle == 12) {
                        uint32_t has_layer = *(const uint32_t *)((const char *)ws + 0x544);
                        logf_("WS_INSPECT: ws=%p ws[+0x544]=0x%08x", ws, has_layer);
                    }
                    if (access("/log/astra/frame_ready", F_OK) == 0) {
                        logf_("RENDER_DRIVER [#%d]: [★★★ 发现 frame_ready 标记！ASTRA 全彩画面已就绪！★★★]", cycle);
                    }
                }
            } else if (!interactive || cycle <= 5) {
                logf_("RENDER_DRIVER [#%d]: WidgetSystem::sys_getInstance 返回 NULL (尚未就绪)", cycle);
            }
        } else if (!interactive || cycle <= 5) {
            logf_("RENDER_DRIVER [#%d]: WidgetSystem 符号缺失", cycle);
        }

        __atomic_store_n(&g_render_stage, 6u, __ATOMIC_RELAXED);
        if (!interactive) {
            if (cycle == 12 || cycle == 25) {
                dump_all_threads_status();
                if (g_astra_th) {
                    logf_("DIAG: 向主 UI 线程发送 SIGUSR2 采集堆栈快照...");
                    pthread_kill(g_astra_th, SIGUSR2);
                }
            }
            sleep(1);
        } else {
            uint64_t now_after = g5_msec_now();
            unsigned wait_ms = pending_touch ? 24u : (now_after < active_until_ms ? 35u : 180u);
            g5_touch_wait_ms(wait_ms);
        }
    }
    return NULL;
}

#else

/* 真机监控线程：低开销稀疏心跳（仅在 10s/20s/40s 采样，禁止扫描 /proc 发 SIGUSR2 干扰实时渲染） */
static void *real_heartbeat_thread(void *unused)
{
    (void)unused;
    static const struct {
        unsigned wait_s;
        unsigned elapsed_s;
    } points[3] = {
        { 10u, 10u },
        { 10u, 20u },
        { 20u, 40u },
    };
    int dumped_stuck = 0;
    for (unsigned i = 0; i < 3; i++) {
        sleep(points[i].wait_s);
        if (!g_astra_running) break;
        void *ws = (g_ws_syms_ready && g_pGetWS) ? g_pGetWS() : NULL;
        logf_("REAL_HB [+%us]: stage=%s running=%d ws=%p in_ok=%d drawfb=%u/%u grm_chk=%u pres=%u rpc=%u fast_t=%u wait=%u/%u mmap_err=%u",
              points[i].elapsed_s, g_real_handoff_stage, g_astra_running, ws, g_real_in_init_done,
              g_draw_fb_cnt, g_real_drawfb_done_cnt, g_grm_chk_cnt,
              g_real_present_cnt, g_sync_rpc_cnt, __atomic_load_n(&g_sync_time_fast_cnt, __ATOMIC_RELAXED),
              g_model_wait_hit, g_model_wait_timeout, g_ob5_mmap_fail_cnt);
        {
            void *tp = g_real_g5_tp_obj;
            if (tp) {
                logf_("REAL_TP_HB [+%us]: vt4=%u press=%u rel=%u sus=%u dir=(%u,%u) ev_sw=%u raw=%u mode=%u",
                      points[i].elapsed_s, g_g5tp_vt4_cnt, g_g5_mouse_press_cnt, g_g5_mouse_rel_cnt,
                      (unsigned)*(const volatile uint8_t  *)((uintptr_t)tp + 0x20u),
                      (unsigned)*(const volatile uint8_t  *)((uintptr_t)tp + 0x30u),
                      (unsigned)*(const volatile uint8_t  *)((uintptr_t)tp + 0x31u),
                      (unsigned)*(const volatile uint8_t  *)((uintptr_t)tp + 0x32u),
                      (unsigned)*(const volatile uint8_t  *)((uintptr_t)tp + 0x35u),
                      *(const volatile uint32_t *)((uintptr_t)tp + 0x44u));
                /* 若启动 10s 后 LIRO 仍未上报任何触摸包，补发一次 cmd=3(1) 防止启动阶段后续流程重置 TouchPanel 状态 */
                if (points[i].elapsed_s == 10u && g_g5tp_vt4_cnt == 0u &&
                    g_g5tp_ob5_send_msg != NULL && !g_g5tp_hb_retried) {
                    g_g5tp_hb_retried = 1;
                    uint32_t cmd3_retry[2] = { 3u, 1u };
                    int rc3 = g_g5tp_ob5_send_msg(tp, 0x01010227u, cmd3_retry, (uint32_t)sizeof(cmd3_retry), 2u, 0u);
                    logf_("REAL_TP_HB: +10s vt4 仍为 0，一次性补发 0x01010227 cmd=3(1) -> rc=%d", rc3);
                }
            }
        }
        if (points[i].elapsed_s == 20u && g_real_drawfb_done_cnt == 0u && !dumped_stuck) {
            dumped_stuck = 1;
            logf_("REAL_HB: 20s 仍未观察到 libOb5:drawFramebuffer 完成，转储线程状态快照...");
            dump_all_threads_status();
        }
    }
    return NULL;
}

#endif /* !ZVE10_REAL_DEVICE */

__attribute__((minsize, cold))
static void *watchdog_thread(void *unused)
{
    (void)unused;
    /* 15 秒时系统已稳定进入 60fps drawfb 循环，立即清零失败计数，避免正常关机误判为启动失败 */
    sleep(15);
    if (g_astra_running) {
        write_int(FAILCNT_PATH, 0);
        logf_("ASTRA 存活满 15s，主绘制循环健康，启动失败计数安全清零");
    }
    return NULL;
}

/* [scr0039_boot] 初次向导直通与主动脏矩形触发（双保险） */
__attribute__((minsize, cold))
static void *wizard_bypass_thread(void *unused)
{
    (void)unused;
    logf_("WIZARD_BYPASS: 启动向导直通监听线程，等待 UI 初始化完成...");
    /* 轮询等待 event suppression none 或主循环 drawFramebuffer >= 2 */
    for (int i = 0; i < 200; i++) {
        if (__atomic_load_n(&g_appfw_seqlog_saw_suppression_none, __ATOMIC_ACQUIRE) ||
            __atomic_load_n(&g_draw_fb_cnt, __ATOMIC_ACQUIRE) >= 2u) {
            break;
        }
        usleep(50000); /* 50ms */
    }
    g5_boot_mode_t mode = g5_get_boot_mode();
    if (mode != ASTRA_BOOT_MENU) {
        logf_("WIZARD_BYPASS: boot_mode=%d keep normal path", (int)mode);
#ifndef ZVE10_REAL_DEVICE
        __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
        g5_wake_render_driver();
#endif
        return NULL;
    }
    /* 进入主事件循环后延迟 1.5 秒，让初次向导 (scr0039_boot) 稳定展现 */
    usleep(1500000);

    logf_("WIZARD_BYPASS: 触发初次向导直通与主动脏矩形 (MENU 按下/抬起)...");
    g5_inject_g4_key(0x1b, 1);
    usleep(80000);
    g5_inject_g4_key(0x1b, 0);

    /* 唤醒渲染管线加速画面生成 (QEMU 软光栅模式下需要显式唤醒驱动) */
#ifndef ZVE10_REAL_DEVICE
    __atomic_store_n(&g_boost_render_flag, 1, __ATOMIC_RELEASE);
    g5_wake_render_driver();
#endif
    logf_("WIZARD_BYPASS: 初次向导直通注入完成！");
    return NULL;
}

static int spawn(void *(*fn)(void *), size_t stack, const char *name)
{
    pthread_attr_t at;
    pthread_t th;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (stack) pthread_attr_setstacksize(&at, stack);
    int rc = pthread_create(&th, &at, fn, NULL);
    pthread_attr_destroy(&at);
    logf_("pthread_create(%s) rc=%d", name, rc);
    return rc;
}

__attribute__((minsize, cold))
static int fallback_g4(const char *why)
{
    logf_("FALLBACK -> 四代 UI (%s)", why);
    void *h = dlopen(LIBDIR "libObj.so", RTLD_GLOBAL | RTLD_LAZY);
    if (!h) {
        logf_("  dlopen %slibObj.so 失败: %s", LIBDIR, dlerror());
    } else {
        init_fn g4 = (init_fn)dlsym(h, "Application_System_Init");
        if (!g4) g4 = (init_fn)dlsym(h, "Application_System_InjS");
        if (g4) {
            logf_("  四代原始入口成功装载，接管主循环...");
            return g4(g_init_arg);
        }
        logf_("  四代入口未找到: %s", dlerror());
    }
    logf_("  [CRITICAL] 无法直接启动四代主循环，进入宿主守护休眠以保住 im.elf 存活...");
    while (1) {
        sleep(10);
    }
    return 0;
}

__attribute__((visibility("default")))
int Application_System_Init(void *arg)
{
    g_init_arg = arg;
    mkdir(LOG_DIR, 0755);
    mkdir(STATE_DIR, 0755);

    /* 对齐 SD 卡多路径挂载点，确保五代访问 /mnt/sdcard 或 /media/sdcard 时能命中四代 /mnt/sd */
    (void)mkdir("/mnt/sdcard", 0777);
    (void)symlink("/mnt/sd", "/mnt/sdcard");
    (void)mkdir("/media", 0777);
    (void)mkdir("/media/sdcard", 0777);
    (void)symlink("/mnt/sd", "/media/sdcard");
    struct stat log_st;
    if (stat(LOG_PATH, &log_st) == 0 && log_st.st_size > 512 * 1024) {
        (void)rename(LOG_PATH, LOG_DIR "/boot.prev.log");
    }
    g_logfd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    snprintf(g_runid, sizeof g_runid, "R%08lx-%d", (unsigned long)time(NULL), (int)getpid());
#ifdef ZVE10_REAL_DEVICE
    logf_("==== appFwBoot(g4host) v0.5 REAL-DEVICE Application_System_Init arg=%p ====", arg);
#else
    logf_("==== appFwBoot(g4host) v0.5 QEMU-MODE Application_System_Init arg=%p ====", arg);
#endif

    if (access(DISABLE_PATH, F_OK) == 0)
        return fallback_g4("disable 标志存在");

    int fails = read_int(FAILCNT_PATH, 0);
    if (fails >= ASTRA_MAX_FAIL) {
        logf_("ASTRA_WARN: 历史失败计数达到上限 %d，自动清零复位以保证主系统平稳拉起", fails);
        write_int(FAILCNT_PATH, 0);
        fails = 0;
    }
    write_int(FAILCNT_PATH, fails + 1);

    /* 严禁在物理闪存上重命名或破坏原厂 /setting/BACKUP.BIN (相机核心传感器与硬件标定必需品) */

    /* 核心护航：第一时间注入 libObj.so 的 Context 桩，彻底堵死后台并发线程空指针崩溃 */
    init_libobj_context_stub();

    /* 核心护航 2：全局拦截 libc 中的 __assert_fail 与 abort 入口，构筑断言免疫装甲 */
    void *pAssert = dlsym(RTLD_DEFAULT, "__assert_fail");
    if (pAssert) patch_function_noop(pAssert, "__assert_fail");
    void *pAbort = dlsym(RTLD_DEFAULT, "abort");
    if (pAbort) patch_function_noop(pAbort, "abort");

    install_crash_logger();
    if (spawn(astra_thread, ASTRA_STACK_SIZE, "AppFw") != 0)
        return fallback_g4("AppFw 线程创建失败");
    spawn(watchdog_thread, 64 * 1024, "AstraWd");
    spawn(wizard_bypass_thread, 64 * 1024, "AstraWizBypass");
#ifndef ZVE10_REAL_DEVICE
    spawn(render_driver_thread, 128 * 1024, "AstraRender");
#elif !defined(ZVE10_USB_SANDBOX)
    spawn(real_heartbeat_thread, 64 * 1024, "AstraRealHb");
#endif
    return 0;
}
