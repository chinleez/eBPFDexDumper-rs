//go:build ignore
#include "header.h"
#include "vmlinux.h"

const struct config_t *unused_config_t __attribute__((unused));
const struct art_layout_t *unused_art_layout_t __attribute__((unused));
const struct dex_event_data_t *unused_dex_event_data_t __attribute__((unused));
const struct method_event_data_t *unused_method_event_data_t __attribute__((unused));
const buf_t *unused_buf_t __attribute__((unused));
const struct dex_chunk_event_t *unused_dex_chunk_event_t __attribute__((unused));
const struct dex_read_failure_t *unused_dex_read_failure_t __attribute__((unused));
const struct layout_debug_event_t *unused_layout_debug_event_t __attribute__((unused));
const struct native_buffer_event_t *unused_native_buffer_event_t __attribute__((unused));

#define DEFAULT_SHADOW_FRAME_METHOD_OFFSET 0x08
#define DEFAULT_ART_METHOD_DECLARING_CLASS_OFFSET 0x00
#define DEFAULT_ART_METHOD_DEX_METHOD_INDEX_OFFSET 0x08
#define DEFAULT_ART_METHOD_DATA_OFFSET 0x10
#define DEFAULT_CLASS_DEX_CACHE_OFFSET 0x10
#define DEFAULT_DEX_CACHE_DEX_FILE_OFFSET 0x10
#define DEFAULT_DEX_FILE_BEGIN_OFFSET 0x08
#define DEFAULT_DEX_HEADER_FILE_SIZE_OFFSET 0x20
#define DEFAULT_CODE_ITEM_INSNS_SIZE_OFFSET 0x0c
#define DEFAULT_CODE_ITEM_INSNS_OFFSET 0x10
#define DEX_MAGIC 0x0a786564
#define MAX_DEX_FILE_SIZE 0x40000000
#define LAYOUT_REASON_ART_CHAIN_FAILED 1
#define LAYOUT_REASON_CODE_ITEM_FAILED 2
#define LAYOUT_SOURCE_ART_CHAIN 1
#define LAYOUT_SOURCE_CODE_ITEM 2
#define NATIVE_SOURCE_MMAP 1
#define NATIVE_SOURCE_MPROTECT 2
#define NATIVE_SOURCE_MEMFD_CREATE 3
#define NATIVE_SOURCE_MEMCPY 4
#define NATIVE_SOURCE_MEMMOVE 5
#define NATIVE_SOURCE_MEMSET 6
#define NATIVE_MAX_COPY_SIZE 0x40000000
#define NATIVE_MIN_COPY_SIZE 0x70

static const struct art_layout_t default_art_layout = {
    .shadow_frame_method_offset = DEFAULT_SHADOW_FRAME_METHOD_OFFSET,
    .art_method_declaring_class_offset = DEFAULT_ART_METHOD_DECLARING_CLASS_OFFSET,
    .art_method_dex_method_index_offset = DEFAULT_ART_METHOD_DEX_METHOD_INDEX_OFFSET,
    .art_method_data_offset = DEFAULT_ART_METHOD_DATA_OFFSET,
    .class_dex_cache_offset = DEFAULT_CLASS_DEX_CACHE_OFFSET,
    .dex_cache_dex_file_offset = DEFAULT_DEX_CACHE_DEX_FILE_OFFSET,
    .dex_file_begin_offset = DEFAULT_DEX_FILE_BEGIN_OFFSET,
    .dex_header_file_size_offset = DEFAULT_DEX_HEADER_FILE_SIZE_OFFSET,
    .code_item_insns_size_offset = DEFAULT_CODE_ITEM_INSNS_SIZE_OFFSET,
    .code_item_insns_offset = DEFAULT_CODE_ITEM_INSNS_OFFSET,
};

static __always_inline bool valid_uid(uid_t uid) {
	return uid != INVALID_UID_PID;
}

static __always_inline bool filter_art(u64 artmethod) {
    // check if high 32 bits are zero
    return (artmethod & 0xFFFFFFFF00000000) == 0;
}

static __always_inline void* untag(void* ptr)
{
    void* tmp = (void*)((long)(ptr)&0x00ffffffffffffff);
    return tmp;
}

static __always_inline u32 current_tgid(void)
{
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline struct config_t *get_config(void)
{
    u32 zero = 0;
    return (struct config_t *)bpf_map_lookup_elem(&config_map, &zero);
}

static __always_inline struct art_layout_t *get_art_layout(void)
{
    u32 zero = 0;
    struct art_layout_t *layout = (struct art_layout_t *)bpf_map_lookup_elem(&art_layout_map, &zero);
    if (layout) {
        return layout;
    }
    return (struct art_layout_t *)&default_art_layout;
}

static __always_inline void submit_layout_debug_event(
    struct config_t *conf,
    u32 pid,
    u64 art_method_ptr,
    u64 code_item_ptr,
    u64 begin,
    u32 size,
    u32 reason,
    u32 source)
{
    bool layout_debug_enable = conf && conf->debug_layout != 0;
    bool code_item_fallback_enable = !conf || conf->code_item_fallback != 0;
    if (!layout_debug_enable) {
        if (reason == 0 || !code_item_fallback_enable) {
            return;
        }
    }
    if (!code_item_fallback_enable && source == LAYOUT_SOURCE_CODE_ITEM) {
        return;
    }
    struct layout_debug_event_t *evt = (struct layout_debug_event_t *)bpf_ringbuf_reserve(
        &layout_debug_events, sizeof(struct layout_debug_event_t), 0);
    if (!evt) {
        return;
    }
    evt->art_method_ptr = art_method_ptr;
    evt->code_item_ptr = code_item_ptr;
    evt->begin = begin;
    evt->pid = pid;
    evt->size = size;
    evt->reason = reason;
    evt->source = source;
    bpf_ringbuf_submit(evt, BPF_RB_FORCE_WAKEUP);
}

static __always_inline int looks_like_dex_header(u64 addr, u32 dex_header_file_size_offset, u32 *size)
{
    *size = 0;
    if (addr == 0) {
        return 0;
    }
    u32 magic = 0;
    if (bpf_probe_read_user(&magic, sizeof(u32), (void *)untag((void *)addr)) != 0) {
        return 0;
    }
    if (magic != DEX_MAGIC) {
        return 0;
    }
    bpf_probe_read_user(
        size,
        sizeof(u32),
        (void *)((unsigned long)untag((void *)addr) + dex_header_file_size_offset));
    return *size >= NATIVE_MIN_COPY_SIZE && *size <= MAX_DEX_FILE_SIZE;
}

static __always_inline void submit_native_buffer_event(
    struct config_t *conf,
    u32 pid,
    u64 addr,
    u64 size,
    u32 source,
    u32 prot,
    u32 flags)
{
    bool native_buffer_scan_enable = !conf || conf->native_buffer_scan != 0;
    if (!native_buffer_scan_enable || addr == 0 || size < NATIVE_MIN_COPY_SIZE || size > NATIVE_MAX_COPY_SIZE) {
        return;
    }
    struct native_buffer_event_t *evt = (struct native_buffer_event_t *)bpf_ringbuf_reserve(
        &native_buffer_events, sizeof(struct native_buffer_event_t), 0);
    if (!evt) {
        return;
    }
    evt->addr = addr;
    evt->size = size;
    evt->pid = pid;
    evt->source = source;
    evt->prot = prot;
    evt->flags = flags;
    bpf_ringbuf_submit(evt, BPF_RB_FORCE_WAKEUP);
}

static __always_inline void submit_dex_chunks_partial(u64 begin, u32 pid, u32 size);

static __always_inline int read_code_item_from_art_method(
    u64 art_method_ptr,
    struct art_layout_t *layout,
    u64 *code_item_ptr)
{
    *code_item_ptr = 0;
    if (bpf_probe_read_user(
            code_item_ptr,
            sizeof(u64),
            (void *)(art_method_ptr + layout->art_method_data_offset)) != 0) {
        return 0;
    }
    *code_item_ptr = (u64)untag((void *)*code_item_ptr);
    return *code_item_ptr != 0;
}

static __always_inline void submit_dex_from_begin(u32 pid, u64 begin, u32 size)
{
    if (begin == 0 || size == 0 || size > MAX_DEX_FILE_SIZE) {
        return;
    }

    u32 exist = 1;
    u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);
    if (value != 0 && *value == 1) {
        return;
    }

    struct dex_event_data_t *dex_evt = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
    if (dex_evt) {
        dex_evt->begin = begin;
        dex_evt->pid = pid;
        dex_evt->size = size;
        bpf_ringbuf_submit(dex_evt, BPF_RB_FORCE_WAKEUP);
    }
    submit_dex_chunks_partial(begin, pid, size);
    bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
}

static __always_inline int read_dex_from_art_method(
    u64 art_method_ptr,
    u32 art_method_declaring_class_offset,
    u32 class_dex_cache_offset,
    u32 dex_cache_dex_file_offset,
    u32 dex_file_begin_offset,
    u32 dex_header_file_size_offset,
    u64 *begin,
    u32 *size)
{
    *begin = 0;
    *size = 0;

    u32 declaring_class_ref = 0;
    bpf_probe_read_user(
        &declaring_class_ref,
        sizeof(declaring_class_ref),
        (void *)(art_method_ptr + art_method_declaring_class_offset));
    unsigned char *declaring_class_ptr = (unsigned char *)(u64)declaring_class_ref;
    if (!declaring_class_ptr) {
        return 0;
    }

    u32 dex_cache_ref = 0;
    bpf_probe_read_user(
        &dex_cache_ref,
        sizeof(dex_cache_ref),
        declaring_class_ptr + class_dex_cache_offset);
    unsigned char *dex_cache_ptr = (unsigned char *)(u64)dex_cache_ref;
    if (!dex_cache_ptr) {
        return 0;
    }

    unsigned char *dex_file_ptr = 0;
    bpf_probe_read_user(
        &dex_file_ptr,
        sizeof(u64),
        dex_cache_ptr + dex_cache_dex_file_offset);
    dex_file_ptr = (unsigned char *)untag(dex_file_ptr);
    if (!dex_file_ptr) {
        return 0;
    }

    bpf_probe_read_user(begin, sizeof(u64), dex_file_ptr + dex_file_begin_offset);
    bpf_probe_read_user(
        size,
        sizeof(u32),
        (void *)((unsigned long)untag((void *)*begin) + dex_header_file_size_offset));
    if (*begin == 0 || *size == 0 || *size > MAX_DEX_FILE_SIZE) {
        return 0;
    }

    u32 magic = 0;
    bpf_probe_read_user(&magic, sizeof(u32), (void *)untag((void *)*begin));
    if (magic != DEX_MAGIC) {
        return 0;
    }
    // Strip MTE/PAC tag from the output begin so subsequent BPF chunk reads
    // and user-space process_vm_readv calls all target the canonical address.
    *begin = (u64)untag((void *)*begin);
    return 1;
}

static __always_inline int resolve_dex_from_art_method(
    u64 art_method_ptr,
    struct art_layout_t *layout,
    u64 *begin,
    u32 *size,
    u32 *dex_method_index)
{
    *dex_method_index = 0;
    bpf_probe_read_user(
        dex_method_index,
        sizeof(u32),
        (void *)(art_method_ptr + layout->art_method_dex_method_index_offset));

    if (read_dex_from_art_method(
            art_method_ptr,
            layout->art_method_declaring_class_offset,
            layout->class_dex_cache_offset,
            layout->dex_cache_dex_file_offset,
            layout->dex_file_begin_offset,
            layout->dex_header_file_size_offset,
            begin,
            size)) {
        return 1;
    }

#pragma unroll
    for (int class_slot = 0; class_slot < 4; class_slot++) {
        u32 class_dex_cache_offset = 0x10 + class_slot * 8;
#pragma unroll
        for (int dex_cache_slot = 0; dex_cache_slot < 4; dex_cache_slot++) {
            u32 dex_cache_dex_file_offset = 0x10 + dex_cache_slot * 8;
            if (read_dex_from_art_method(
                    art_method_ptr,
                    layout->art_method_declaring_class_offset,
                    class_dex_cache_offset,
                    dex_cache_dex_file_offset,
                    layout->dex_file_begin_offset,
                    layout->dex_header_file_size_offset,
                    begin,
                    size)) {
                return 1;
            }
        }
    }
    return 0;
}

static __always_inline 
u32 read_method_bytecode(u64 art_method_ptr, u32 *codeitem_size) {
    *codeitem_size = 0;
    
    // Check if this method's bytecode has already been read
    u32 *cached = (u32 *)bpf_map_lookup_elem(&methodCodeCache_map, &art_method_ptr);
    if (cached && *cached == 1) {
        return 0; // Already read, don't read again
    }
    
    // Get the CodeItem pointer from ArtMethod
    struct art_layout_t *layout = get_art_layout();
    u64 code_item_ptr = 0;
    if (!read_code_item_from_art_method(art_method_ptr, layout, &code_item_ptr)) {
        return 0; // No bytecode (native method or abstract)
    }
    
    // Read CodeItem header to get insns_size_in_code_units
    u32 insns_size = 0;
    if (bpf_probe_read_user(&insns_size, sizeof(u32), (void *)(code_item_ptr + layout->code_item_insns_size_offset)) != 0) {
        return 0;
    }
    
    if (insns_size == 0 || insns_size > 0x10000) { // Sanity check
        return 0;
    }
    
    *codeitem_size = insns_size * 2; // Convert to bytes
    
    // Get per-CPU buffer
    u32 zero = 0;
    buf_t *buf = (buf_t *)bpf_map_lookup_elem(&bufs_m, &zero);
    if (!buf) {
        return 0;
    }
    
    // Read bytecode into buffer
    u32 bytes_to_read = *codeitem_size;
    if (bytes_to_read > MAX_PERCPU_BUFSIZE - sizeof(struct method_event_data_t)) {
        bytes_to_read = MAX_PERCPU_BUFSIZE - sizeof(struct method_event_data_t);
        *codeitem_size = bytes_to_read;
    }
    
    asm volatile("if %[size] < %[max] goto +1;\n"
    "%[size] = %[max];\n"
    :
    : [size] "r"(bytes_to_read), [max] "i"(MAX_PERCPU_BUFSIZE - sizeof(struct method_event_data_t)));

    if (bpf_probe_read_user(buf->buf + sizeof(struct method_event_data_t), bytes_to_read, 
	                            (void *)(code_item_ptr + layout->code_item_insns_offset)) != 0) {
        *codeitem_size = 0;
        return 0;
    }
    
    // Mark this method as read
    u32 read_flag = 1;
    bpf_map_update_elem(&methodCodeCache_map, &art_method_ptr, &read_flag, BPF_ANY);
    
    return 1;
}

static __always_inline
void submit_method_event_with_bytecode(u64 begin, u32 pid, u32 size, u64 art_method_ptr, 
                                       u32 method_index, u32 codeitem_size) {
    if (codeitem_size > 0) {
        // Submit with bytecode using variable-length ringbuf
        u32 zero = 0;
        buf_t *buf = (buf_t *)bpf_map_lookup_elem(&bufs_m, &zero);
        if (!buf) {
            return;
        }
        
        struct method_event_data_t *method_evt = (struct method_event_data_t *)buf->buf;
        method_evt->begin = begin;
        method_evt->pid = pid;
        method_evt->size = size;
        method_evt->art_method_ptr = art_method_ptr;
        method_evt->method_index = method_index;
        method_evt->codeitem_size = codeitem_size;
        
        u32 total_size = sizeof(struct method_event_data_t) + codeitem_size;
        asm volatile("if %[size] < %[max] goto +1;\n"
        "%[size] = %[max];\n"
        :
        : [size] "r"(total_size), [max] "i"(MAX_PERCPU_BUFSIZE));
        bpf_ringbuf_output(&method_events, buf->buf, total_size, BPF_RB_FORCE_WAKEUP);
    } else {
        // Submit without bytecode using fixed-size structure
        struct method_event_data_t *method_evt = (struct method_event_data_t *)bpf_ringbuf_reserve(&method_events, sizeof(struct method_event_data_t), 0);
        if (method_evt) {
            method_evt->begin = begin;
            method_evt->pid = pid;
            method_evt->size = size;
            method_evt->art_method_ptr = art_method_ptr;
            method_evt->method_index = method_index;
            method_evt->codeitem_size = 0;
            bpf_ringbuf_submit(method_evt, BPF_RB_FORCE_WAKEUP);
        }
    }
}

// Max chunks per invocation to control runtime
#define MAX_CHUNKS_PER_CALL 128  // Increased for faster DEX transfer

static __always_inline void submit_dex_chunks_partial(u64 begin, u32 pid, u32 size) {
    if (size == 0) return;

    // load current progress
    u32 *pnext = (u32 *)bpf_map_lookup_elem(&dexProgress_map, &begin);
    u32 next_off = 0;
    if (pnext) {
        next_off = *pnext;
        if (next_off >= size) {
            return; // completed
        }
    }

    // compute max payload per record
    const u32 hdr_sz = sizeof(struct dex_chunk_event_t);
    const u32 max_payload = RINGBUF_SIZE - hdr_sz;

    #pragma unroll
    for (int i = 0; i < MAX_CHUNKS_PER_CALL; i++) {
        if (next_off >= size) {
            break;
        }

        u32 remain = size > next_off ? size - next_off : 0;
        if (remain == 0) {
            break;
        }
        u32 payload = remain;
        if (payload > max_payload) {
            payload = max_payload;
        }

        // Reserve fixed-size space in ringbuf (use constant size for verifier)
        struct dex_chunk_event_t *evt = (struct dex_chunk_event_t *)bpf_ringbuf_reserve(&dex_chunks, RINGBUF_SIZE, 0);
        if (!evt) {
            // Failed to reserve, stop processing
            // Notify user space about read failure so it can use a fallback reader.
            struct dex_read_failure_t *failure_evt = (struct dex_read_failure_t *)bpf_ringbuf_reserve(&read_failures, sizeof(struct dex_read_failure_t), 0);
            if (failure_evt) {
                failure_evt->begin = begin;
                failure_evt->pid = pid;
                failure_evt->size = size;
                failure_evt->failed_offset = next_off;
                bpf_ringbuf_submit(failure_evt, BPF_RB_FORCE_WAKEUP);
            }
            break;
        }

        // Fill the event header
        evt->begin = begin;
        evt->pid = pid;
        evt->size = size;
        evt->offset = next_off;
        evt->data_len = payload;

        // read user memory into buffer after header
        u32 read_size = payload;
        asm volatile("if %[size] < %[max] goto +1;\n"
                     "%[size] = %[max];\n"
                     : [size] "+r"(read_size)
                     : [max] "i"(max_payload));
        int ret = bpf_probe_read_user((void *)((char *)evt + sizeof(*evt)), read_size, (void *)(begin + next_off));
        if (ret != 0) {
            bpf_ringbuf_discard(evt, 0);
            // Notify user space about read failure so it can use a fallback reader.
            struct dex_read_failure_t *failure_evt = (struct dex_read_failure_t *)bpf_ringbuf_reserve(&read_failures, sizeof(struct dex_read_failure_t), 0);
            if (failure_evt) {
                failure_evt->begin = begin;
                failure_evt->pid = pid;
                failure_evt->size = size;
                failure_evt->failed_offset = next_off;
                bpf_ringbuf_submit(failure_evt, BPF_RB_FORCE_WAKEUP);
            }
            
            break;
        }

        // Submit the filled event
        bpf_ringbuf_submit(evt, BPF_RB_FORCE_WAKEUP);

        next_off += payload;
    }

    // store progress
    bpf_map_update_elem(&dexProgress_map, &begin, &next_off, BPF_ANY);
}

static __always_inline int handle_art_method(struct config_t *conf, u32 pid, u64 art_method_ptr)
{
    if (filter_art(art_method_ptr)) {
        return 0;
    }

    struct art_layout_t *layout = get_art_layout();
    u32 dex_method_index = 0;
    u64 begin = 0;
    u32 size = 0;
    if (!resolve_dex_from_art_method(art_method_ptr, layout, &begin, &size, &dex_method_index)) {
        u64 code_item_ptr = 0;
        if (read_code_item_from_art_method(art_method_ptr, layout, &code_item_ptr)) {
            submit_layout_debug_event(
                conf,
                pid,
                art_method_ptr,
                code_item_ptr,
                0,
                0,
                LAYOUT_REASON_ART_CHAIN_FAILED,
                LAYOUT_SOURCE_CODE_ITEM);
        } else {
            submit_layout_debug_event(
                conf,
                pid,
                art_method_ptr,
                0,
                0,
                0,
                LAYOUT_REASON_CODE_ITEM_FAILED,
                LAYOUT_SOURCE_CODE_ITEM);
        }
        return 0;
    }

    u8 ch = 0;
    bpf_probe_read_user(&ch, sizeof(u8), (void *)untag((void *)begin));
    if (begin == 0 || size == 0 || ch != 0x64) {
        return 0;
    }

    submit_layout_debug_event(
        conf,
        pid,
        art_method_ptr,
        0,
        begin,
        size,
        0,
        LAYOUT_SOURCE_ART_CHAIN);

    u32 exist = 1;
    u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);
    if (value == 0 || *value != 1) {
        struct dex_event_data_t *dex_evt = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
        if (dex_evt) {
            dex_evt->begin = begin;
            dex_evt->pid = pid;
            dex_evt->size = size;
            bpf_ringbuf_submit(dex_evt, BPF_RB_FORCE_WAKEUP);
        }
        submit_dex_chunks_partial(begin, pid, size);
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);
    }

    u32 codeitem_size = 0;
    read_method_bytecode(art_method_ptr, &codeitem_size);
    submit_method_event_with_bytecode(
        begin, pid, size, art_method_ptr, dex_method_index, codeitem_size);
    return 0;
}

static __always_inline
bool trace_allowed(struct config_t *conf, u32 pid, u32 uid)
{
    if (!conf) {
        return true;
    }

    if (valid_uid(conf->uid)) {
        if (conf->uid != uid) {
            return false;
        }
    }
    if (valid_uid(conf->pid)) {
        if (conf->pid != pid) {
            return false;
        }
    }
    return true;
}

SEC("uprobe/libart_execute")
int uprobe_libart_execute(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }

    struct art_layout_t *layout = get_art_layout();
    unsigned char *shadow_frame_ptr = (unsigned char *)PT_REGS_PARM3(ctx);

    u64 art_method_ptr = 0;
    bpf_probe_read_user(
        &art_method_ptr,
        sizeof(u64),
        shadow_frame_ptr + layout->shadow_frame_method_offset);
    return handle_art_method(conf, pid, art_method_ptr);
}

SEC("uprobe/libart_executeNterpImpl")
int uprobe_libart_executeNterpImpl(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }

    u64 art_method_ptr = (u64)PT_REGS_PARM1(ctx);
    return handle_art_method(conf, pid, art_method_ptr);
}

// NterpOpInvoke
SEC("uprobe/libart_nterpOpInvoke")
int uprobe_libart_nterpOpInvoke(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }

    u64 art_method_ptr = (u64)PT_REGS_PARM1(ctx);
    return handle_art_method(conf, pid, art_method_ptr);
}

// DexFile::DexFile constructor. On AArch64 C++ ABI, x1 is base.
SEC("uprobe/libart_dexFileCtor")
int uprobe_libart_dexFileCtor(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }

    struct art_layout_t *layout = get_art_layout();
    u64 begin = (u64)PT_REGS_PARM2(ctx);
    u32 size = 0;
    if (looks_like_dex_header(begin, layout->dex_header_file_size_offset, &size)) {
        submit_dex_from_begin(pid, begin, size);
    }
    return 0;
}

SEC("uprobe/libc_memcpy")
int uprobe_libc_memcpy(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 size = (u64)PT_REGS_PARM3(ctx);
    if (size == 0 || size > NATIVE_MAX_COPY_SIZE) {
        return 0;
    }
    struct native_copy_args_t args = {};
    args.dst = (u64)PT_REGS_PARM1(ctx);
    args.size = size;
    args.source = NATIVE_SOURCE_MEMCPY;
    bpf_map_update_elem(&native_copy_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/libc_memcpy")
int uretprobe_libc_memcpy(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct native_copy_args_t *args = (struct native_copy_args_t *)bpf_map_lookup_elem(&native_copy_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }
    struct art_layout_t *layout = get_art_layout();
    u32 dex_size = 0;
    if (looks_like_dex_header(args->dst, layout->dex_header_file_size_offset, &dex_size)) {
        struct config_t *conf = get_config();
        submit_native_buffer_event(conf, (u32)(pid_tgid >> 32), args->dst, dex_size, args->source, 0, 0);
    }
    bpf_map_delete_elem(&native_copy_args_map, &pid_tgid);
    return 0;
}

SEC("uprobe/libc_memmove")
int uprobe_libc_memmove(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 size = (u64)PT_REGS_PARM3(ctx);
    if (size == 0 || size > NATIVE_MAX_COPY_SIZE) {
        return 0;
    }
    struct native_copy_args_t args = {};
    args.dst = (u64)PT_REGS_PARM1(ctx);
    args.size = size;
    args.source = NATIVE_SOURCE_MEMMOVE;
    bpf_map_update_elem(&native_copy_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/libc_memmove")
int uretprobe_libc_memmove(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct native_copy_args_t *args = (struct native_copy_args_t *)bpf_map_lookup_elem(&native_copy_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }
    struct art_layout_t *layout = get_art_layout();
    u32 dex_size = 0;
    if (looks_like_dex_header(args->dst, layout->dex_header_file_size_offset, &dex_size)) {
        struct config_t *conf = get_config();
        submit_native_buffer_event(conf, (u32)(pid_tgid >> 32), args->dst, dex_size, args->source, 0, 0);
    }
    bpf_map_delete_elem(&native_copy_args_map, &pid_tgid);
    return 0;
}

SEC("uprobe/libc_mmap")
int uprobe_libc_mmap(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct native_alloc_args_t args = {};
    args.size = (u64)PT_REGS_PARM2(ctx);
    args.prot = (u32)PT_REGS_PARM3(ctx);
    args.flags = (u32)PT_REGS_PARM4(ctx);
    if (args.size == 0 || args.size > NATIVE_MAX_COPY_SIZE) {
        return 0;
    }
    bpf_map_update_elem(&native_alloc_args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("uretprobe/libc_mmap")
int uretprobe_libc_mmap(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct native_alloc_args_t *args = (struct native_alloc_args_t *)bpf_map_lookup_elem(&native_alloc_args_map, &pid_tgid);
    if (!args) {
        return 0;
    }
    u64 addr = (u64)PT_REGS_RC(ctx);
    if (addr != (u64)-1) {
        struct config_t *conf = get_config();
        submit_native_buffer_event(conf, (u32)(pid_tgid >> 32), addr, args->size, NATIVE_SOURCE_MMAP, args->prot, args->flags);
    }
    bpf_map_delete_elem(&native_alloc_args_map, &pid_tgid);
    return 0;
}

SEC("uprobe/libc_mprotect")
int uprobe_libc_mprotect(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 addr = (u64)PT_REGS_PARM1(ctx);
    u64 size = (u64)PT_REGS_PARM2(ctx);
    u32 prot = (u32)PT_REGS_PARM3(ctx);
    submit_native_buffer_event(conf, (u32)(pid_tgid >> 32), addr, size, NATIVE_SOURCE_MPROTECT, prot, 0);
    return 0;
}

SEC("uretprobe/libc_memfd_create")
int uretprobe_libc_memfd_create(struct pt_regs *ctx)
{
    (void)ctx;
    return 0;
}

// ClassLinker::RegisterDexFile(ClassLinker* this, DexFile const& dex,
//                              ObjPtr<ClassLoader> loader). On AArch64 C++ ABI
// PARM2 (x1) is the DexFile pointer, which lets us recover dex begin/size the
// same way uprobe_libart_verifyClass does for stripped ROMs that inline the
// DexFile constructor.
SEC("uprobe/libart_registerDexFile")
int uprobe_libart_registerDexFile(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }

    unsigned char *dex_file_ptr = (unsigned char *)PT_REGS_PARM2(ctx);
    dex_file_ptr = (unsigned char *)untag(dex_file_ptr);
    if (!dex_file_ptr) {
        return 0;
    }

    struct art_layout_t *layout = get_art_layout();
    u64 begin = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + layout->dex_file_begin_offset);
    if (begin == 0) {
        return 0;
    }
    begin = (u64)untag((void *)begin);
    u32 size = 0;
    if (looks_like_dex_header(begin, layout->dex_header_file_size_offset, &size)) {
        submit_dex_from_begin(pid, begin, size);
    }
    return 0;
}

// VerifyClass
SEC("uprobe/libart_verifyClass")
int uprobe_libart_verifyClass(struct pt_regs *ctx)
{
    u32 pid = current_tgid();
    struct config_t *conf = get_config();
    if (!trace_allowed(conf, pid, bpf_get_current_uid_gid())){
        return 0;
    }

    struct dex_event_data_t evt = {};
    __builtin_memset(&evt, 0, sizeof(evt)); 
    unsigned char *dex_file_ptr = (unsigned char *)PT_REGS_PARM3(ctx);
    dex_file_ptr = (unsigned char *)untag(dex_file_ptr);
    struct art_layout_t *layout = get_art_layout();
    
    u64 begin = 0;
    u32 size = 0;
    bpf_probe_read_user(&begin, sizeof(u64), dex_file_ptr + layout->dex_file_begin_offset);
    if (begin == 0) {
        return 0;
    }
    begin = (u64)untag((void *)begin);
    bpf_probe_read_user(
        &size,
        sizeof(u32),
        (void *)((unsigned long)begin + layout->dex_header_file_size_offset));

    if (size != 0 && size <= MAX_DEX_FILE_SIZE) {
        u32 exist = 1;
        u32 *value = (u32 *)bpf_map_lookup_elem(&dexFileCache_map, &begin);

        if (value != 0 && *value == 1){
            return 0;
        }

        struct dex_event_data_t *evt_ptr = (struct dex_event_data_t *)bpf_ringbuf_reserve(&events, sizeof(struct dex_event_data_t), 0);
        if (evt_ptr) {
            evt_ptr->begin = begin;
            evt_ptr->pid = pid;
            evt_ptr->size = size;
            bpf_ringbuf_submit(evt_ptr, BPF_RB_FORCE_WAKEUP);
        }
        bpf_map_update_elem(&dexFileCache_map, &begin, &exist, BPF_ANY);

        // submit dex chunks progressively via ringbuf
        submit_dex_chunks_partial(begin, pid, size);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
