#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    NO_ERROR         = '\0',
    INTERNAL_ERROR   = 'I',
    MEMORY_ERROR     = 'M',
    PARSE_ERROR      = 'P',
    RUNTIME_ERROR    = 'R',
    TERMINATED_ERROR = 'T',
};

static const uint16_t js_function_marker[] = {0xBFF,'J','a','v','a','S','c','r','i','p','t','F','u','n','c','t','i','o','n'};

// defined in mini_racer_extension.c, opaque to mini_racer_v8.cc
struct Context;

// defined in mini_racer_extension.c
void v8_get_flags(char **p, size_t *n);
void v8_thread_main(struct Context *c, uintptr_t isolate);
void v8_dispatch(struct Context *c);
void v8_reply(struct Context *c, const uint8_t *p, size_t n);
void v8_roundtrip(struct Context *c, const uint8_t **p, size_t *n);

// defined in mini_racer_v8.cc
void v8_global_init(void);
void v8_thread_init(struct Context *c, const uint8_t *snapshot_buf,
                    size_t snapshot_len, int64_t max_memory,
                    int verbose_exceptions); // calls v8_thread_main
void v8_attach(const uint8_t *p, size_t n);
void v8_call(const uint8_t *p, size_t n);
void v8_eval(const uint8_t *p, size_t n);
void v8_heap_stats(void);
void v8_heap_snapshot(void);
void v8_pump_message_loop(void);
void v8_snapshot(const uint8_t *p, size_t n);
void v8_warmup(const uint8_t *p, size_t n);
void v8_idle_notification(const uint8_t *p, size_t n);
void v8_low_memory_notification(void);
void v8_terminate_execution(uintptr_t isolate); // called from ruby or watchdog thread

#ifdef __cplusplus
}
#endif
