/* C ABI of pokey-core (Rust, core/pokey-ffi). Keep in sync with src/lib.rs;
 * `cargo test -p pokey-ffi` checks every constant below against Rust.
 *
 * Errors: functions returning int32_t return POKEY_OK or an POKEY_ERR_* code and
 * write a NUL-terminated, truncated message into err[err_cap] (may be NULL).
 * Handles are immutable after creation and may be shared across threads;
 * release each with its _free function. */
#ifndef POKEY_CORE_H
#define POKEY_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POKEY_OK 0
#define POKEY_ERR_ARGUMENT 1
#define POKEY_ERR_BUNDLE 2
#define POKEY_ERR_ENGINE 3
#define POKEY_ERR_SELF_TEST 4
#define POKEY_ERR_NOT_FOUND 5
#define POKEY_ERR_PANIC 6

#define POKEY_MODE_ACTIVATION 0
#define POKEY_MODE_LOAD 1

#define POKEY_OUTCOME_CLEAN 0
#define POKEY_OUTCOME_STATIC_MATCH 1
#define POKEY_OUTCOME_SCHEMA_VIOLATION 2
#define POKEY_OUTCOME_DECODE_ERROR 3
#define POKEY_OUTCOME_TIMEOUT 4
#define POKEY_OUTCOME_RESOURCE_EXCEEDED 5
#define POKEY_OUTCOME_CRASH 6
#define POKEY_OUTCOME_PROTOCOL_VIOLATION 7

#define POKEY_CHANNEL_STABLE 1
#define POKEY_CHANNEL_CANARY 2

#define POKEY_SEVERITY_NONE 0
#define POKEY_SEVERITY_LOW 1
#define POKEY_SEVERITY_MEDIUM 2
#define POKEY_SEVERITY_HIGH 3
#define POKEY_SEVERITY_CRITICAL 4

#define POKEY_ACTION_ALLOW 0
#define POKEY_ACTION_LOG 1
#define POKEY_ACTION_ALERT 2
#define POKEY_ACTION_QUARANTINE 3

typedef struct PokeyBundle PokeyBundle;
typedef struct PokeyEngine PokeyEngine;
typedef struct PokeyReport PokeyReport;

typedef struct {
    uint64_t version;
    int64_t created;
    int64_t expires;
    uint8_t channel;         /* POKEY_CHANNEL_* */
    bool expired;            /* load mode: keep scanning, raise stale-rules alert */
    uint32_t memory_limit_mb;
    uint32_t self_tests;
} PokeyBundleInfo;

typedef struct {
    bool decode;             /* run stage 2 (ImageIO) */
    uint64_t max_bytes;
    uint64_t max_pixels;
    uint32_t deadline_ms;
} PokeyFormatPolicy;

typedef struct {
    uint8_t severity;        /* POKEY_SEVERITY_* */
    uint8_t action;          /* POKEY_ACTION_* */
} PokeyAction;

/* Verify a bundle against n_roots pinned Ed25519 keys (32 bytes each,
 * concatenated in roots) with threshold. POKEY_MODE_ACTIVATION enforces the
 * certificate window, expiry and version > *current_version (NULL = none);
 * POKEY_MODE_LOAD reloads an already activated bundle. */
int32_t pokey_bundle_open(const uint8_t *bytes, size_t len,
                        const uint8_t *roots, size_t n_roots, size_t threshold,
                        int64_t now, uint32_t mode, const uint64_t *current_version,
                        PokeyBundle **out, char *err, size_t err_cap);
void pokey_bundle_free(PokeyBundle *bundle);
int32_t pokey_bundle_info(const PokeyBundle *bundle, PokeyBundleInfo *out);
/* POKEY_ERR_NOT_FOUND when the extension is not mapped (use "other"). */
int32_t pokey_bundle_format_for_extension(const PokeyBundle *bundle, const char *ext,
                                        char *name, size_t name_cap);
/* format NULL or unknown falls back to "other". */
int32_t pokey_bundle_format_policy(const PokeyBundle *bundle, const char *format,
                                 PokeyFormatPolicy *out);
int32_t pokey_bundle_action(const PokeyBundle *bundle, uint32_t outcome, PokeyAction *out);

int32_t pokey_engine_new(const PokeyBundle *bundle, PokeyEngine **out, char *err, size_t err_cap);
void pokey_engine_free(PokeyEngine *engine);
int32_t pokey_engine_self_test(const PokeyEngine *engine, const PokeyBundle *bundle,
                             uint32_t *passed, char *err, size_t err_cap);
/* NULL only on invalid arguments or internal panic: treat as CRASH. */
PokeyReport *pokey_engine_scan(const PokeyEngine *engine, const uint8_t *data, size_t len,
                           const char *hint);
uint32_t pokey_engine_version(void);

void pokey_report_free(PokeyReport *report);
uint32_t pokey_report_outcome(const PokeyReport *report);
uint64_t pokey_report_offset(const PokeyReport *report);
uint64_t pokey_report_fuel_used(const PokeyReport *report);
const char *pokey_report_format(const PokeyReport *report); /* may be NULL */
const char *pokey_report_detail(const PokeyReport *report);
size_t pokey_report_hit_count(const PokeyReport *report);
const char *pokey_report_hit(const PokeyReport *report, size_t i);

#ifdef __cplusplus
}
#endif
#endif
