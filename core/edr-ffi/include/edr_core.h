/* C ABI of edr-core (Rust, core/edr-ffi). Keep in sync with src/lib.rs;
 * `cargo test -p edr-ffi` checks every constant below against Rust.
 *
 * Errors: functions returning int32_t return EDR_OK or an EDR_ERR_* code and
 * write a NUL-terminated, truncated message into err[err_cap] (may be NULL).
 * Handles are immutable after creation and may be shared across threads;
 * release each with its _free function. */
#ifndef EDR_CORE_H
#define EDR_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EDR_OK 0
#define EDR_ERR_ARGUMENT 1
#define EDR_ERR_BUNDLE 2
#define EDR_ERR_ENGINE 3
#define EDR_ERR_SELF_TEST 4
#define EDR_ERR_NOT_FOUND 5
#define EDR_ERR_PANIC 6

#define EDR_MODE_ACTIVATION 0
#define EDR_MODE_LOAD 1

#define EDR_OUTCOME_CLEAN 0
#define EDR_OUTCOME_STATIC_MATCH 1
#define EDR_OUTCOME_SCHEMA_VIOLATION 2
#define EDR_OUTCOME_DECODE_ERROR 3
#define EDR_OUTCOME_TIMEOUT 4
#define EDR_OUTCOME_RESOURCE_EXCEEDED 5
#define EDR_OUTCOME_CRASH 6
#define EDR_OUTCOME_PROTOCOL_VIOLATION 7

#define EDR_CHANNEL_STABLE 1
#define EDR_CHANNEL_CANARY 2

#define EDR_SEVERITY_NONE 0
#define EDR_SEVERITY_LOW 1
#define EDR_SEVERITY_MEDIUM 2
#define EDR_SEVERITY_HIGH 3
#define EDR_SEVERITY_CRITICAL 4

#define EDR_ACTION_ALLOW 0
#define EDR_ACTION_LOG 1
#define EDR_ACTION_ALERT 2
#define EDR_ACTION_QUARANTINE 3

typedef struct EdrBundle EdrBundle;
typedef struct EdrEngine EdrEngine;
typedef struct EdrReport EdrReport;

typedef struct {
    uint64_t version;
    int64_t created;
    int64_t expires;
    uint8_t channel;         /* EDR_CHANNEL_* */
    bool expired;            /* load mode: keep scanning, raise stale-rules alert */
    uint32_t memory_limit_mb;
    uint32_t self_tests;
} EdrBundleInfo;

typedef struct {
    bool decode;             /* run stage 2 (ImageIO) */
    uint64_t max_bytes;
    uint64_t max_pixels;
    uint32_t deadline_ms;
} EdrFormatPolicy;

typedef struct {
    uint8_t severity;        /* EDR_SEVERITY_* */
    uint8_t action;          /* EDR_ACTION_* */
} EdrAction;

/* Verify a bundle against n_roots pinned Ed25519 keys (32 bytes each,
 * concatenated in roots) with threshold. EDR_MODE_ACTIVATION enforces the
 * certificate window, expiry and version > *current_version (NULL = none);
 * EDR_MODE_LOAD reloads an already activated bundle. */
int32_t edr_bundle_open(const uint8_t *bytes, size_t len,
                        const uint8_t *roots, size_t n_roots, size_t threshold,
                        int64_t now, uint32_t mode, const uint64_t *current_version,
                        EdrBundle **out, char *err, size_t err_cap);
void edr_bundle_free(EdrBundle *bundle);
int32_t edr_bundle_info(const EdrBundle *bundle, EdrBundleInfo *out);
/* EDR_ERR_NOT_FOUND when the extension is not mapped (use "other"). */
int32_t edr_bundle_format_for_extension(const EdrBundle *bundle, const char *ext,
                                        char *name, size_t name_cap);
/* format NULL or unknown falls back to "other". */
int32_t edr_bundle_format_policy(const EdrBundle *bundle, const char *format,
                                 EdrFormatPolicy *out);
int32_t edr_bundle_action(const EdrBundle *bundle, uint32_t outcome, EdrAction *out);

int32_t edr_engine_new(const EdrBundle *bundle, EdrEngine **out, char *err, size_t err_cap);
void edr_engine_free(EdrEngine *engine);
int32_t edr_engine_self_test(const EdrEngine *engine, const EdrBundle *bundle,
                             uint32_t *passed, char *err, size_t err_cap);
/* NULL only on invalid arguments or internal panic: treat as CRASH. */
EdrReport *edr_engine_scan(const EdrEngine *engine, const uint8_t *data, size_t len,
                           const char *hint);
uint32_t edr_engine_version(void);

void edr_report_free(EdrReport *report);
uint32_t edr_report_outcome(const EdrReport *report);
uint64_t edr_report_offset(const EdrReport *report);
uint64_t edr_report_fuel_used(const EdrReport *report);
const char *edr_report_format(const EdrReport *report); /* may be NULL */
const char *edr_report_detail(const EdrReport *report);
size_t edr_report_hit_count(const EdrReport *report);
const char *edr_report_hit(const EdrReport *report, size_t i);

#ifdef __cplusplus
}
#endif
#endif
