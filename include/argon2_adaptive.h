/*
 * Adaptive Argon2 - load based parameter selection, versioned envelope
 * storage and audit logging.
 *
 * This extension keeps the stock Argon2 PHC encoding and verification API
 * intact.  New hashes are wrapped in a versioned "$a2ad$" envelope that
 * records the policy/format versions, the selected pressure tier and the
 * exact m/t/p parameters together with the embedded stock PHC string:
 *
 *   $a2ad$v=<fmt>$pv=<policy>$tier=<0|1|2>$m=<m>,t=<t>,p=<p>$<reserved>$<phc>
 *
 * The envelope is transparent to stock verifiers: decode_string() unwraps
 * it to the embedded PHC string, so argon2id_verify() and friends keep
 * working for both old plain hashes and new envelope hashes.
 */

#ifndef ARGON2_ADAPTIVE_H
#define ARGON2_ADAPTIVE_H

#include <stddef.h>
#include <stdint.h>

#include "argon2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ARGON2_ADAPTIVE_FMT_VERSION 1
#define ARGON2_ADAPTIVE_POLICY_VERSION 1

#define ARGON2_ADAPTIVE_ENVELOPE_MAGIC "$a2ad$"

/* Long enough for an envelope wrapping any stock encoded hash. */
#define ARGON2_ADAPTIVE_ENCODED_MAX 1024
#define ARGON2_ADAPTIVE_PHC_MAX 640

#define ARGON2_ADAPTIVE_AUDIT_RING_DEFAULT 64

/* Extra return code (stock Argon2 codes end at -35). */
#define ARGON2_ADAPTIVE_AUDIT_OPEN_FAIL (-40)

/* Pass as load1 to observe() when no system load average is available. */
#define ARGON2_ADAPTIVE_LOAD_UNAVAILABLE (-1.0)

typedef enum argon2_adaptive_tier {
    ARGON2_ADAPTIVE_TIER_LOW = 0,
    ARGON2_ADAPTIVE_TIER_MEDIUM = 1,
    ARGON2_ADAPTIVE_TIER_HIGH = 2
} argon2_adaptive_tier;

ARGON2_PUBLIC const char *argon2_adaptive_tier_name(argon2_adaptive_tier tier);

/*
 * Argon2 cost parameters.  m_cost is in kibibytes (as in the stock API),
 * t_cost is the number of passes and parallelism is lanes/threads.
 */
typedef struct argon2_adaptive_params {
    uint32_t t_cost;
    uint32_t m_cost;
    uint32_t parallelism;
} argon2_adaptive_params;

typedef struct argon2_adaptive_config {
    int policy_version;
    argon2_type type;
    uint32_t salt_length;
    uint32_t hash_length;

    /* Active-login concurrency bands (inclusive lower bounds). */
    uint32_t medium_threshold;
    uint32_t high_threshold;
    uint32_t critical_threshold;

    argon2_adaptive_params low;
    argon2_adaptive_params medium;
    argon2_adaptive_params high;

    /* Never select parameters weaker than this floor. */
    argon2_adaptive_params floor;

    /* JSON-lines audit destination; NULL disables file logging. */
    const char *audit_path;

    size_t audit_ring_capacity;

    /* Sample the system load average on login_start/login_end. */
    int use_load_average;

    /* Optional injected load1 provider (deterministic tests); NULL uses
     * getloadavg()/proc when use_load_average is set. */
    double (*load1_provider)(void);
} argon2_adaptive_config;

ARGON2_PUBLIC void
argon2_adaptive_default_config(argon2_adaptive_config *config);

/*
 * Fast, deterministic profile used by the acceptance suite.  Parameters
 * are intentionally tiny so hundreds of real pthreads can hash/verify in
 * seconds; the banding/floor/audit logic is identical to production.
 */
ARGON2_PUBLIC void
argon2_adaptive_test_config(argon2_adaptive_config *config);

typedef struct argon2_adaptive_controller argon2_adaptive_controller;

/*
 * Lifecycle.  init() allocates a controller and writes the "init" audit
 * record.  config may be NULL to use argon2_adaptive_default_config().
 */
ARGON2_PUBLIC int argon2_adaptive_init(argon2_adaptive_controller **controller,
                                       const argon2_adaptive_config *config);
ARGON2_PUBLIC void argon2_adaptive_destroy(argon2_adaptive_controller *controller);

/*
 * Feed a load sample.  active is the absolute number of in-flight logins;
 * load1 is the 1-minute load average or ARGON2_ADAPTIVE_LOAD_UNAVAILABLE.
 * Re-evaluates the tier and emits param_change/overload/recovered records.
 */
ARGON2_PUBLIC int argon2_adaptive_observe(argon2_adaptive_controller *controller,
                                          uint32_t active, double load1);

/* Re-evaluate the tier from the current gauge value. */
ARGON2_PUBLIC int argon2_adaptive_evaluate(argon2_adaptive_controller *controller);

/* Concurrency gauge hooks for login endpoints. */
ARGON2_PUBLIC int argon2_adaptive_login_start(argon2_adaptive_controller *controller);
ARGON2_PUBLIC int argon2_adaptive_login_end(argon2_adaptive_controller *controller);

ARGON2_PUBLIC uint32_t
argon2_adaptive_active(const argon2_adaptive_controller *controller);
ARGON2_PUBLIC argon2_adaptive_tier
argon2_adaptive_current_tier(const argon2_adaptive_controller *controller);
ARGON2_PUBLIC int
argon2_adaptive_overload(const argon2_adaptive_controller *controller);
ARGON2_PUBLIC void
argon2_adaptive_current_params(const argon2_adaptive_controller *controller,
                               argon2_adaptive_params *params);

/* Clamp params up to config->floor and the absolute Argon2 minimums.
 * Returns ARGON2_OK or an Argon2_ErrorCodes value. */
ARGON2_PUBLIC int
argon2_adaptive_clamp_params(const argon2_adaptive_config *config,
                             argon2_adaptive_params *params);

/*
 * Hash a password with the currently selected parameters and return a
 * versioned "$a2ad$" envelope.
 */
ARGON2_PUBLIC int
argon2_adaptive_hash_encoded(argon2_adaptive_controller *controller,
                             const void *pwd, size_t pwdlen,
                             char *encoded, size_t encodedlen);

/* Verify either an envelope hash or a legacy stock PHC hash. */
ARGON2_PUBLIC int
argon2_adaptive_verify(argon2_adaptive_controller *controller,
                       const char *encoded, const void *pwd, size_t pwdlen);

/*
 * Transparent rehash guidance: returns 1 when the stored hash is a legacy
 * PHC string, uses an older format/policy version, or falls below the
 * security floor; 0 when it is current; -1 when it cannot be parsed.
 */
ARGON2_PUBLIC int
argon2_adaptive_needs_rehash(argon2_adaptive_controller *controller,
                             const char *encoded);

/* Envelope parsing. */
typedef struct argon2_adaptive_envelope {
    int format_version;
    int policy_version;
    argon2_adaptive_tier tier;
    argon2_adaptive_params params;
    char phc[ARGON2_ADAPTIVE_PHC_MAX];
} argon2_adaptive_envelope;

ARGON2_PUBLIC int argon2_adaptive_is_envelope(const char *encoded);
ARGON2_PUBLIC int argon2_adaptive_parse(const char *encoded,
                                       argon2_adaptive_envelope *envelope);

/* Audit ring. */
typedef enum argon2_adaptive_audit_kind {
    ARGON2_ADAPTIVE_AUDIT_INIT = 0,
    ARGON2_ADAPTIVE_AUDIT_PARAM_CHANGE = 1,
    ARGON2_ADAPTIVE_AUDIT_OVERLOAD = 2,
    ARGON2_ADAPTIVE_AUDIT_RECOVERED = 3
} argon2_adaptive_audit_kind;

typedef struct argon2_adaptive_audit_event {
    argon2_adaptive_audit_kind kind;
    int policy_version;
    int format_version;
    argon2_adaptive_tier tier;
    argon2_adaptive_tier old_tier;
    argon2_adaptive_tier new_tier;
    argon2_adaptive_params params;
    argon2_adaptive_params old_params;
    argon2_adaptive_params new_params;
    uint32_t active;
    int has_load1;
    double load1;
    int overload;
    char timestamp[32];
    char trigger[24];
    char reason[160];
} argon2_adaptive_audit_event;

ARGON2_PUBLIC size_t
argon2_adaptive_audit_count(const argon2_adaptive_controller *controller);
ARGON2_PUBLIC int
argon2_adaptive_audit_get(const argon2_adaptive_controller *controller,
                          size_t index, argon2_adaptive_audit_event *event);

/*
 * Process-wide default controller, lazily initialised from
 * argon2_adaptive_default_config() (override with
 * argon2_adaptive_set_default_config() before first use).
 */
ARGON2_PUBLIC int
argon2_adaptive_set_default_config(const argon2_adaptive_config *config);
ARGON2_PUBLIC argon2_adaptive_controller *
argon2_adaptive_default_controller(void);
ARGON2_PUBLIC void argon2_adaptive_default_shutdown(void);

ARGON2_PUBLIC int argon2_adaptive_login_hash(const void *pwd, size_t pwdlen,
                                             char *encoded, size_t encodedlen);
ARGON2_PUBLIC int argon2_adaptive_login_verify(const char *encoded,
                                               const void *pwd, size_t pwdlen);

#ifdef __cplusplus
}
#endif

#endif /* ARGON2_ADAPTIVE_H */
