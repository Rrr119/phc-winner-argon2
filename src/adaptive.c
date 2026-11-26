/*
 * Adaptive Argon2 controller: load based parameter selection, versioned
 * envelope encoding and JSON-lines audit trail.
 *
 * See include/argon2_adaptive.h for the envelope format and API.
 */

#if defined(__linux__) || defined(__GLIBC__)
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include "argon2.h"
#include "argon2_adaptive.h"

#ifndef ARGON2_NO_THREADS
#include <pthread.h>
#endif

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

struct argon2_adaptive_controller {
    argon2_adaptive_config config;
    char *audit_path;
    FILE *audit_fp;
#ifndef ARGON2_NO_THREADS
    pthread_mutex_t lock;
    int lock_initialised;
#endif
    uint32_t active;
    argon2_adaptive_tier tier;
    int overload;

    argon2_adaptive_audit_event *ring;
    size_t ring_capacity;
    size_t ring_total;
};

static void controller_lock(argon2_adaptive_controller *c) {
#ifndef ARGON2_NO_THREADS
    if (c->lock_initialised) {
        (void)pthread_mutex_lock(&c->lock);
    }
#else
    (void)c;
#endif
}

static void controller_unlock(argon2_adaptive_controller *c) {
#ifndef ARGON2_NO_THREADS
    if (c->lock_initialised) {
        (void)pthread_mutex_unlock(&c->lock);
    }
#else
    (void)c;
#endif
}

ARGON2_PUBLIC const char *argon2_adaptive_tier_name(argon2_adaptive_tier tier) {
    switch (tier) {
        case ARGON2_ADAPTIVE_TIER_LOW:
            return "low";
        case ARGON2_ADAPTIVE_TIER_MEDIUM:
            return "medium";
        case ARGON2_ADAPTIVE_TIER_HIGH:
            return "high";
        default:
            return "unknown";
    }
}

ARGON2_PUBLIC void
argon2_adaptive_default_config(argon2_adaptive_config *config) {
    if (config == NULL) {
        return;
    }
    memset(config, 0, sizeof(*config));
    config->policy_version = ARGON2_ADAPTIVE_POLICY_VERSION;
    config->type = Argon2_id;
    config->salt_length = 16;
    config->hash_length = 32;

    config->medium_threshold = 8;
    config->high_threshold = 32;
    config->critical_threshold = 64;

    /* OWASP-style baseline; memory in KiB. */
    config->low.t_cost = 3;
    config->low.m_cost = 65536;
    config->low.parallelism = 1;

    config->medium.t_cost = 2;
    config->medium.m_cost = 32768;
    config->medium.parallelism = 1;

    config->high.t_cost = 2;
    config->high.m_cost = 19456;
    config->high.parallelism = 1;

    config->floor.t_cost = 1;
    config->floor.m_cost = 19456;
    config->floor.parallelism = 1;

    config->audit_path = NULL;
    config->audit_ring_capacity = ARGON2_ADAPTIVE_AUDIT_RING_DEFAULT;
    config->use_load_average = 1;
    config->load1_provider = NULL;
}

ARGON2_PUBLIC void
argon2_adaptive_test_config(argon2_adaptive_config *config) {
    if (config == NULL) {
        return;
    }
    argon2_adaptive_default_config(config);

    /* Deterministic concurrency bands exercised by the acceptance suite. */
    config->medium_threshold = 4;
    config->high_threshold = 16;
    config->critical_threshold = 64;

    /* Tiny fast profiles; work(t*m) drops 768 -> 256 -> 64. */
    config->low.t_cost = 3;
    config->low.m_cost = 256;
    config->low.parallelism = 2;

    config->medium.t_cost = 2;
    config->medium.m_cost = 128;
    config->medium.parallelism = 1;

    config->high.t_cost = 1;
    config->high.m_cost = 64;
    config->high.parallelism = 1;

    config->floor.t_cost = 1;
    config->floor.m_cost = 64;
    config->floor.parallelism = 1;
}

ARGON2_PUBLIC int
argon2_adaptive_clamp_params(const argon2_adaptive_config *config,
                             argon2_adaptive_params *params) {
    argon2_adaptive_params floor;

    if (params == NULL || config == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    floor = config->floor;

    if (floor.t_cost < ARGON2_MIN_TIME) {
        floor.t_cost = ARGON2_MIN_TIME;
    }
    if (floor.parallelism < ARGON2_MIN_LANES) {
        floor.parallelism = ARGON2_MIN_LANES;
    }
    if (floor.m_cost < ARGON2_MIN_MEMORY) {
        floor.m_cost = ARGON2_MIN_MEMORY;
    }

    if (params->t_cost < floor.t_cost) {
        params->t_cost = floor.t_cost;
    }
    if (params->m_cost < floor.m_cost) {
        params->m_cost = floor.m_cost;
    }
    if (params->parallelism < floor.parallelism) {
        params->parallelism = floor.parallelism;
    }
    /* Argon2 requires m_cost >= 8 * lanes. */
    if (params->m_cost < 8u * params->parallelism) {
        params->m_cost = 8u * params->parallelism;
    }
    return ARGON2_OK;
}

static argon2_adaptive_tier
tier_for_active(const argon2_adaptive_config *config, uint32_t active) {
    if (active >= config->high_threshold) {
        return ARGON2_ADAPTIVE_TIER_HIGH;
    }
    if (active >= config->medium_threshold) {
        return ARGON2_ADAPTIVE_TIER_MEDIUM;
    }
    return ARGON2_ADAPTIVE_TIER_LOW;
}

static void current_params_locked(const argon2_adaptive_controller *c,
                                  argon2_adaptive_params *params) {
    *params = c->config.low;
    if (c->tier == ARGON2_ADAPTIVE_TIER_MEDIUM) {
        *params = c->config.medium;
    } else if (c->tier == ARGON2_ADAPTIVE_TIER_HIGH) {
        *params = c->config.high;
    }
    (void)argon2_adaptive_clamp_params(&c->config, params);
}

static void timestamp_now(char *out, size_t outlen) {
    time_t now;
    struct tm tm_store;
    struct tm *tm_ptr;

    if (out == NULL || outlen == 0) {
        return;
    }
    out[0] = '\0';
    now = time(NULL);
    tm_ptr = gmtime_r(&now, &tm_store);
    if (tm_ptr == NULL) {
        tm_ptr = gmtime(&now);
    }
    if (tm_ptr != NULL) {
        (void)strftime(out, outlen, "%Y-%m-%dT%H:%M:%SZ", tm_ptr);
    }
    if (out[0] == '\0') {
        (void)snprintf(out, outlen, "1970-01-01T00:00:00Z");
    }
}

static double sample_load1(const argon2_adaptive_config *config, int *available) {
    *available = 0;
    if (config->load1_provider != NULL) {
        double value = config->load1_provider();
        if (!isnan(value) && value >= 0.0) {
            *available = 1;
            return value;
        }
        return 0.0;
    }
#if defined(__linux__) || defined(__GLIBC__) || defined(__APPLE__)
    if (config->use_load_average) {
        double loads[3];
        if (getloadavg(loads, 3) == 3) {
            *available = 1;
            return loads[0];
        }
    }
#else
    (void)config;
#endif
    return 0.0;
}

static void json_append_load(char *line, size_t line_size, size_t *used,
                             int has_load, double load1) {
    int written;
    if (has_load) {
        written = snprintf(line + *used, line_size - *used,
                           "\"load1\":%.2f", load1);
    } else {
        written = snprintf(line + *used, line_size - *used, "\"load1\":null");
    }
    if (written > 0 && (size_t)written < line_size - *used) {
        *used += (size_t)written;
    }
}

/* Call with controller lock held. */
static void audit_emit_locked(argon2_adaptive_controller *c,
                              argon2_adaptive_audit_kind kind,
                              const argon2_adaptive_tier *old_tier,
                              const argon2_adaptive_tier *new_tier,
                              uint32_t active, int has_load, double load1,
                              const char *trigger, const char *reason) {
    argon2_adaptive_audit_event event;
    char line[1024];
    size_t used = 0;
    int written;

    memset(&event, 0, sizeof(event));
    event.kind = kind;
    event.policy_version = c->config.policy_version;
    event.format_version = ARGON2_ADAPTIVE_FMT_VERSION;
    event.tier = c->tier;
    event.active = active;
    event.has_load1 = has_load;
    event.load1 = load1;
    event.overload = c->overload;
    if (old_tier != NULL) {
        event.old_tier = *old_tier;
        event.old_params = c->config.low;
        if (*old_tier == ARGON2_ADAPTIVE_TIER_MEDIUM) {
            event.old_params = c->config.medium;
        } else if (*old_tier == ARGON2_ADAPTIVE_TIER_HIGH) {
            event.old_params = c->config.high;
        }
        (void)argon2_adaptive_clamp_params(&c->config, &event.old_params);
    }
    if (new_tier != NULL) {
        event.new_tier = *new_tier;
        event.new_params = c->config.low;
        if (*new_tier == ARGON2_ADAPTIVE_TIER_MEDIUM) {
            event.new_params = c->config.medium;
        } else if (*new_tier == ARGON2_ADAPTIVE_TIER_HIGH) {
            event.new_params = c->config.high;
        }
        (void)argon2_adaptive_clamp_params(&c->config, &event.new_params);
    }
    event.params = event.new_params;
    if (kind == ARGON2_ADAPTIVE_AUDIT_INIT) {
        event.params = c->config.low;
        current_params_locked(c, &event.params);
        event.tier = c->tier;
    } else if (kind == ARGON2_ADAPTIVE_AUDIT_OVERLOAD ||
               kind == ARGON2_ADAPTIVE_AUDIT_RECOVERED) {
        event.format_version = 0; /* omitted from these records */
    }
    if (trigger != NULL) {
        (void)strncpy(event.trigger, trigger, sizeof(event.trigger) - 1);
    }
    if (reason != NULL) {
        (void)strncpy(event.reason, reason, sizeof(event.reason) - 1);
    }
    timestamp_now(event.timestamp, sizeof(event.timestamp));

    if (c->ring != NULL && c->ring_capacity > 0) {
        size_t slot = c->ring_total % c->ring_capacity;
        c->ring[slot] = event;
        c->ring_total++;
    }

    if (c->audit_fp == NULL) {
        return;
    }

    written = snprintf(line, sizeof(line),
                       "{\"ts\":\"%s\",\"event\":\"", event.timestamp);
    used = (written > 0) ? (size_t)written : 0;

    if (kind == ARGON2_ADAPTIVE_AUDIT_INIT) {
        written = snprintf(line + used, sizeof(line) - used,
                           "init\",\"policy_ver\":%d,\"fmt_ver\":%d,"
                           "\"tier\":\"%s\",\"params\":"
                           "{\"t\":%u,\"m\":%u,\"p\":%u},",
                           event.policy_version, event.format_version,
                           argon2_adaptive_tier_name(c->tier),
                           event.params.t_cost, event.params.m_cost,
                           event.params.parallelism);
    } else if (kind == ARGON2_ADAPTIVE_AUDIT_PARAM_CHANGE) {
        written = snprintf(
            line + used, sizeof(line) - used,
            "param_change\",\"policy_ver\":%d,\"fmt_ver\":%d,"
            "\"old_tier\":\"%s\",\"new_tier\":\"%s\","
            "\"old\":{\"t\":%u,\"m\":%u,\"p\":%u},"
            "\"new\":{\"t\":%u,\"m\":%u,\"p\":%u},",
            event.policy_version, event.format_version,
            argon2_adaptive_tier_name(event.old_tier),
            argon2_adaptive_tier_name(event.new_tier),
            event.old_params.t_cost, event.old_params.m_cost,
            event.old_params.parallelism, event.new_params.t_cost,
            event.new_params.m_cost, event.new_params.parallelism);
    } else if (kind == ARGON2_ADAPTIVE_AUDIT_OVERLOAD) {
        written = snprintf(line + used, sizeof(line) - used,
                           "overload\",\"policy_ver\":%d,",
                           event.policy_version);
    } else {
        written = snprintf(line + used, sizeof(line) - used,
                           "recovered\",\"policy_ver\":%d,",
                           event.policy_version);
    }
    if (written > 0 && (size_t)written < sizeof(line) - used) {
        used += (size_t)written;
    }

    written = snprintf(line + used, sizeof(line) - used,
                       "\"active\":%u,", active);
    if (written > 0 && (size_t)written < sizeof(line) - used) {
        used += (size_t)written;
    }
    json_append_load(line, sizeof(line), &used, has_load, load1);

    written = snprintf(line + used, sizeof(line) - used,
                       ",\"overload\":%d,\"trigger\":\"%s\",\"reason\":\"%s\"}\n",
                       c->overload, event.trigger, event.reason);
    if (written > 0 && (size_t)written < sizeof(line) - used) {
        used += (size_t)written;
    }

    if (used < sizeof(line)) {
        (void)fwrite(line, 1, used, c->audit_fp);
        (void)fflush(c->audit_fp);
    }
}

/* Call with controller lock held. */
static int reevaluate_locked(argon2_adaptive_controller *c, uint32_t active,
                             int has_load, double load1,
                             const char *trigger) {
    argon2_adaptive_tier new_tier;
    const char *reason;

    c->active = active;

    if (active >= c->config.critical_threshold) {
        if (!c->overload) {
            c->overload = 1;
            audit_emit_locked(
                c, ARGON2_ADAPTIVE_AUDIT_OVERLOAD, NULL, NULL, active,
                has_load, load1, trigger,
                "critical concurrency: keeping security floor and "
                "requesting load shedding/queueing");
        }
    } else if (c->overload) {
        c->overload = 0;
        audit_emit_locked(c, ARGON2_ADAPTIVE_AUDIT_RECOVERED, NULL, NULL,
                          active, has_load, load1, trigger,
                          "concurrency back below critical threshold");
    }

    new_tier = tier_for_active(&c->config, active);
    if (new_tier != c->tier) {
        argon2_adaptive_tier old_tier = c->tier;
        reason = (new_tier > old_tier)
                     ? "pressure up: reducing argon2 cost within "
                       "security floor"
                     : "pressure down: restoring stronger argon2 parameters";
        c->tier = new_tier;
        audit_emit_locked(c, ARGON2_ADAPTIVE_AUDIT_PARAM_CHANGE, &old_tier,
                          &new_tier, active, has_load, load1, trigger, reason);
    }
    return ARGON2_OK;
}

ARGON2_PUBLIC int argon2_adaptive_observe(argon2_adaptive_controller *controller,
                                          uint32_t active, double load1) {
    int has_load = (load1 >= 0.0 && !isnan(load1));
    if (controller == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    controller_lock(controller);
    (void)reevaluate_locked(controller, active, has_load,
                            has_load ? load1 : 0.0, "manual_sample");
    controller_unlock(controller);
    return ARGON2_OK;
}

ARGON2_PUBLIC int
argon2_adaptive_evaluate(argon2_adaptive_controller *controller) {
    double load1 = 0.0;
    int has_load = 0;
    uint32_t active;

    if (controller == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    controller_lock(controller);
    active = controller->active;
    load1 = sample_load1(&controller->config, &has_load);
    (void)reevaluate_locked(controller, active, has_load, load1, "evaluate");
    controller_unlock(controller);
    return ARGON2_OK;
}

ARGON2_PUBLIC int
argon2_adaptive_login_start(argon2_adaptive_controller *controller) {
    double load1 = 0.0;
    int has_load = 0;
    uint32_t active;

    if (controller == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    controller_lock(controller);
    active = controller->active + 1;
    load1 = sample_load1(&controller->config, &has_load);
    (void)reevaluate_locked(controller, active, has_load, load1, "login_start");
    controller_unlock(controller);
    return ARGON2_OK;
}

ARGON2_PUBLIC int
argon2_adaptive_login_end(argon2_adaptive_controller *controller) {
    double load1 = 0.0;
    int has_load = 0;
    uint32_t active;

    if (controller == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    controller_lock(controller);
    active = (controller->active > 0) ? controller->active - 1 : 0;
    load1 = sample_load1(&controller->config, &has_load);
    (void)reevaluate_locked(controller, active, has_load, load1, "login_end");
    controller_unlock(controller);
    return ARGON2_OK;
}

ARGON2_PUBLIC uint32_t
argon2_adaptive_active(const argon2_adaptive_controller *controller) {
    uint32_t value = 0;
    if (controller == NULL) {
        return 0;
    }
    controller_lock((argon2_adaptive_controller *)controller);
    value = controller->active;
    controller_unlock((argon2_adaptive_controller *)controller);
    return value;
}

ARGON2_PUBLIC argon2_adaptive_tier
argon2_adaptive_current_tier(const argon2_adaptive_controller *controller) {
    argon2_adaptive_tier tier = ARGON2_ADAPTIVE_TIER_LOW;
    if (controller == NULL) {
        return tier;
    }
    controller_lock((argon2_adaptive_controller *)controller);
    tier = controller->tier;
    controller_unlock((argon2_adaptive_controller *)controller);
    return tier;
}

ARGON2_PUBLIC int
argon2_adaptive_overload(const argon2_adaptive_controller *controller) {
    int value = 0;
    if (controller == NULL) {
        return 0;
    }
    controller_lock((argon2_adaptive_controller *)controller);
    value = controller->overload;
    controller_unlock((argon2_adaptive_controller *)controller);
    return value;
}

ARGON2_PUBLIC void
argon2_adaptive_current_params(const argon2_adaptive_controller *controller,
                               argon2_adaptive_params *params) {
    if (params == NULL) {
        return;
    }
    memset(params, 0, sizeof(*params));
    if (controller == NULL) {
        return;
    }
    controller_lock((argon2_adaptive_controller *)controller);
    current_params_locked(controller, params);
    controller_unlock((argon2_adaptive_controller *)controller);
}

ARGON2_PUBLIC size_t
argon2_adaptive_audit_count(const argon2_adaptive_controller *controller) {
    size_t count = 0;
    if (controller == NULL) {
        return 0;
    }
    controller_lock((argon2_adaptive_controller *)controller);
    count = controller->ring_total < controller->ring_capacity
                ? controller->ring_total
                : controller->ring_capacity;
    controller_unlock((argon2_adaptive_controller *)controller);
    return count;
}

ARGON2_PUBLIC int
argon2_adaptive_audit_get(const argon2_adaptive_controller *controller,
                          size_t index, argon2_adaptive_audit_event *event) {
    size_t count;
    size_t slot;

    if (controller == NULL || event == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    controller_lock((argon2_adaptive_controller *)controller);
    count = controller->ring_total < controller->ring_capacity
                ? controller->ring_total
                : controller->ring_capacity;
    if (index >= count || controller->ring == NULL) {
        controller_unlock((argon2_adaptive_controller *)controller);
        return ARGON2_INCORRECT_PARAMETER;
    }
    if (controller->ring_total <= controller->ring_capacity) {
        slot = index;
    } else {
        slot = (controller->ring_total % controller->ring_capacity + index) %
               controller->ring_capacity;
    }
    *event = controller->ring[slot];
    controller_unlock((argon2_adaptive_controller *)controller);
    return ARGON2_OK;
}

static int generate_salt(uint8_t *salt, uint32_t length) {
    FILE *urandom;
    uint32_t i;
    unsigned int seed;

    urandom = fopen("/dev/urandom", "rb");
    if (urandom != NULL) {
        size_t got = fread(salt, 1, length, urandom);
        (void)fclose(urandom);
        if (got == length) {
            return ARGON2_OK;
        }
    }

    seed = (unsigned int)time(NULL) ^ (unsigned int)getpid() ^
           (unsigned int)(uintptr_t)salt;
    for (i = 0; i < length; i++) {
        seed = seed * 1103515245u + 12345u;
        salt[i] = (uint8_t)((seed >> 16) & 0xff);
    }
    return ARGON2_OK;
}

ARGON2_PUBLIC int argon2_adaptive_init(argon2_adaptive_controller **out,
                                       const argon2_adaptive_config *config) {
    argon2_adaptive_controller *controller;
    argon2_adaptive_config local;
    int rc;

    if (out == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    *out = NULL;

    controller = (argon2_adaptive_controller *)calloc(1, sizeof(*controller));
    if (controller == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    if (config == NULL) {
        argon2_adaptive_default_config(&local);
    } else {
        local = *config;
    }
    if (local.policy_version < 1) {
        local.policy_version = ARGON2_ADAPTIVE_POLICY_VERSION;
    }
    if (local.salt_length < ARGON2_MIN_SALT_LENGTH) {
        local.salt_length = ARGON2_MIN_SALT_LENGTH;
    }
    if (local.hash_length < ARGON2_MIN_OUTLEN) {
        local.hash_length = 32;
    }
    if (local.audit_ring_capacity == 0) {
        local.audit_ring_capacity = ARGON2_ADAPTIVE_AUDIT_RING_DEFAULT;
    }
    if (local.medium_threshold == 0) {
        local.medium_threshold = 1;
    }
    if (local.high_threshold < local.medium_threshold) {
        local.high_threshold = local.medium_threshold;
    }
    if (local.critical_threshold < local.high_threshold) {
        local.critical_threshold = local.high_threshold;
    }

    controller->config = local;
    controller->tier = ARGON2_ADAPTIVE_TIER_LOW;
    controller->active = 0;
    controller->overload = 0;
    controller->ring_capacity = local.audit_ring_capacity;
    controller->ring = (argon2_adaptive_audit_event *)calloc(
        controller->ring_capacity, sizeof(argon2_adaptive_audit_event));
    if (controller->ring == NULL) {
        argon2_adaptive_destroy(controller);
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    if (local.audit_path != NULL) {
        controller->audit_path = strdup(local.audit_path);
        if (controller->audit_path == NULL) {
            argon2_adaptive_destroy(controller);
            return ARGON2_MEMORY_ALLOCATION_ERROR;
        }
        controller->audit_fp = fopen(controller->audit_path, "a");
        if (controller->audit_fp == NULL) {
            argon2_adaptive_destroy(controller);
            return ARGON2_ADAPTIVE_AUDIT_OPEN_FAIL;
        }
    }

#ifndef ARGON2_NO_THREADS
    if (pthread_mutex_init(&controller->lock, NULL) == 0) {
        controller->lock_initialised = 1;
    }
#endif

    controller_lock(controller);
    audit_emit_locked(controller, ARGON2_ADAPTIVE_AUDIT_INIT, NULL, NULL, 0, 0,
                      0.0, "init",
                      "adaptive argon2 controller initialised");
    controller_unlock(controller);

    *out = controller;
    rc = ARGON2_OK;
    return rc;
}

ARGON2_PUBLIC void
argon2_adaptive_destroy(argon2_adaptive_controller *controller) {
    if (controller == NULL) {
        return;
    }
#ifndef ARGON2_NO_THREADS
    if (controller->lock_initialised) {
        (void)pthread_mutex_destroy(&controller->lock);
        controller->lock_initialised = 0;
    }
#endif
    if (controller->audit_fp != NULL) {
        (void)fclose(controller->audit_fp);
        controller->audit_fp = NULL;
    }
    free(controller->audit_path);
    free(controller->ring);
    free(controller);
}

ARGON2_PUBLIC int
argon2_adaptive_is_envelope(const char *encoded) {
    if (encoded == NULL) {
        return 0;
    }
    return strncmp(encoded, ARGON2_ADAPTIVE_ENVELOPE_MAGIC,
                   strlen(ARGON2_ADAPTIVE_ENVELOPE_MAGIC)) == 0;
}

ARGON2_PUBLIC int argon2_adaptive_parse(const char *encoded,
                                       argon2_adaptive_envelope *envelope) {
    unsigned int format_version = 0;
    unsigned int policy_version = 0;
    unsigned int tier = 0;
    unsigned int m_cost = 0;
    unsigned int t_cost = 0;
    unsigned int parallelism = 0;
    const char *double_sep;
    const char *phc;
    int matched;

    if (encoded == NULL || envelope == NULL) {
        return ARGON2_INCORRECT_PARAMETER;
    }
    memset(envelope, 0, sizeof(*envelope));

    if (!argon2_adaptive_is_envelope(encoded)) {
        return ARGON2_DECODING_FAIL;
    }

    matched = sscanf(encoded,
                     "$a2ad$v=%u$pv=%u$tier=%u$m=%u,t=%u,p=%u",
                     &format_version, &policy_version, &tier, &m_cost,
                     &t_cost, &parallelism);
    if (matched != 6) {
        return ARGON2_DECODING_FAIL;
    }
    if (format_version != (unsigned int)ARGON2_ADAPTIVE_FMT_VERSION ||
        tier > (unsigned int)ARGON2_ADAPTIVE_TIER_HIGH || m_cost == 0 ||
        t_cost == 0 || parallelism == 0) {
        return ARGON2_DECODING_FAIL;
    }

    double_sep = strstr(encoded, "$$");
    if (double_sep == NULL) {
        return ARGON2_DECODING_FAIL;
    }
    phc = double_sep + 1; /* second '$' starts the embedded PHC */
    if (strncmp(phc, "$argon2", 7) != 0) {
        return ARGON2_DECODING_FAIL;
    }

    envelope->format_version = (int)format_version;
    envelope->policy_version = (int)policy_version;
    envelope->tier = (argon2_adaptive_tier)tier;
    envelope->params.m_cost = (uint32_t)m_cost;
    envelope->params.t_cost = (uint32_t)t_cost;
    envelope->params.parallelism = (uint32_t)parallelism;

    (void)strncpy(envelope->phc, phc, sizeof(envelope->phc) - 1);
    envelope->phc[sizeof(envelope->phc) - 1] = '\0';
    return ARGON2_OK;
}

static argon2_type phc_type(const char *phc) {
    if (strncmp(phc, "$argon2id$", 10) == 0) {
        return Argon2_id;
    }
    if (strncmp(phc, "$argon2i$", 9) == 0) {
        return Argon2_i;
    }
    if (strncmp(phc, "$argon2d$", 9) == 0) {
        return Argon2_d;
    }
    return (argon2_type)-1;
}

static int verify_phc(const char *phc, const void *pwd, size_t pwdlen) {
    argon2_type type = phc_type(phc);
    if ((int)type < 0) {
        return ARGON2_INCORRECT_TYPE;
    }
    return argon2_verify(phc, pwd, pwdlen, type);
}

static int phc_params(const char *phc, argon2_adaptive_params *params) {
    const char *marker = strstr(phc, "$m=");
    unsigned int m_cost = 0;
    unsigned int t_cost = 0;
    unsigned int parallelism = 0;
    int matched;

    if (marker == NULL) {
        return ARGON2_DECODING_FAIL;
    }
    matched = sscanf(marker, "$m=%u,t=%u,p=%u", &m_cost, &t_cost,
                     &parallelism);
    if (matched != 3) {
        return ARGON2_DECODING_FAIL;
    }
    params->m_cost = (uint32_t)m_cost;
    params->t_cost = (uint32_t)t_cost;
    params->parallelism = (uint32_t)parallelism;
    return ARGON2_OK;
}

ARGON2_PUBLIC int
argon2_adaptive_hash_encoded(argon2_adaptive_controller *controller,
                             const void *pwd, size_t pwdlen, char *encoded,
                             size_t encodedlen) {
    argon2_adaptive_params params;
    argon2_adaptive_tier tier;
    int policy_version;
    argon2_type type;
    uint32_t salt_length;
    uint32_t hash_length;
    uint8_t salt[64];
    char phc[ARGON2_ADAPTIVE_PHC_MAX];
    int rc;
    int written;

    if (controller == NULL || encoded == NULL || encodedlen == 0) {
        return ARGON2_INCORRECT_PARAMETER;
    }

    controller_lock(controller);
    current_params_locked(controller, &params);
    tier = controller->tier;
    policy_version = controller->config.policy_version;
    type = controller->config.type;
    salt_length = controller->config.salt_length;
    hash_length = controller->config.hash_length;
    controller_unlock(controller);

    if (salt_length > sizeof(salt)) {
        salt_length = sizeof(salt);
    }
    rc = generate_salt(salt, salt_length);
    if (rc != ARGON2_OK) {
        return rc;
    }

    rc = argon2_hash(params.t_cost, params.m_cost, params.parallelism, pwd,
                     pwdlen, salt, salt_length, NULL, hash_length, phc,
                     sizeof(phc), type, ARGON2_VERSION_NUMBER);
    if (rc != ARGON2_OK) {
        return rc;
    }

    written = snprintf(
        encoded, encodedlen,
        "$a2ad$v=%d$pv=%d$tier=%d$m=%u,t=%u,p=%u$%s",
        ARGON2_ADAPTIVE_FMT_VERSION, policy_version, (int)tier,
        params.m_cost, params.t_cost, params.parallelism, phc);
    if (written < 0 || (size_t)written >= encodedlen) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }
    return ARGON2_OK;
}

ARGON2_PUBLIC int
argon2_adaptive_verify(argon2_adaptive_controller *controller,
                       const char *encoded, const void *pwd, size_t pwdlen) {
    argon2_adaptive_envelope envelope;
    argon2_adaptive_params phc_cost;
    int rc;

    (void)controller;
    if (encoded == NULL) {
        return ARGON2_DECODING_FAIL;
    }

    if (argon2_adaptive_is_envelope(encoded)) {
        rc = argon2_adaptive_parse(encoded, &envelope);
        if (rc != ARGON2_OK) {
            return rc;
        }
        rc = phc_params(envelope.phc, &phc_cost);
        if (rc != ARGON2_OK) {
            return rc;
        }
        if (phc_cost.m_cost != envelope.params.m_cost ||
            phc_cost.t_cost != envelope.params.t_cost ||
            phc_cost.parallelism != envelope.params.parallelism) {
            return ARGON2_DECODING_FAIL;
        }
        return verify_phc(envelope.phc, pwd, pwdlen);
    }

    return verify_phc(encoded, pwd, pwdlen);
}

ARGON2_PUBLIC int
argon2_adaptive_needs_rehash(argon2_adaptive_controller *controller,
                             const char *encoded) {
    argon2_adaptive_envelope envelope;
    argon2_adaptive_config fallback;
    const argon2_adaptive_config *config;
    int policy_version;
    int rc;

    if (encoded == NULL) {
        return -1;
    }
    if (!argon2_adaptive_is_envelope(encoded)) {
        return 1;
    }
    rc = argon2_adaptive_parse(encoded, &envelope);
    if (rc != ARGON2_OK) {
        return -1;
    }

    if (controller != NULL) {
        config = &controller->config;
        policy_version = config->policy_version;
    } else {
        argon2_adaptive_default_config(&fallback);
        config = &fallback;
        policy_version = ARGON2_ADAPTIVE_POLICY_VERSION;
    }

    if (envelope.format_version < ARGON2_ADAPTIVE_FMT_VERSION) {
        return 1;
    }
    if (envelope.policy_version < policy_version) {
        return 1;
    }
    if (envelope.params.t_cost < config->floor.t_cost ||
        envelope.params.m_cost < config->floor.m_cost ||
        envelope.params.parallelism < config->floor.parallelism) {
        return 1;
    }
    return 0;
}

/* Process-wide default controller --------------------------------------- */

#ifndef ARGON2_NO_THREADS
static pthread_mutex_t default_controller_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
static argon2_adaptive_controller *default_controller_instance = NULL;
static int default_config_override_set = 0;
static argon2_adaptive_config default_config_override;

ARGON2_PUBLIC int
argon2_adaptive_set_default_config(const argon2_adaptive_config *config) {
#ifndef ARGON2_NO_THREADS
    (void)pthread_mutex_lock(&default_controller_lock);
#endif
    if (default_controller_instance != NULL) {
#ifndef ARGON2_NO_THREADS
        (void)pthread_mutex_unlock(&default_controller_lock);
#endif
        return ARGON2_INCORRECT_PARAMETER;
    }
    if (config != NULL) {
        default_config_override = *config;
        default_config_override_set = 1;
    } else {
        default_config_override_set = 0;
    }
#ifndef ARGON2_NO_THREADS
    (void)pthread_mutex_unlock(&default_controller_lock);
#endif
    return ARGON2_OK;
}

ARGON2_PUBLIC argon2_adaptive_controller *
argon2_adaptive_default_controller(void) {
    argon2_adaptive_controller *instance = NULL;

#ifndef ARGON2_NO_THREADS
    (void)pthread_mutex_lock(&default_controller_lock);
#endif
    if (default_controller_instance == NULL) {
        const argon2_adaptive_config *cfg =
            default_config_override_set ? &default_config_override : NULL;
        if (argon2_adaptive_init(&default_controller_instance, cfg) !=
            ARGON2_OK) {
            default_controller_instance = NULL;
        }
    }
    instance = default_controller_instance;
#ifndef ARGON2_NO_THREADS
    (void)pthread_mutex_unlock(&default_controller_lock);
#endif
    return instance;
}

ARGON2_PUBLIC void argon2_adaptive_default_shutdown(void) {
#ifndef ARGON2_NO_THREADS
    (void)pthread_mutex_lock(&default_controller_lock);
#endif
    if (default_controller_instance != NULL) {
        argon2_adaptive_destroy(default_controller_instance);
        default_controller_instance = NULL;
    }
    default_config_override_set = 0;
#ifndef ARGON2_NO_THREADS
    (void)pthread_mutex_unlock(&default_controller_lock);
#endif
}

#if defined(__GNUC__)
static void argon2_adaptive_default_cleanup(void)
    __attribute__((destructor));
static void argon2_adaptive_default_cleanup(void) {
    argon2_adaptive_default_shutdown();
}
#endif

ARGON2_PUBLIC int argon2_adaptive_login_hash(const void *pwd, size_t pwdlen,
                                             char *encoded,
                                             size_t encodedlen) {
    argon2_adaptive_controller *c = argon2_adaptive_default_controller();
    int rc;
    if (c == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    (void)argon2_adaptive_login_start(c);
    rc = argon2_adaptive_hash_encoded(c, pwd, pwdlen, encoded, encodedlen);
    (void)argon2_adaptive_login_end(c);
    return rc;
}

ARGON2_PUBLIC int
argon2_adaptive_login_verify(const char *encoded, const void *pwd,
                             size_t pwdlen) {
    argon2_adaptive_controller *c = argon2_adaptive_default_controller();
    int rc;
    if (c == NULL) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    (void)argon2_adaptive_login_start(c);
    rc = argon2_adaptive_verify(c, encoded, pwd, pwdlen);
    (void)argon2_adaptive_login_end(c);
    return rc;
}
