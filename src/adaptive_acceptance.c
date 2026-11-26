/*
 * Acceptance suite for adaptive Argon2.
 *
 * Exercises:
 *   1. deterministic three-pressure banding (1 / 8 / 32) plus critical load
 *   2. security-floor clamping
 *   3. real pthread concurrency rounds at 1 / 8 / 32 in-flight logins
 *   4. versioned envelope format and legacy hash compatibility
 *   5. in-memory audit ring and JSON-lines audit file
 *
 * Usage: adaptive_acceptance [audit-log-path]
 *
 * Exit status is 0 only when every check passes.
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

#include "argon2.h"
#include "argon2_adaptive.h"

#ifndef ARGON2_NO_THREADS
#include <pthread.h>
#endif

static int checks_total = 0;
static int checks_failed = 0;

static void check(int condition, const char *label) {
    checks_total++;
    if (condition) {
        printf("  [ok]   %s\n", label);
    } else {
        checks_failed++;
        printf("  [FAIL] %s\n", label);
    }
}

static const char *const TEST_PASSWORD = "correct horse battery staple";
static const size_t TEST_PASSWORD_LEN = 28;
static const char *const WRONG_PASSWORD = "wrong password";
static const size_t WRONG_PASSWORD_LEN = 14;

static int stock_verify(argon2_type type, const char *encoded,
                        const char *password, size_t password_len) {
    if (type == Argon2_i) {
        return argon2i_verify(encoded, password, password_len);
    }
    if (type == Argon2_d) {
        return argon2d_verify(encoded, password, password_len);
    }
    return argon2id_verify(encoded, password, password_len);
}

/* ------------------------------------------------------------------ */
/* Section 3: real pthread concurrency                                 */
/* ------------------------------------------------------------------ */

#ifndef ARGON2_NO_THREADS

typedef struct worker_result {
    int hash_ok;
    int verify_ok;
    int stock_ok;
    char encoded[ARGON2_ADAPTIVE_ENCODED_MAX];
} worker_result;

typedef struct worker_arg {
    argon2_adaptive_controller *controller;
    pthread_barrier_t *all_in;
    pthread_barrier_t *may_leave;
    worker_result *result;
} worker_arg;

static void *worker_main(void *pointer) {
    worker_arg *arg = (worker_arg *)pointer;
    worker_result *result = arg->result;

    if (argon2_adaptive_login_start(arg->controller) != ARGON2_OK) {
        return NULL;
    }

    (void)pthread_barrier_wait(arg->all_in);
    (void)pthread_barrier_wait(arg->may_leave);

    if (argon2_adaptive_hash_encoded(
            arg->controller, TEST_PASSWORD, TEST_PASSWORD_LEN,
            result->encoded, sizeof(result->encoded)) == ARGON2_OK) {
        result->hash_ok = 1;
        if (argon2_adaptive_verify(arg->controller, result->encoded,
                                   TEST_PASSWORD,
                                   TEST_PASSWORD_LEN) == ARGON2_OK) {
            result->verify_ok = 1;
        }
        if (argon2id_verify(result->encoded, TEST_PASSWORD,
                            TEST_PASSWORD_LEN) == ARGON2_OK) {
            result->stock_ok = 1;
        }
    }

    (void)argon2_adaptive_login_end(arg->controller);
    return NULL;
}

#define MAX_ROUND_WORKERS 32

static void run_concurrency_round(argon2_adaptive_controller *controller,
                                  int worker_count,
                                  argon2_adaptive_tier expected_tier) {
    pthread_t threads[MAX_ROUND_WORKERS];
    worker_arg args[MAX_ROUND_WORKERS];
    worker_result results[MAX_ROUND_WORKERS];
    pthread_barrier_t all_in;
    pthread_barrier_t may_leave;
    argon2_adaptive_tier tier;
    int barrier_rc;
    int i;
    int create_rc;

    printf("\n-- real concurrency round: %d in-flight logins --\n",
           worker_count);

    barrier_rc = pthread_barrier_init(&all_in, NULL,
                                      (unsigned int)worker_count + 1u);
    check(barrier_rc == 0, "barrier init (all_in)");
    barrier_rc = pthread_barrier_init(&may_leave, NULL,
                                      (unsigned int)worker_count + 1u);
    check(barrier_rc == 0, "barrier init (may_leave)");

    memset(results, 0, sizeof(results));
    memset(args, 0, sizeof(args));

    for (i = 0; i < worker_count; i++) {
        args[i].controller = controller;
        args[i].all_in = &all_in;
        args[i].may_leave = &may_leave;
        args[i].result = &results[i];
        create_rc = pthread_create(&threads[i], NULL, worker_main, &args[i]);
        check(create_rc == 0, "pthread_create worker");
    }

    (void)pthread_barrier_wait(&all_in);

    check((int)argon2_adaptive_active(controller) == worker_count,
          "gauge counts all in-flight workers");

    tier = argon2_adaptive_current_tier(controller);
    check(tier == expected_tier,
          "real concurrency selects expected pressure tier");
    printf("  active=%d -> tier=%s\n", worker_count,
           argon2_adaptive_tier_name(tier));

    (void)pthread_barrier_wait(&may_leave);

    for (i = 0; i < worker_count; i++) {
        (void)pthread_join(threads[i], NULL);
    }

    for (i = 0; i < worker_count; i++) {
        check(results[i].hash_ok, "worker adaptive hash succeeds");
        check(results[i].verify_ok, "worker adaptive verify succeeds");
        check(results[i].stock_ok,
              "stock argon2id_verify accepts versioned hash");
    }

    (void)pthread_barrier_destroy(&all_in);
    (void)pthread_barrier_destroy(&may_leave);
}

static void run_concurrency_section(argon2_adaptive_controller *controller) {
    /* Section 1 left an absolute sample of 1 active login; re-zero. */
    (void)argon2_adaptive_observe(controller, 0,
                                  ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    printf("\n[3/5] real pthread concurrency pressures ---\n");
    run_concurrency_round(controller, 1, ARGON2_ADAPTIVE_TIER_LOW);
    run_concurrency_round(controller, 8, ARGON2_ADAPTIVE_TIER_MEDIUM);
    run_concurrency_round(controller, 32, ARGON2_ADAPTIVE_TIER_HIGH);
}

#else  /* ARGON2_NO_THREADS */

static void run_concurrency_section(argon2_adaptive_controller *controller) {
    (void)argon2_adaptive_observe(controller, 0,
                                  ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    printf("\n[3/5] real pthread concurrency pressures "
           "(skipped: ARGON2_NO_THREADS) ---\n");
}

#endif /* ARGON2_NO_THREADS */

/* ------------------------------------------------------------------ */
/* Section 4: envelopes and legacy hashes                              */
/* ------------------------------------------------------------------ */

static void run_legacy_hash(const char *encoded, argon2_type type,
                            argon2_adaptive_controller *controller) {
    check(stock_verify(type, encoded, TEST_PASSWORD, TEST_PASSWORD_LEN) ==
              ARGON2_OK,
          "stock verify validates the same legacy hash");
    check(stock_verify(type, encoded, WRONG_PASSWORD, WRONG_PASSWORD_LEN) !=
              ARGON2_OK,
          "wrong password on legacy hash is rejected");
    check(argon2_adaptive_needs_rehash(controller, encoded) == 1,
          "legacy hash is flagged for transparent rehash");
}

static void run_envelope_tier(argon2_adaptive_controller *controller,
                              uint32_t pressure,
                              argon2_adaptive_tier expected_tier,
                              const argon2_adaptive_params *expected_params) {
    char encoded[ARGON2_ADAPTIVE_ENCODED_MAX];
    char tampered[ARGON2_ADAPTIVE_ENCODED_MAX];
    argon2_adaptive_envelope parsed;
    argon2_adaptive_tier tier;
    size_t length;
    int rc;

    (void)argon2_adaptive_observe(controller, pressure,
                                  ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);

    encoded[0] = '\0';
    rc = argon2_adaptive_hash_encoded(controller, TEST_PASSWORD,
                                     TEST_PASSWORD_LEN, encoded,
                                     sizeof(encoded));
    check(rc == ARGON2_OK, "adaptive envelope hash succeeds");

    check(argon2_adaptive_is_envelope(encoded) &&
              strncmp(encoded, "$a2ad$v=1$pv=1$", 15) == 0,
          "new hash carries the versioned envelope prefix");

    rc = argon2_adaptive_parse(encoded, &parsed);
    check(rc == ARGON2_OK, "envelope parses");

    check(rc == ARGON2_OK && parsed.format_version == 1 &&
              parsed.policy_version == 1,
          "envelope reports format and policy versions");

    check(rc == ARGON2_OK && parsed.tier == expected_tier,
          "envelope records the selecting tier");

    check(rc == ARGON2_OK &&
              parsed.params.m_cost == expected_params->m_cost &&
              parsed.params.t_cost == expected_params->t_cost &&
              parsed.params.parallelism == expected_params->parallelism,
          "envelope stores the exact applied m/t/p parameters");

    check(rc == ARGON2_OK &&
              strncmp(parsed.phc, "$argon2", 7) == 0 &&
              strstr(parsed.phc, "$m=") != NULL,
          "envelope embeds a stock PHC string");

    check(argon2_adaptive_verify(controller, encoded, TEST_PASSWORD,
                                 TEST_PASSWORD_LEN) == ARGON2_OK,
          "adaptive verify accepts new envelope hash");

    check(argon2_adaptive_verify(controller, encoded, WRONG_PASSWORD,
                                 WRONG_PASSWORD_LEN) != ARGON2_OK,
          "wrong password on envelope hash is rejected");

    check(argon2id_verify(encoded, TEST_PASSWORD, TEST_PASSWORD_LEN) ==
              ARGON2_OK,
          "existing argon2id_verify accepts new envelope hash");

    check(argon2_adaptive_needs_rehash(controller, encoded) == 0,
          "fresh envelope hash needs no rehash");

    (void)strncpy(tampered, encoded, sizeof(tampered) - 1);
    tampered[sizeof(tampered) - 1] = '\0';
    length = strlen(tampered);
    if (length > 0) {
        char *last_field = strrchr(tampered, '$');
        if (last_field != NULL && last_field[1] != '\0') {
            last_field++;
            last_field[0] = (last_field[0] == 'A') ? 'B' : 'A';
        } else {
            tampered[length - 1] = (tampered[length - 1] == 'A') ? 'B' : 'A';
        }
    }
    check(argon2_adaptive_verify(controller, tampered, TEST_PASSWORD,
                                 TEST_PASSWORD_LEN) != ARGON2_OK,
          "tampered envelope hash is rejected");

    tier = argon2_adaptive_current_tier(controller);
    printf("  tier=%-6s stored=%s\n", argon2_adaptive_tier_name(tier),
           encoded);
}

/* ------------------------------------------------------------------ */
/* Section 5: audit file                                               */
/* ------------------------------------------------------------------ */

static int count_audit_lines(const char *path, int *has_init,
                             int *has_param_change, int *has_high_switch) {
    FILE *file;
    char line[2048];
    int lines = 0;

    *has_init = 0;
    *has_param_change = 0;
    *has_high_switch = 0;

    file = fopen(path, "r");
    if (file == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (line[0] == '\n' || line[0] == '\0') {
            continue;
        }
        lines++;
        if (strstr(line, "\"event\":\"init\"") != NULL) {
            *has_init = 1;
        }
        if (strstr(line, "\"event\":\"param_change\"") != NULL) {
            *has_param_change = 1;
        }
        if (strstr(line, "\"new_tier\":\"high\"") != NULL) {
            *has_high_switch = 1;
        }
    }
    (void)fclose(file);
    return lines;
}

int main(int argc, char **argv) {
    const char *audit_arg = "argon2_param_audit.log";
    char *audit_resolved;

    argon2_adaptive_config config;
    argon2_adaptive_controller *controller = NULL;
    int rc;

    argon2_adaptive_config floor_config;
    argon2_adaptive_controller *floor_controller = NULL;
    char floor_hash[ARGON2_ADAPTIVE_ENCODED_MAX];

    argon2_adaptive_params low_params;
    argon2_adaptive_params medium_params;
    argon2_adaptive_params high_params;
    unsigned long long low_work;
    unsigned long long medium_work;
    unsigned long long high_work;

    static const uint8_t fixed_salt[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    char legacy_id[512];
    char legacy_i[512];
    char legacy_i10[512];

    argon2_adaptive_params tier_params[3];

    size_t event_count;
    size_t event_index;
    int change_records = 0;
    int overload_seen = 0;
    int audit_lines;
    int file_has_init;
    int file_has_param_change;
    int file_has_high_switch;

    if (argc > 1 && argv[1] != NULL) {
        audit_arg = argv[1];
    }

    printf("=== Adaptive Argon2 acceptance ===\n");

    /* ---------------- Section 1 ---------------- */
    argon2_adaptive_test_config(&config);
    config.audit_path = audit_arg;
    rc = argon2_adaptive_init(&controller, &config);

    audit_resolved = realpath(audit_arg, NULL);
    printf("audit log: %s\n",
           audit_resolved != NULL ? audit_resolved : audit_arg);
    free(audit_resolved);

    check(rc == ARGON2_OK && controller != NULL,
          "adaptive controller initialises");

    printf("\n[1/5] three concurrency pressures (deterministic) ---\n");

    rc = argon2_adaptive_observe(controller, 1,
                                 ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    check(rc == ARGON2_OK, "observe sample accepted");
    check(argon2_adaptive_current_tier(controller) ==
              ARGON2_ADAPTIVE_TIER_LOW,
          "concurrency band maps to expected tier");
    argon2_adaptive_current_params(controller, &low_params);
    low_work = (unsigned long long)low_params.t_cost * low_params.m_cost;
    printf("  concurrency=%2d -> tier=%-6s t=%u m=%uKiB p=%u "
           "work(t*m)=%llu\n",
           1, argon2_adaptive_tier_name(ARGON2_ADAPTIVE_TIER_LOW),
           (unsigned int)low_params.t_cost,
           (unsigned int)low_params.m_cost,
           (unsigned int)low_params.parallelism, low_work);

    rc = argon2_adaptive_observe(controller, 8,
                                 ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    check(rc == ARGON2_OK, "observe sample accepted");
    check(argon2_adaptive_current_tier(controller) ==
              ARGON2_ADAPTIVE_TIER_MEDIUM,
          "concurrency band maps to expected tier");
    argon2_adaptive_current_params(controller, &medium_params);
    medium_work =
        (unsigned long long)medium_params.t_cost * medium_params.m_cost;
    printf("  concurrency=%2d -> tier=%-6s t=%u m=%uKiB p=%u "
           "work(t*m)=%llu\n",
           8, argon2_adaptive_tier_name(ARGON2_ADAPTIVE_TIER_MEDIUM),
           (unsigned int)medium_params.t_cost,
           (unsigned int)medium_params.m_cost,
           (unsigned int)medium_params.parallelism, medium_work);

    rc = argon2_adaptive_observe(controller, 32,
                                 ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    check(rc == ARGON2_OK, "observe sample accepted");
    check(argon2_adaptive_current_tier(controller) ==
              ARGON2_ADAPTIVE_TIER_HIGH,
          "concurrency band maps to expected tier");
    argon2_adaptive_current_params(controller, &high_params);
    high_work = (unsigned long long)high_params.t_cost * high_params.m_cost;
    printf("  concurrency=%2d -> tier=%-6s t=%u m=%uKiB p=%u "
           "work(t*m)=%llu\n",
           32, argon2_adaptive_tier_name(ARGON2_ADAPTIVE_TIER_HIGH),
           (unsigned int)high_params.t_cost,
           (unsigned int)high_params.m_cost,
           (unsigned int)high_params.parallelism, high_work);

    check(low_params.t_cost != medium_params.t_cost ||
              low_params.m_cost != medium_params.m_cost ||
              low_params.parallelism != medium_params.parallelism,
          "low and medium pressures select different parameters");
    check(medium_params.t_cost != high_params.t_cost ||
              medium_params.m_cost != high_params.m_cost ||
              medium_params.parallelism != high_params.parallelism,
          "medium and high pressures select different parameters");
    check(low_work > medium_work && medium_work > high_work,
          "hashing work factor decreases monotonically under pressure");

    rc = argon2_adaptive_observe(controller, 64,
                                 ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    check(rc == ARGON2_OK, "critical sample accepted");
    check(argon2_adaptive_overload(controller) == 1,
          "critical concurrency raises overload advisory");
    check(argon2_adaptive_current_tier(controller) ==
              ARGON2_ADAPTIVE_TIER_HIGH,
          "critical load keeps HIGH/floor tier");
    {
        argon2_adaptive_params critical_params;
        argon2_adaptive_current_params(controller, &critical_params);
        check(critical_params.t_cost >= config.floor.t_cost &&
                  critical_params.m_cost >= config.floor.m_cost &&
                  critical_params.parallelism >= config.floor.parallelism,
              "critical parameters stay at/above the security floor");
    }

    (void)argon2_adaptive_observe(controller, 1,
                                  ARGON2_ADAPTIVE_LOAD_UNAVAILABLE);
    check(argon2_adaptive_overload(controller) == 0,
          "overload clears after pressure drops");

    /* ---------------- Section 2 ---------------- */
    printf("\n[2/5] security floor clamping ---\n");
    argon2_adaptive_test_config(&floor_config);
    floor_config.low.t_cost = 0;
    floor_config.low.m_cost = 16;
    floor_config.low.parallelism = 0;
    floor_config.medium = floor_config.low;
    floor_config.high = floor_config.low;
    floor_config.audit_path = NULL;
    rc = argon2_adaptive_init(&floor_controller, &floor_config);
    check(rc == ARGON2_OK && floor_controller != NULL,
          "floor-test controller initialises");

    {
        argon2_adaptive_params clamped;
        argon2_adaptive_current_params(floor_controller, &clamped);
        check(clamped.t_cost == floor_config.floor.t_cost &&
                  clamped.m_cost == floor_config.floor.m_cost &&
                  clamped.parallelism == floor_config.floor.parallelism,
              "sub-floor profile is clamped up to the security floor");
    }

    floor_hash[0] = '\0';
    rc = argon2_adaptive_hash_encoded(floor_controller, TEST_PASSWORD,
                                     TEST_PASSWORD_LEN, floor_hash,
                                     sizeof(floor_hash));
    check(rc == ARGON2_OK, "hash with clamped floor parameters succeeds");
    check(argon2_adaptive_verify(floor_controller, floor_hash, TEST_PASSWORD,
                                 TEST_PASSWORD_LEN) == ARGON2_OK,
          "clamped hash verifies");

    /* ---------------- Section 3 ---------------- */
    run_concurrency_section(controller);

    /* ---------------- Section 4 ---------------- */
    printf("\n[4/5] versioned format and legacy compatibility ---\n");

    legacy_id[0] = '\0';
    legacy_i[0] = '\0';
    legacy_i10[0] = '\0';

    rc = argon2id_hash_encoded(3, 256, 2, TEST_PASSWORD, TEST_PASSWORD_LEN,
                               fixed_salt, sizeof(fixed_salt), 32, legacy_id,
                               sizeof(legacy_id));
    check(rc == ARGON2_OK && legacy_id[0] != '\0',
          "argon2id v19 m=256 legacy hash");
    run_legacy_hash(legacy_id, Argon2_id, controller);

    rc = argon2i_hash_encoded(3, 256, 2, TEST_PASSWORD, TEST_PASSWORD_LEN,
                              fixed_salt, sizeof(fixed_salt), 32, legacy_i,
                              sizeof(legacy_i));
    check(rc == ARGON2_OK && legacy_i[0] != '\0',
          "argon2i  v19 m=256 legacy hash");
    run_legacy_hash(legacy_i, Argon2_i, controller);

    rc = argon2_hash(2, 65536, 1, TEST_PASSWORD, TEST_PASSWORD_LEN,
                     fixed_salt, sizeof(fixed_salt), NULL, 32, legacy_i10,
                     sizeof(legacy_i10), Argon2_i, ARGON2_VERSION_10);
    check(rc == ARGON2_OK && legacy_i10[0] != '\0',
          "argon2i  v1.0 m=65536 legacy hash");
    run_legacy_hash(legacy_i10, Argon2_i, controller);

    argon2_adaptive_test_config(&config);
    tier_params[0] = config.low;
    tier_params[1] = config.medium;
    tier_params[2] = config.high;

    run_envelope_tier(controller, 1, ARGON2_ADAPTIVE_TIER_LOW,
                      &tier_params[0]);
    run_envelope_tier(controller, 8, ARGON2_ADAPTIVE_TIER_MEDIUM,
                      &tier_params[1]);
    run_envelope_tier(controller, 32, ARGON2_ADAPTIVE_TIER_HIGH,
                      &tier_params[2]);

    {
        char default_hash[ARGON2_ADAPTIVE_ENCODED_MAX];
        default_hash[0] = '\0';
        rc = argon2_adaptive_login_hash(TEST_PASSWORD, TEST_PASSWORD_LEN,
                                        default_hash, sizeof(default_hash));
        check(rc == ARGON2_OK &&
                  argon2_adaptive_is_envelope(default_hash),
              "default controller login_hash produces envelope");
        check(argon2_adaptive_login_verify(default_hash, TEST_PASSWORD,
                                           TEST_PASSWORD_LEN) == ARGON2_OK,
              "default controller login_verify succeeds");
        check(argon2_adaptive_login_verify(default_hash, WRONG_PASSWORD,
                                          WRONG_PASSWORD_LEN) != ARGON2_OK,
              "default controller rejects wrong password");
        argon2_adaptive_default_shutdown();
    }

    /* ---------------- Section 5 ---------------- */
    printf("\n[5/5] audit log ---\n");

    event_count = argon2_adaptive_audit_count(controller);
    check(event_count > 0, "in-memory audit ring recorded events");

    for (event_index = 0; event_index < event_count; event_index++) {
        argon2_adaptive_audit_event event;
        if (argon2_adaptive_audit_get(controller, event_index, &event) !=
            ARGON2_OK) {
            continue;
        }
        if (event.kind == ARGON2_ADAPTIVE_AUDIT_PARAM_CHANGE) {
            change_records++;
            check(event.old_params.t_cost != event.new_params.t_cost ||
                      event.old_params.m_cost != event.new_params.m_cost ||
                      event.old_params.parallelism !=
                          event.new_params.parallelism,
                  "parameter_change event carries a real delta");
        }
        if (event.kind == ARGON2_ADAPTIVE_AUDIT_OVERLOAD) {
            overload_seen = 1;
        }
    }

    check(change_records >= 2, "multiple parameter changes were audited");
    check(overload_seen == 1, "overload transition was audited");

    audit_lines = count_audit_lines(audit_arg, &file_has_init,
                                    &file_has_param_change,
                                    &file_has_high_switch);
    check(audit_lines >= 0 && file_has_init,
          "audit file contains init record");
    check(audit_lines >= 0 && file_has_param_change,
          "audit file contains param_change records");
    check(audit_lines >= 0 && file_has_high_switch,
          "audit file records a switch to the high-pressure tier");
    check(audit_lines >= 2, "audit file contains multiple JSON-lines records");
    if (audit_lines >= 0) {
        printf("  audit file: %s (%d JSON lines)\n", audit_arg, audit_lines);
    }

    printf("\n=== %d checks, %d failure(s) ===\n", checks_total,
           checks_failed);
    if (checks_failed == 0) {
        printf("ALL ADAPTIVE ARGON2 ACCEPTANCE CHECKS PASSED\n");
    }

    argon2_adaptive_destroy(floor_controller);
    argon2_adaptive_destroy(controller);

    return checks_failed == 0 ? 0 : 1;
}
