#pragma once

#include "c.h"
#include "tscout/StaticTracepoint-ELFx86.h"

// TODO(Matt): look at macros to automatically grab function name and file name

// Define a Marker without a semaphore
#define TS_MARKER(name, ...) \
	FOLLY_SDT_PROBE_N(noisepage, name, 0, FOLLY_SDT_NARG(0, ##__VA_ARGS__), ##__VA_ARGS__)

// Define a semaphore outside of local scope for use with a Marker
#define TS_DEFINE_SEMAPHORE(name) FOLLY_SDT_DEFINE_SEMAPHORE(noisepage, name)

// Declare a semaphore outside of local scope for use with a Marker
#define TS_DECLARE_SEMAPHORE(name) FOLLY_SDT_DECLARE_SEMAPHORE(noisepage, name)

// Define a Marker for use with a previously-defined semaphore
#define TS_MARKER_WITH_SEMAPHORE(name, ...) \
	FOLLY_SDT_PROBE_N(noisepage, name, 1, FOLLY_SDT_NARG(0, ##__VA_ARGS__), ##__VA_ARGS__)

// Test if previously-definied semaphore is in use
#define TS_MARKER_IS_ENABLED(name) (FOLLY_SDT_SEMAPHORE(noisepage, name) > 0)

// Define variables required by all of the markers. This avoids the C90 warnings.
#define TS_MARKER_SETUP()                                                                       \
  /* Features. */                                                                               \
  uint64_t query_id;                                                                            \
  /* The current node. */                                                                       \
  void *cur_node;

// Define common features.
#define TS_FEATURES_MARKER(name, current_node, plan_state_ptr, ...)                             \
  query_id = plan_state_ptr->state->es_plannedstmt->queryId;                                    \
  cur_node = (void *) current_node;                                                             \
  TS_MARKER(                                                                                    \
    name,                                                                                       \
    query_id,                                                                                   \
    cur_node,                                                                                   \
    plan_state_ptr->plan,                                                                       \
    ##__VA_ARGS__                                                                               \
  );
