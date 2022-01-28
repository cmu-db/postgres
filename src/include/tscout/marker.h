#pragma once

#include "c.h"
#include "tscout/StaticTracepoint-ELFx86.h"

// Define a Marker without a semaphore
#define TS_MARKER(name, ...) FOLLY_SDT_PROBE_N(noisepage, name, 0, FOLLY_SDT_NARG(0, ##__VA_ARGS__), ##__VA_ARGS__)

// Define a semaphore outside of local scope for use with a Marker
#define TS_DEFINE_SEMAPHORE(name) FOLLY_SDT_DEFINE_SEMAPHORE(noisepage, name)

// Declare a semaphore outside of local scope for use with a Marker
#define TS_DECLARE_SEMAPHORE(name) FOLLY_SDT_DECLARE_SEMAPHORE(noisepage, name)

// Define a Marker for use with a previously-defined semaphore
#define TS_MARKER_WITH_SEMAPHORE(name, ...) \
  FOLLY_SDT_PROBE_N(noisepage, name, 1, FOLLY_SDT_NARG(0, ##__VA_ARGS__), ##__VA_ARGS__)

// Test if previously-definied semaphore is in use
#define TS_MARKER_IS_ENABLED(name) (FOLLY_SDT_SEMAPHORE(noisepage, name) > 0)
