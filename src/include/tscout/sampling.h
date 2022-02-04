#pragma once

#include "c.h"  // bool

extern bool tscout_executor_running;  // true if TScout is collecting data for this query execution. Read to check the
                                      // result of TScoutExecutorSample. Never assign to this variable from somewhere
                                      // other than TScoutExecutorSample.
extern double tscout_executor_sampling_rate;  // guc variable (e.g., SET tscout_executor_sampling_rate = 0.5;)

/**
 * Called at the start of query execution. For the duration of query execution, check tscout_executor_running before
 * each TScout interaction to see if this query is being tracked.
 */
void TScoutExecutorSample();