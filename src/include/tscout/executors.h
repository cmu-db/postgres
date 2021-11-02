#pragma once

#include "tscout/marker.h"

#define TS_EXECUTOR_WRAPPER(node_type)                                                                          \
static TupleTableSlot *                                                                                         \
Exec##node_type(PlanState *pstate)                                                                              \
{                                                                                                               \
  TupleTableSlot *result;                                                                                       \
  TS_MARKER(Exec##node_type##_begin);                                                         					\
                                                                                                                \
  result = _Exec##node_type(pstate);                                                                            \
                                                                                                                \
  TS_MARKER(Exec##node_type##_end);                                                           					\
  TS_MARKER(                                                                                                    \
    Exec##node_type##_features,                                                               					\
    pstate->state->es_plannedstmt->queryId,                                                                     \
    castNode(node_type##State, pstate),                                                                         \
    pstate->plan                                                                                                \
  );                                                                                                            \
  return result;                                                                                                \
}
