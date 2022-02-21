#include <time.h>

// clang-format off
// Extension magic.
#include "postgres.h"
#include "fmgr.h"
// clang-format on

#include "commands/createas.h"
#include "commands/explain.h"
#include "nodes/pg_list.h"
#include "operating_unit_features.h"
#include "optimizer/planner.h"
#include "parser/parsetree.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;
void _PG_init(void);
void _PG_fini(void);

static void ExplainOneQueryWrapper(Query *query, int cursorOptions, IntoClause *into, ExplainState *es,
                                   const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv);
static void WalkPlan(Plan *plan, ExplainState *es);
static void ExplainFeatures(Plan *node, ExplainState *es);
static size_t GetFieldSize(c_type type);

static ExplainOneQuery_hook_type chain_ExplainOneQuery = NULL;

void _PG_init(void) {
  elog(LOG, "Initializing extension.");

  // Hook the ExplainOneQuery wrapper to the head of the chain.
  chain_ExplainOneQuery = ExplainOneQuery_hook;
  ExplainOneQuery_hook = ExplainOneQueryWrapper;

  // Init logic (like setting flags) go here.
}

void _PG_fini(void) {
  // Clean up logic goes here.
  ExplainOneQuery_hook = chain_ExplainOneQuery;
  elog(DEBUG1, "Finishing extension.");
}

static void ExplainOneQueryWrapper(Query *query, int cursorOptions, IntoClause *into, ExplainState *es,
                                   const char *queryString, ParamListInfo params, QueryEnvironment *queryEnv) {
  PlannedStmt *plan;
  QueryDesc *queryDesc;
  instr_time plan_start, plan_duration;
  int eflags = 0;

  if (chain_ExplainOneQuery) {
    chain_ExplainOneQuery(query, cursorOptions, into, es, queryString, params, queryEnv);
  }

  // Postgres does not expose an interface to call into the standard ExplainOneQuery.
  // Hence, we duplicate the operations performed by the standard ExplainOneQuery i.e.,
  // calling into the standard planner.
  // A non-standard planner can be hooked in, in the the future.
  INSTR_TIME_SET_CURRENT(plan_start);
  plan = (planner_hook ? planner_hook(query, queryString, cursorOptions, params)
                       : standard_planner(query, queryString, cursorOptions, params));

  INSTR_TIME_SET_CURRENT(plan_duration);
  INSTR_TIME_SUBTRACT(plan_duration, plan_start);

  // We first run the standard explain code path. This is due to an adverse interaction
  // between hutch and HypoPG.
  //
  // HypoPG utilizes two hooks: (1) The ProcessUtility_hook is invoked at the beginning of a
  // utility command (e.g., EXPLAIN). The hook determines whether HypoPG is compatible
  // with the current utility command and sets a flag. (2) ExecutorEnd_hook is used
  // to clear the per-query state (it resets the flag set by the ProcessUtility_hook)
  //
  // However, in order for Hutch to generate the X's, we execute an ExecutorStart(),
  // extract all the X's from the resulting query plan & state, and invoke ExecutorEnd().
  //
  // Assuming we are unable/unwilling to clone HypoPG and patch this behavior, then
  // generating the X's will shutdown HypoPG for this query. This means that HypoPG will
  // no longer intercept any catalog inquiries about its hypothetical indexes.
  //
  // This "fix" assumes that we don't depend on HypoPG interception (e.g., catalog)
  // to generate the X's. This is because ExplainOnePlan() will also end up
  // invoking the ExecutorEnd_hook which shuts down HypoPG. As such, we first invoke
  // ExplainOnePlan() and then we generate the relevant X's.
  ExplainOnePlan(plan, into, es, queryString, params, queryEnv, &plan_duration, NULL);

  if (es->format == EXPLAIN_FORMAT_TSCOUT) {
    queryDesc =
        CreateQueryDesc(plan, queryString, InvalidSnapshot, InvalidSnapshot, None_Receiver, params, queryEnv, 0);

    if (es->analyze)
      eflags = 0;
    else
      eflags = EXEC_FLAG_EXPLAIN_ONLY;
    if (into) eflags |= GetIntoRelEFlags(into);

    // Run the executor.
    ExecutorStart(queryDesc, eflags);
    // This calls into initPlan() which populates the plan tree.
    // TODO (Karthik): Create a hook to executor start.

    // Finally, walks through the plan, dumping the output of the plan in a separate top-level group.
    ExplainOpenGroup("TscoutProps", NULL, true, es);
    WalkPlan(queryDesc->planstate->plan, es);
    ExplainCloseGroup("TscoutProps", NULL, true, es);

    // Free the created query description resources.
    ExecutorEnd(queryDesc);
    FreeQueryDesc(queryDesc);
  }
}

/**
 * @brief Fetch the size of the field.
 *
 * @param type (c_type) - The C field type.
 * @return size_t - Size of the field on the machine.
 */
size_t GetFieldSize(c_type type) {
  switch (type) {
    case T_BOOL:
      return sizeof(bool);
    case T_ENUM:
      // For now, let's assume that all enumerations are the size of ints.
      // We're only interested in the NodeTag enum which is an int.
      // TODO (Karthik): Revisit this.
    case T_INT:
      return sizeof(int);
    case T_SHORT:
      return sizeof(short);
    case T_LONG:
      return sizeof(long);
    case T_DOUBLE:
      return sizeof(double);
    case T_PTR:
    case T_LIST_PTR:
      return sizeof(void *);
    default:
      break;
  }

  // Abort in case of unknown field type.
  abort();
}

/**
 * @brief - Explain the features of the given node.
 *
 * @param node (Plan *) - Plan node to be explained.
 * @param es (ExplainState *) - The current EXPLAIN state.
 */
static void ExplainFeatures(Plan *node, ExplainState *es) {
  char *nodeTagExplainer, nodeName[17];
  int i, start_index, field_size, next_field_size, padding, num_fields;
  field *fields;

  nodeTagExplainer = NULL;
  start_index = 0;

  // NOTE: It is assumed that ou_list contains definitions for all the node tags.
  nodeTagExplainer = ou_list[nodeTag(node)].name;
  num_fields = ou_list[nodeTag(node)].num_xs;
  fields = ou_list[nodeTag(node)].fields;

  sprintf(nodeName, "node-%d", node->plan_node_id);
  ExplainPropertyText("node", nodeName, es);
  ExplainPropertyText("tag", nodeTagExplainer, es);

  for (i = 0; i < num_fields; i++) {
    field_size = GetFieldSize(fields[i].type);
    next_field_size = i < num_fields - 1 ? GetFieldSize(fields[i + 1].type) : 8;

    switch (fields[i].type) {
      case T_BOOL:
        elog(DEBUG1, "%s: %x", fields[i].name, *(bool *)((char *)(node) + start_index));
        ExplainPropertyBool(fields[i].name, *(bool *)((char *)(node) + start_index), es);
        break;

      case T_INT:
      case T_ENUM:
        elog(DEBUG1, "%s: %d", fields[i].name, *(int *)((char *)(node) + start_index));
        ExplainPropertyInteger(fields[i].name, "units", *(int *)((char *)(node) + start_index), es);
        break;

      case T_SHORT:
        elog(DEBUG1, "%s: %ld", fields[i].name, (int64) * (short *)((char *)(node) + start_index));
        ExplainPropertyInteger(fields[i].name, "units", (int64) * (short *)((char *)(node) + start_index), es);
        break;

      case T_LONG:
        elog(DEBUG1, "%s: %ld", fields[i].name, (int64) * (long *)((char *)(node) + start_index));
        ExplainPropertyInteger(fields[i].name, "units", (int64) * (long *)((char *)(node) + start_index), es);
        break;

      case T_DOUBLE:
        elog(DEBUG1, "%s: %lf", fields[i].name, *(double *)((char *)(node) + start_index));
        ExplainPropertyFloat(fields[i].name, "units", *(double *)((char *)(node) + start_index), 6, es);
        break;

      case T_PTR:
        elog(DEBUG1, "%s: %s", fields[i].name, "<skipped>");
        ExplainPropertyText(fields[i].name, "<skipped>", es);
        break;

      case T_LIST_PTR: {
        // This is effectively the definition of T_LIST_PTR's "Encoder". We could codegen these in the future.
        List *list;
        int length = 0;  // Default to 0, and only update if List is non-NIL.
        list = *(List **)((char *)(node) + start_index);
        if (list != NIL) {
          length = list->length;
        }
        elog(DEBUG1, "%s: %d", fields[i].name, length);
        ExplainPropertyInteger(fields[i].name, "units", length, es);
        break;
      }

      default:
        break;
    }

    padding = (next_field_size - ((start_index + field_size) % next_field_size)) % next_field_size;
    start_index += field_size + padding;
    elog(DEBUG1, "Padding: %d, start index: %d", padding, start_index);
  }
}

/**
 * @brief - Walk through the plan tree, dumping features to the current open group.
 *
 * @param plan (Plan *) - Plan node.
 * @param es (ExplainState *) - The current EXPLAIN state.
 */
static void WalkPlan(Plan *plan, ExplainState *es) {
  Assert(plan != NULL);

  // 1. Explain the current node.
  ExplainFeatures(plan, es);

  // 2. Explain the tree rooted in the outer (left) plan.
  if (plan != NULL && outerPlan(plan) != NULL) {
    ExplainOpenGroup("left-child", "left-child", true, es);
    WalkPlan(outerPlan(plan), es);
    ExplainCloseGroup("left-child", "left-child", true, es);
  }

  // 3. Explain the tree rooted in the inner (right) plan.
  if (plan != NULL && innerPlan(plan) != NULL) {
    ExplainOpenGroup("right-child", "right-child", true, es);
    WalkPlan(innerPlan(plan), es);
    ExplainCloseGroup("right-child", "right-child", true, es);
  }

  // TODO (Karthik): Handle sub-plans.
}
