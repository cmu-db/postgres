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
static size_t GetFieldSize(c_type type, int padding);
static const char *GetNodeType(Plan *node);
static const char *GetOperationType(Plan *node);

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
    ExplainOpenGroup("Tscout", "Tscout", true, es);
    WalkPlan(queryDesc->planstate->plan, es);
    ExplainCloseGroup("Tscout", "Tscout", true, es);
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
 * @param padding (int) - Size of padding if a padding field.
 * @return size_t - Size of the field on the machine.
 */
size_t GetFieldSize(c_type type, int padding) {
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
    case T_PADDING:
      return padding;
    default:
      break;
  }

  // Abort in case of unknown field type.
  abort();
}

/**
 * @brief Fetch the type of the node in human readable format.
 * NOTE - This duplicates the code in backend/commands/explain.c --> ExplainNode()
 * The human readable strings to explain the node types are not declared as
 * constants in the Postgres codebase and are scoped local to the ExplainNode()
 * function. While our goal is to not duplicate code between the Postgres codebase
 * and this extension, in this case, it seems both reasonable and unavoidable.
 * In the event that new node types are added to the Postgres codebase, and this function
 * is not updated correspondingly, we would not have a human-readable string associated with
 * the newly defined node types, which I think is a fair maintainability tradeoff.
 *
 * @param node (Plan *) - Plan node whose type is to be fetched.
 * @return const char* - The node type.
 */
static const char *GetNodeType(Plan *node) {
  const char *sname = NULL;

  switch (nodeTag(node)) {
    case T_Result:
      sname = "Result";
      break;
    case T_ProjectSet:
      sname = "ProjectSet";
      break;
    case T_ModifyTable:
      sname = "ModifyTable";
      break;
    case T_Append:
      sname = "Append";
      break;
    case T_MergeAppend:
      sname = "Merge Append";
      break;
    case T_RecursiveUnion:
      sname = "Recursive Union";
      break;
    case T_BitmapAnd:
      sname = "BitmapAnd";
      break;
    case T_BitmapOr:
      sname = "BitmapOr";
      break;
    case T_NestLoop:
      sname = "Nested Loop";
      break;
    case T_MergeJoin:
      sname = "Merge Join";
      break;
    case T_HashJoin:
      sname = "Hash Join";
      break;
    case T_SeqScan:
      sname = "Seq Scan";
      break;
    case T_SampleScan:
      sname = "Sample Scan";
      break;
    case T_Gather:
      sname = "Gather";
      break;
    case T_GatherMerge:
      sname = "Gather Merge";
      break;
    case T_IndexScan:
      sname = "Index Scan";
      break;
    case T_IndexOnlyScan:
      sname = "Index Only Scan";
      break;
    case T_BitmapIndexScan:
      sname = "Bitmap Index Scan";
      break;
    case T_BitmapHeapScan:
      sname = "Bitmap Heap Scan";
      break;
    case T_TidScan:
      sname = "Tid Scan";
      break;
    case T_TidRangeScan:
      sname = "Tid Range Scan";
      break;
    case T_SubqueryScan:
      sname = "Subquery Scan";
      break;
    case T_FunctionScan:
      sname = "Function Scan";
      break;
    case T_TableFuncScan:
      sname = "Table Function Scan";
      break;
    case T_ValuesScan:
      sname = "Values Scan";
      break;
    case T_CteScan:
      sname = "CTE Scan";
      break;
    case T_NamedTuplestoreScan:
      sname = "Named Tuplestore Scan";
      break;
    case T_WorkTableScan:
      sname = "WorkTable Scan";
      break;
    case T_ForeignScan:
      sname = "Foreign Scan";
      break;
    case T_CustomScan:
      sname = "Custom Scan";
      break;
    case T_Material:
      sname = "Materialize";
      break;
    case T_Memoize:
      sname = "Memoize";
      break;
    case T_Sort:
      sname = "Sort";
      break;
    case T_IncrementalSort:
      sname = "Incremental Sort";
      break;
    case T_Group:
      sname = "Group";
      break;
    case T_Agg: {
      sname = "Aggregate";
    } break;
    case T_WindowAgg:
      sname = "WindowAgg";
      break;
    case T_Unique:
      sname = "Unique";
      break;
    case T_SetOp:
      sname = "SetOp";
      break;
    case T_LockRows:
      sname = "LockRows";
      break;
    case T_Limit:
      sname = "Limit";
      break;
    case T_Hash:
      sname = "Hash";
      break;
    default:
      sname = "???";
      break;
  }

  return sname;
}

/**
 * @brief Fetch the operation type of the given node.
 * OperationTypes are currently available for nodes of "type":
 * 1. PlannedStmt
 * 2. ModifyTable
 * 3. ForeignScan
 * NOTE - See note in GetNodeType().
 *
 * @param node (Plan *) - Plan node whose operation type is to be fetched.
 * @return const char* - The operation type of the node.
 */
static const char *GetOperationType(Plan *node) {
  const char *operation = NULL;
  switch (((ModifyTable *)node)->operation) {
    case CMD_SELECT:
      operation = "Select";
      break;
    case CMD_INSERT:
      operation = "Insert";
      break;
    case CMD_UPDATE:
      operation = "Update";
      break;
    case CMD_DELETE:
      operation = "Delete";
      break;
    default:
      break;
  }
  return operation;
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
  ExplainPropertyText("node_type", GetNodeType(node), es);

  if (nodeTag(node) == T_ModifyTable) {
    ExplainPropertyText("operation", GetOperationType(node), es);
  }

  for (i = 0; i < num_fields; i++) {
    field_size = GetFieldSize(fields[i].type, fields[i].padding);
    next_field_size = i < num_fields - 1 ? GetFieldSize(fields[i + 1].type, fields[i + 1].padding) : 8;

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
        // This is effectively the definition of T_LIST_PTR's "Reagent". We could codegen these in the future.
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

  if (outerPlan(plan) != NULL || innerPlan(plan) != NULL) {
    ExplainOpenGroup("Plans", "Plans", false, es);
  }

  // 2. Explain the tree rooted in the outer (left) plan.
  if (outerPlan(plan) != NULL) {
    ExplainOpenGroup("left-child", NULL, true, es);
    WalkPlan(outerPlan(plan), es);
    ExplainCloseGroup("left-child", NULL, true, es);
  }

  // 3. Explain the tree rooted in the inner (right) plan.
  if (innerPlan(plan) != NULL) {
    ExplainOpenGroup("right-child", NULL, true, es);
    WalkPlan(innerPlan(plan), es);
    ExplainCloseGroup("right-child", NULL, true, es);
  }

  if (outerPlan(plan) != NULL || innerPlan(plan) != NULL) {
    ExplainCloseGroup("Plans", "Plans", false, es);
  }

  // TODO (Karthik): Handle sub-plans.
}
