/**
 * @brief - An enum that represents all the C data types
 * encountered while scanning the Postgres code-base.
 * The scan operation is performed by the Clang parser.
 * See `cmudb/tscout/clang_parser.py`.
 *
 */
typedef enum c_type {
  T_BOOL = 0,
  T_SHORT,
  T_INT,
  T_LONG,
  T_FLOAT,
  T_DOUBLE,
  T_ENUM,
  T_PTR,
  T_UNKNOWN,
  T_LIST_PTR,
} c_type;

/**
 * @brief - A feature for the behavior models (also called an X).
 * An X contains a name and a C data type.
 *
 */
typedef struct field {
  c_type type;
  char *name;
} field;

/**
 * @brief - An OperatingUnit as defined by TScout.
 *
 */
typedef struct OperatingUnit {
  int ou_index;
  char *name;
  int num_xs;
  field *fields;
} ou;

// Features go here.
field feat_none[0];

ou ou_list[] = {
    (ou){OU_INDEX, OU_NAME, NUM_Xs, OU_Xs},
};