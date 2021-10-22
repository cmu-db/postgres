from subprocess import Popen
import time
import psutil
import os

for proc in psutil.process_iter(['pid', 'name', 'username']): 
    if proc.info["name"].lower().startswith("postgres"):
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass

logfile_name = "/home/gh/postgres/querylogs.txt"
if os.path.exists(logfile_name):
    os.remove(logfile_name)
logfile = open(logfile_name, "w")

# configure and install Postgres
os.chdir("/home/gh/postgres/")
print(os.getcwd())
Popen(args=["./cmudb/build/configure.sh debug"], shell=True).wait()
Popen(["make clean -s"], shell=True).wait()
Popen(args=["make -j -s"], shell=True).wait()
Popen(args=["make install -j -s"], shell=True).wait()

# setup database for benchbase
Popen(args=["rm -rf data"], shell=True).wait()
Popen(args=["mkdir -p data"], shell=True).wait()
Popen(args=["./build/bin/initdb -D data"], shell=True).wait()
pg_proc = Popen(args=["./build/bin/postgres -D data -W 2 &"], shell=True, stdout=logfile, stderr=logfile)
time.sleep(3)
Popen(args=["./build/bin/createdb test"], shell=True).wait()
Popen(args=['''./build/bin/psql -d test -c "CREATE ROLE admin WITH PASSWORD 'password' SUPERUSER CREATEDB CREATEROLE INHERIT LOGIN;"'''], shell=True).wait()
Popen(args=["./build/bin/createdb -O admin benchbase"], shell=True).wait()
Popen(args=['''./build/bin/psql -d test -c "ALTER DATABASE test SET compute_query_id = 'ON';"'''], shell=True).wait()
Popen(args=['''./build/bin/psql -d benchbase -c "ALTER DATABASE benchbase SET compute_query_id = 'ON';"'''], shell=True).wait()

# Postgres argument: -r filename (to send all server log output to filename)

benchbase_dir = "/home/gh/benchbase/"
snapshot = f"{benchbase_dir}target/benchbase-2021-SNAPSHOT.zip"
benchbase_snapshot_dir = f"{benchbase_dir}benchbase-2021-SNAPSHOT/"


# build benchbase and setup tpc-c
# os.chdir(benchbase_dir)
# print(os.getcwd())
# Popen(args=["./mvnw clean package"], shell=True).wait()

if not os.path.exists(benchbase_snapshot_dir):
    Popen(args=[f"unzip {snapshot}"], shell=True).wait()

os.chdir(benchbase_snapshot_dir)
print(os.getcwd())
Popen(args=["java -jar benchbase.jar -b tpcc -c config/postgres/sample_tpcc_config.xml --create=true --load=true"], shell=True).wait()




# shutdown postgres now that complete
print("Shutting down PG process and closing logfile")
pg_proc.kill()
logfile.close()




# # attach tscout to postmaster
# cd ~/noisepage_bpf
# rm *.csv
# sudo python3 tscout.py `pgrep -ox postgres`

# # run benchbase
# cd ~/benchbase/target/benchbase-2021-SNAPSHOT/
# java -jar benchbase.jar -b tpcc -c config/postgres/sample_tpcc_config.xml --execute=true



# # shutdown tscout



# # investigate tscout results






# # load tscout results into training data db



# # maybe load benchbase results into training data db




#------------------------------------------------------------------------------
# REPORTING AND LOGGING
#------------------------------------------------------------------------------

# - Where to Log -

#log_destination = 'stderr'		# Valid values are combinations of
					# stderr, csvlog, syslog, and eventlog,
					# depending on platform.  csvlog
					# requires logging_collector to be on.

# This is used when logging to stderr:
#logging_collector = off		# Enable capturing of stderr and csvlog
					# into log files. Required to be on for
					# csvlogs.
					# (change requires restart)

# These are only used if logging_collector is on:
#log_directory = 'log'			# directory where log files are written,
					# can be absolute or relative to PGDATA
#log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'	# log file name pattern,
					# can include strftime() escapes
#log_file_mode = 0600			# creation mode for log files,
					# begin with 0 to use octal notation
#log_rotation_age = 1d			# Automatic rotation of logfiles will
					# happen after that time.  0 disables.
#log_rotation_size = 10MB		# Automatic rotation of logfiles will
					# happen after that much log output.
					# 0 disables.
#log_truncate_on_rotation = off		# If on, an existing log file with the
					# same name as the new log file will be
					# truncated rather than appended to.
					# But such truncation only occurs on
					# time-driven rotation, not on restarts
					# or size-driven rotation.  Default is
					# off, meaning append to existing files
					# in all cases.

# These are relevant when logging to syslog:
#syslog_facility = 'LOCAL0'
#syslog_ident = 'postgres'
#syslog_sequence_numbers = on
#syslog_split_messages = on

# This is only relevant when logging to eventlog (Windows):
# (change requires restart)
#event_source = 'PostgreSQL'

# - When to Log -

#log_min_messages = warning		# values in order of decreasing detail:
					#   debug5
					#   debug4
					#   debug3
					#   debug2
					#   debug1
					#   info
					#   notice
					#   warning
					#   error
					#   log
					#   fatal
					#   panic

#log_min_error_statement = error	# values in order of decreasing detail:
					#   debug5
					#   debug4
					#   debug3
					#   debug2
					#   debug1
					#   info
					#   notice
					#   warning
					#   error
					#   log
					#   fatal
					#   panic (effectively off)

#log_min_duration_statement = -1	# -1 is disabled, 0 logs all statements
					# and their durations, > 0 logs only
					# statements running at least this number
					# of milliseconds

#log_min_duration_sample = -1		# -1 is disabled, 0 logs a sample of statements
					# and their durations, > 0 logs only a sample of
					# statements running at least this number
					# of milliseconds;
					# sample fraction is determined by log_statement_sample_rate

#log_statement_sample_rate = 1.0	# fraction of logged statements exceeding
					# log_min_duration_sample to be logged;
					# 1.0 logs all such statements, 0.0 never logs


#log_transaction_sample_rate = 0.0	# fraction of transactions whose statements
					# are logged regardless of their duration; 1.0 logs all
					# statements from all transactions, 0.0 never logs

# - What to Log -

#debug_print_parse = off
#debug_print_rewritten = off
#debug_print_plan = off
#debug_pretty_print = on
#log_autovacuum_min_duration = -1	# log autovacuum activity;
					# -1 disables, 0 logs all actions and
					# their durations, > 0 logs only
					# actions running at least this number
					# of milliseconds.
#log_checkpoints = off
#log_connections = off
#log_disconnections = off
#log_duration = off
#log_error_verbosity = default		# terse, default, or verbose messages
#log_hostname = off
#log_line_prefix = '%m [%p] '		# special values:
					#   %a = application name
					#   %u = user name
					#   %d = database name
					#   %r = remote host and port
					#   %h = remote host
					#   %b = backend type
					#   %p = process ID
					#   %P = process ID of parallel group leader
					#   %t = timestamp without milliseconds
					#   %m = timestamp with milliseconds
					#   %n = timestamp with milliseconds (as a Unix epoch)
					#   %Q = query ID (0 if none or not computed)
					#   %i = command tag
					#   %e = SQL state
					#   %c = session ID
					#   %l = session line number
					#   %s = session start timestamp
					#   %v = virtual transaction ID
					#   %x = transaction ID (0 if none)
					#   %q = stop here in non-session
					#        processes
					#   %% = '%'
					# e.g. '<%u%%%d> '
#log_lock_waits = off			# log lock waits >= deadlock_timeout
#log_recovery_conflict_waits = off	# log standby recovery conflict waits
					# >= deadlock_timeout
#log_parameter_max_length = -1		# when logging statements, limit logged
					# bind-parameter values to N bytes;
					# -1 means print in full, 0 disables
#log_parameter_max_length_on_error = 0	# when logging an error, limit logged
					# bind-parameter values to N bytes;
					# -1 means print in full, 0 disables
#log_statement = 'none'			# none, ddl, mod, all
#log_replication_commands = off
#log_temp_files = -1			# log temporary files equal or larger
					# than the specified size in kilobytes;
					# -1 disables, 0 logs all temp files
log_timezone = 'Etc/UTC'


#------------------------------------------------------------------------------
# PROCESS TITLE
#------------------------------------------------------------------------------

#cluster_name = ''			# added to process titles if nonempty
					# (change requires restart)
#update_process_title = on


#------------------------------------------------------------------------------
# STATISTICS
#------------------------------------------------------------------------------

# - Query and Index Statistics Collector -

#track_activities = on
#track_activity_query_size = 1024	# (change requires restart)
#track_counts = on
#track_io_timing = off
#track_wal_io_timing = off
#track_functions = none			# none, pl, all
#stats_temp_directory = 'pg_stat_tmp'


# - Monitoring -

#compute_query_id = auto
#log_statement_stats = off
#log_parser_stats = off
#log_planner_stats = off
#log_executor_stats = off

