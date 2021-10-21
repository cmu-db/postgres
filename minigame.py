from subprocess import Popen
import time
import psutil
import os

for proc in psutil.process_iter(['pid', 'name', 'username']): 
    if proc.info["name"].startswith("postgres"):
        print(f"Killing pre-existing PG process: {proc}")
        proc.kill()

logfile_name = "/home/gh/postgres/querylogs.txt"
if os.path.exists(logfile_name):
    os.remove(logfile_name)
logfile = open(logfile_name, "w")

# configure and install Postgres
os.chdir("/home/gh/postgres/")
print(os.getcwd())
Popen(["make clean"], shell=True).wait()
Popen(args=["./cmudb/build/configure.sh debug"], shell=True).wait()
Popen(args=["make -j"], shell=True).wait()
Popen(args=["make install -j"], shell=True).wait()




# setup database for benchbase
Popen(args=["rm -rf data"], shell=True).wait()
Popen(args=["mkdir -p data"], shell=True).wait()
Popen(args=["./build/bin/initdb -D data"], shell=True).wait()
pg_proc = Popen(args=["./build/bin/postgres -D data -W 2 &"], shell=True, stdout=logfile, stderr=logfile)
time.sleep(3)
Popen(args=["./build/bin/createdb gh-test"], shell=True).wait()
Popen(args=['''./build/bin/psql -d gh-test -c "CREATE ROLE admin WITH PASSWORD 'password' SUPERUSER CREATEDB CREATEROLE INHERIT LOGIN;"'''], shell=True).wait()
Popen(args=["./build/bin/createdb -O admin benchbase"], shell=True).wait()




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

