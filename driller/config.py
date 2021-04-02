# https://github.com/shellphish/driller/issues/35#issuecomment-297569445

### Redis Options
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 1

### Celery Options
BROKER_URL = 'pyamqp://myuser:mypasswd@localhost:5672/myvhost'

CELERY_ROUTES = {'driller.tasks.fuzz': {'queue': 'fuzzer'}, 'driller.tasks.drill': {'queue': 'driller'}}

### Environment Options

# directory contain driller-qemu versions, relative to the directoy node.py is invoked in
QEMU_DIR = None

# directory containing the binaries, used by the driller node to find binaries
# BINARY_DIR = '/drill-bins'
BINARY_DIR = '/hz_bins'

# directory containing the pcap corpus
# PCAP_DIR = '/pcaps'
PCAP_DIR = '/hz_pcaps'

### Driller options
# how long to drill before giving up in seconds
DRILL_TIMEOUT = 60 * 60 * 2

# 16 GB
MEM_LIMIT = 3*1024*1024*1024

# where to write a debug file that contains useful debugging information like
# AFL's fuzzing bitmap, input used, binary path, time started.
# Uses following naming convention:
#   <binary_basename>_<input_str_md5>.py
# DEBUG_DIR = '/drill-logs'
DEBUG_DIR = '/hz_logs'

### Fuzzer options

# how often to check for crashes in seconds
CRASH_CHECK_INTERVAL = 60

# how long to fuzz before giving up in seconds
FUZZ_TIMEOUT = 60 * 60 * 24 * 5

# how long before we kill a dictionary creation process
DICTIONARY_TIMEOUT = 60 * 60

# how many fuzzers should be spun up when a fuzzing job is received
FUZZER_INSTANCES = 4

# where the fuzzer should place it's results on the filesystem
# FUZZER_WORK_DIR = '/media/fuzz-ramdisk'
FUZZER_WORK_DIR = 'hz_fuzzer_output'
