import glob
import os

# for functype manager; it invokes an IDAPython script
# TODO: edit this if it doesn't work
ROOT = os.path.dirname(__file__)
IDA_PATH = glob.glob(r'C:\Program Files\IDA *\idat.exe')[0]
IDA_SCRIPT = os.path.join(ROOT, 'util/ida_func_type.py')
FUNCTYPE_CACHE_PATH = os.path.join(ROOT, 'cache')

if not os.path.isdir(FUNCTYPE_CACHE_PATH):
    os.mkdir(FUNCTYPE_CACHE_PATH)

if not os.path.exists(IDA_SCRIPT):
    print("Check if the following file exists:", IDA_SCRIPT)
    exit(1)

# for harnesor
TRACE_PN = "trace"
FUNCTYPE = "functype"
NORMAL_POSTFIX = "normal"
TRACE_PREFIX = ["DC", "RET", "IC", "IJ"]

THRESHOLD = 0x20
TRACE_MAX = 20
INPUT = "QQQQ"

NAMEDIC = {}
NAMEDIC['CP'] = "Code Pointer"
NAMEDIC['DP'] = "Data Pointer"

# for synthesizer
BINREAD = 0x1000
POINTER_SEARCH_LIMIT = 100
INPUT_COMP_LENGTH = 10