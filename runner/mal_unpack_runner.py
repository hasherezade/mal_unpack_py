#!/usr/bin/env python3

"""mal_unpack_runner.py: A Python helper to deploy mal_unpack."""

__author__ = 'hasherezade (hasherezade.net)'
__license__ = "MIT"
__version__ = "1.0"

import sys, os, subprocess
from pathlib import Path
import shutil
import pefile
import uuid
import hashlib
import argparse
try:
    from util_path import UTIL_PATH
except:
    UTIL_PATH="..\\bin\\"
    
MAL_UNPACK_EXE = "mal_unpack.exe"
DLL_LOAD64 = "dll_load64.exe"
DLL_LOAD32 = "dll_load32.exe"
DUMPS_DIR = "dumps"

def mal_unp_res_to_str(returncode):
    if returncode == (-1):
        return "ERROR"
    if returncode == 0:
        return "INFO"
    if returncode == 1:
        return "NOT_DETECTED"
    if returncode == 2:
        return "DETECTED"
    return hex(returncode)

def get_config(sample):
    null_config = (None, None)
    try:
        pe = pefile.PE(sample, fast_load=True)
        if pe is None:
            return null_config
        is_dll = False
        if (pe.is_exe() == False):
            is_dll = True
        is_64b = None
        if (pe.OPTIONAL_HEADER.Magic == 0x10b):
            is_64b = False
        elif (pe.OPTIONAL_HEADER.Magic == 0x20b):
            is_64b = True     
        pe.close()
        if (is_64b == None):
            return null_config   
        return (is_64b, is_dll)
    except:
        return null_config   
        
def rename_sample(sample, is_dll):
    p = Path(sample)
    new_ext = ".exe"
    if (is_dll):
        new_ext = ".dll"
    new_name = p.stem + new_ext
    directory = str(p.parent)
    p.rename(Path(p.parent, new_name))
    abs_name = directory + os.path.sep + new_name 
    return abs_name
    
def log_mal_unp_out(outstr, dump_dir, filename):
    if outstr is None:
        return
    if not os.path.exists(dump_dir):
        os.makedirs(dump_dir)
    filepath = dump_dir + os.path.sep + filename
    with open(filepath, "ab") as handle:
        handle.write(outstr)
  
def run_and_dump(sample, is_64b, is_dll, timeout, sample_out_dir, root_out_dir):

    print("Is 64b: " + str(is_64b))
    print("Is DLL: " + str(is_dll))
    
    orig_name = sample
    sample = rename_sample(sample, is_dll)
    print("Sample name: " + sample)
    cmd = [ os.path.join(UTIL_PATH, MAL_UNPACK_EXE),
    '/timeout' , str(timeout),
    '/dir', sample_out_dir,
    '/img', sample,
    '/hooks', '1',
    '/shellc' , '1',
    '/trigger', 'T'
    ]
    
    exe_name = sample
    if is_dll:
        cmd.append('/cmd')
        cmd.append(sample + ' #1') #run the first exported function
        if is_64b:
            exe_name = os.path.join(UTIL_PATH, DLL_LOAD64)
        else:
            exe_name = os.path.join(UTIL_PATH, DLL_LOAD32)

    cmd.append('/exe')
    cmd.append(exe_name)
    result = subprocess.run(cmd, check=False, capture_output=True)
    os.remove(sample)
    if (result.returncode is None):
        print("mal_unpack failed to run")
        return
    print("mal_unpack result: " + mal_unp_res_to_str(result.returncode))
    log_mal_unp_out(result.stdout, root_out_dir, "mal_unp.stdout.txt")
    log_mal_unp_out(result.stderr, root_out_dir, "mal_unp.stderr.txt")

def calc_sha(filename):
    with open(filename, "rb") as f:
        rbytes = f.read()
        sha_digest = hashlib.sha256(rbytes).hexdigest()
        return sha_digest
        
def unpack_file(orig_file, timeout, out_dir):

    sample_hash = calc_sha(orig_file)
    task_name = str(uuid.uuid4())
    print("File: " + orig_file)
    print("sha256: " + sample_hash)
    print("task ID: " + task_name)
    
    print("starting...")    
    sample_out_dir = out_dir + os.path.sep + sample_hash

    is_64b, is_dll = get_config(orig_file)
    if is_64b == None:
        print("[-] Not a valid PE")
        return
        
    shutil.copy(orig_file, task_name)
    run_and_dump(task_name, is_64b, is_dll, timeout, sample_out_dir, out_dir)
    
def unpack_dir(rootdir, timeout, out_dir):
    for subdir, dirs, files in os.walk(rootdir):
        for file in files:
            filepath = str(os.path.join(subdir, file))   
            if not os.path.isfile(filepath):
                # it is a directory, walk recursively:
                unpack_dir(filepath, timeout, out_dir)
                continue
            print(filepath)
            unpack_file(filepath, timeout, out_dir)
        
def main():

    # check required elements:
    if not os.path.isfile(os.path.join(UTIL_PATH, MAL_UNPACK_EXE)):
        print("[ERROR] MalUnpack binary missing. Please copy \'" + MAL_UNPACK_EXE + "\' to the \'" + UTIL_PATH + "\' directory")
        return
    if not os.path.isfile(os.path.join(UTIL_PATH, DLL_LOAD64)):
        print("[ERROR] DLL load binary missing. Please copy \'" + DLL_LOAD64 + "\' to the \'" + UTIL_PATH + "\' directory")
        return
    if not os.path.isfile(os.path.join(UTIL_PATH, DLL_LOAD32)):
        print("[ERROR] DLL load binary missing. Please copy \'" + DLL_LOAD32 + "\' to the \'" + UTIL_PATH + "\' directory")
        return
        
    # parse input arguments:
    parser = argparse.ArgumentParser(description="MalUnpack Runner")
    parser.add_argument('--inpath', dest="inpath", default=None, help="Malware(s) to be unpacked: it can be a file or a directory",
                            required=True)
    parser.add_argument('--outpath', dest="outpath", default=DUMPS_DIR, help="The directory where the output will be dumped")
    parser.add_argument('--timeout', dest="timeout", default=1000, help="Timeout, default = 1000", type=int)
    args = parser.parse_args()
    
    # run:
    isFile = False
    if os.path.isfile(args.inpath):
        isFile = True
    elif os.path.isdir(args.inpath):
        isFile = False
    else:
        print("[ERROR] The given path does not exist" + args.inpath)
        return

    timeout = args.timeout
    if isFile:
        unpack_file(args.inpath, timeout, args.outpath)
    else:
        unpack_dir(args.inpath, timeout, args.outpath)

if __name__ == "__main__":
    main()
    
