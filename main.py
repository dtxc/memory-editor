# Copyright (c) 2023, thatOneArchUser
# All rights reserved.

# in linux everything is a file
# and we are taking advantage of this

# process memory is stored in /proc/<pid>/mem


import os
import sys
import argparse
import binascii

if os.name != "posix":
    print("Operating system is not supported.")
    sys.exit(1)

nregions = 0 # region count
selected_regions = [] # self explanatory

settings = {
    "int_width": 4, # can be changed from the options command
    "dtype": "int"
}

# byte order
BIG_ENDIAN = "big"
LITTLE_ENDIAN = "little"

# extended ascii map
# non-printable characters are replaced with dots
ascii_map = ['.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', 
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '!', 
    '"', '# ', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', 
    '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 
    'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 
    'X', 'Y', 'Z', '[', '.', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', 
    '|', '}', '~', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',
    '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', 
    '.', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '.', '®', '¯', '°', '±',
    '²', '³', '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿', 'À', 'Á', 'Â', 'Ã',
    'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ',
    'Ö', '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç',
    'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù',
    'ú', 'û', 'ü', 'ý', 'þ', 'ÿ']

# returns the memory regions of a specified process
def get_regions(pid : int):
    ret = {}
    with open(f"/proc/{pid}/maps") as f: # region list is stored in /proc/pid/maps
        for i in f.read().splitlines():
            if "rw-p" in i and "/usr/lib" not in i: # we only need writable regions and exclude the libraries
                t = i.split()
                off = t[0].split("-")
                off[0] = "0x" + off[0].upper() # add 0x to addresses
                off[1] = "0x" + off[1].upper()
                off = '-'.join(off)
                size = int(off.split("-")[1], 16) - int(off.split("-")[0], 16) # region end - region start
                try:
                    _type = t[5] # most likely heap or stack
                    if "/usr/bin" in _type: # executable region (code)
                        _type = "code"
                    if _type == "[heap]":
                        _type = "heap"
                    if _type == "[stack]":
                        _type = "stack"
                except IndexError:
                    _type = "unknown" # other region (still needed)
                
                ret[off] = {"size": size, "type": _type}
                
                global nregions
                nregions += 1
    
    return ret

# converts memory dump to hex dump and prints it
def print_dump(pid : int, start : int, nbytes : int):
    to_print = ""
    idx = 0
    chars = []
    with open(f"/proc/{pid}/mem", "r+b") as f: # read dump as binary
        f.seek(start)
        #for byte in iter(lambda: f.read(1), b''): # for every character in the dump
        for idx in range(nbytes):
            byte = f.read(1)
            if idx == 0:
                to_print += f"{hex(start + idx).upper().replace('0X', '0x')}\t" # add offset to the beginning of the string

            if idx != 0 and idx % 16 == 0: # 16 bytes per line
                to_print += "  |  "
                for char in chars:
                    to_print += ascii_map[ord(char)] # append raw data
                chars = [] # clear raw chars
                to_print += f"\n{hex(start + idx).upper().replace('0X', '0x')}  " # add newline and new offset
            to_print += binascii.hexlify(byte).upper().decode() + " " # decode unsigned character
            chars.append(chr(int(binascii.hexlify(byte).upper().decode(), 16))) # append raw character
    
    if chars != list(): # if raw chars list is not empty
        s = to_print.splitlines()
        lastlen = len(s[len(s) - 1]) # get the length of the last line
        to_print += f"{' ' * (64 - lastlen)}  |  " # add the amount of spaces needed
        for char in chars:
            to_print += ascii_map[ord(char)] # append raw data

    print(to_print) # print hex dump

# search for matches of s in selected regions
def search_mem(pid : int, s):
    matches_map = {}
    for i in range(len(selected_regions)): # for every region...
        lo = int(selected_regions[i].split("-")[0], 16) # low offset
        hi = int(selected_regions[i].split("-")[1], 16) # high offset

        idx = 0
        nbytes = hi - lo
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(lo)
            if settings["dtype"] == "int":
                while idx < nbytes:
                    search = bytearray(int(s).to_bytes(settings["int_width"], LITTLE_ENDIAN)) # convert int to bytearray with little endian order
                    try:
                        if search == bytearray(f.read(settings["int_width"])): # compare search item with current block
                            matches_map[hex(lo + idx)] = s # low offset + index
                    except ValueError:
                        pass
                    idx += settings["int_width"]
            elif settings["dtype"] == "string":
                # we need to do this if the string length is not a multiple of 4, 
                # it calculates how many times the string can fit in the region
                # we use floor division for that
                _iter = int(regions[selected_regions[i]]["size"]) // len(s)
                while idx < _iter:
                    search = bytearray(s.encode())
                    if search == bytearray(f.read(len(s))):
                        matches_map[hex(lo + idx)] = s
                    
                    idx += 1

    return matches_map

def update(pid : int):
    if len(list(mmap.keys())) == 0:
        print("No saved offsets found (try using search <num>)")

    for off in list(mmap.keys()):
        with open(f"/proc/{pid}/mem", "rb") as f:
            lo = int(off, 16)
            f.seek(lo)
            block = f.read(settings["int_width"])
            little = int(binascii.hexlify(block).decode(), 16) # little endian
            big = int(binascii.hexlify(little.to_bytes(settings["int_width"], byteorder=LITTLE_ENDIAN)).decode(), 16) # converted into big endian
            mmap[off] = big

def write_mem(pid : int, off : int, data : bytearray):
    f = open(f"/proc/{pid}/mem", "r+b") # open process memory
    f.seek(off) # go to offset
    f.write(data) # write bytearray
    f.close() # close file

# updates the selected value list and searches for value changes
def mem_refine(pid : int, search):
    update(pid)

    global mmap
    mmap_bak = mmap
    mmap = {}

    for i in list(mmap_bak.keys()):
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(int(i, 16))
            if settings["dtype"] == "int":
                s = bytearray(int(search).to_bytes(settings["int_width"], LITTLE_ENDIAN))
                if s == bytearray(f.read(settings["int_width"])):
                    mmap[i] = search

    return mmap

def set_mem(pid : int, data):
    if len(list(mmap.keys())) == 0:
        print("No saved offsets found (try using search <data>)")
    
    for off in list(mmap.keys()):
        with open(f"/proc/{pid}/mem", "rb") as f:
            if settings["dtype"] == "int":
                arr = bytearray(int(data).to_bytes(settings["int_width"], byteorder=LITTLE_ENDIAN))
                write_mem(pid, int(off, 16), arr)
            elif settings["dtype"] == "string":
                arr = bytearray(data.encode())
                write_mem(pid, int(off, 16), arr)

def get_region_by_offset(off : int):
    for i in range(len(list(regions.keys()))):
        lo = int(list(regions.keys())[i].split("-")[0], 16)
        hi = int(list(regions.keys())[i].split("-")[1], 16)
        if lo <= off <= hi:
            return i + 1
    
    return -1

def print_regions():
    print("\nidx  start\t    end\t\t    size (B)  type\taccess") # i calculated the spaces so it looks perfect
    for i in regions.keys():
        to_print = f"[{list(regions.keys()).index(i)+1}]" # region index
        if i not in selected_regions:
            to_print += " *"
        else:
            to_print += "  "
        
        to_print += f"{i}: {regions[i]['size']}" # offset: size
        to_print += ' ' * (10 - len(str(regions[i]["size"]))) # spaces needed
        to_print += regions[i]["type"] # region type
        to_print += ' ' * (10 - len(regions[i]["type"])) # spaces needed
        to_print += "rw-" # access
        print(to_print)

parser = argparse.ArgumentParser()
parser.add_argument("pid", type=int, help="process id") # sudo python memdump.py <pid>
pid = parser.parse_args().pid

# root access is required to write to memory
if os.geteuid() == 0: # if effective user id is zero (running as root)
    if str(pid) not in os.listdir("/proc"): # pid is not present in running processes
        print("Invalid pid.")
        sys.exit(1)
    
    #  if nregions == 0:
    #      print("No writable regions found.") # idk how you can get this, there are always 3 writable regions, executable, heap and stack
    #      sys.exit(1)

    global regions
    regions = get_regions(pid)
    print(f"Found {nregions} regions")
    selected_regions = list(regions.keys())

    while True:
        cmd = input(">> ").lower().strip() # remove leading and trailing spaces
        argv = cmd.split() # argument vector
        argc = len(argv) # argument count

        if argc == 0: # no command
            continue

        if argv[0] == "dump":
            if argc == 3:
                print_dump(pid, int(argv[1], 16), int(argv[2]))
            else:
                print("dump: reads a memory region and saves it into a file\nusage: dump <address> <bytes>")
        
        elif argv[0] == "write":
            if argc >= 3:
                chars = []
                for i in argv[2:]: # for every argument after 2nd
                    chars.append(int(i, 16))
                data = bytearray(chars) # convert characters to byte array
                write_mem(pid, int(argv[1], 16), data) # write byte array to offset
            else:
                print("write: writes data to a process' memory\nusage: write <address> <data>")
        
        elif argv[0] == "search":
            if argc == 2:
                try:
                    global mmap
                    mmap = search_mem(pid, argv[1])
                    print(f"Found {len(mmap)} matches.")
                except OverflowError:
                    print("search: integer too large, try changing the integer width.")
            else:
                print("search: searches for an integer in the memory\nusage: search <number>")
        
        elif argv[0] == "refine":
            if argc == 2:
                if mmap == {}:
                    print("Nothing selected")
                else:
                    mmap = mem_refine(pid, argv[1])
                    print(f"Found {len(mmap)} matches.")
            else:
                print("refine: updates the current value list and searches for value changes\nusage: refine <number>")

        elif argv[0] == "set":
            if argc == 2:
                try:
                    set_mem(pid, argv[1])
                except OverflowError:
                    print("set: integer too large, try changing the integer width.")
            else:
                print("set: changes the value of an offset\nusage: set <value>")

        elif argv[0] == "options":
            if argc == 3:
                if argv[1] == "set_int_width":
                    try:
                        settings["int_width"] = int(argv[2])
                    except ValueError:
                        print("options: invalid argument")
                elif argv[1] == "set_dtype":
                    types = ["int", "float", "string"]
                    if argv[2] in types:
                        settings["dtype"] = argv[2]
                    else:
                        print("options: invalid argument")
                else:
                    print("options: invalid argument")
            else:
                print("options: changes editor config.\nusage: options <setting> <value>")

        elif argv[0] == "list-regions":
            print_regions()

        elif argv[0] == "update":
            update(pid)

        elif argv[0] == "list":
            for i in mmap.keys():
                region = get_region_by_offset(int(i, 16))
                region_key = list(regions.keys())[region - 1]
                print(f"{i.upper().replace('0X', '0x')}: {mmap[i]} at region {region} ({regions[region_key]['type']})")

        elif argv[0] == "select":
            if argc >= 2:
                for i in argv[1:]:
                    if 0 < int(i) <= nregions:
                        if list(regions.keys())[int(i) - 1] in selected_regions:
                            print("region already selected")
                        else:
                            selected_regions.append(list(regions.keys())[int(i) - 1])
                else:
                    print("select: selects a memory region (all regions are selected by default)\nusage: select <region index>")

        elif argv[0] == "deselect":
            if argc >= 2:
                for i in argv[1:]:
                    if 0 < int(i) <= nregions:
                        selected_regions.remove(list(regions.keys())[int(i) - 1])
                    else:
                        print("Invalid region")
            else:
                print("deselect: deselects a memory region\nusage: deselect <region index>")

        # clears current matches map
        elif argv[0] == "clear":
            mmap = {}

        elif argv[0] == "exit" or argv[0] == "quit":
            sys.exit()
        
        else:
            print(f"{argv[0]}: command not found")
            
else: # not running as root
    print("access denied")
