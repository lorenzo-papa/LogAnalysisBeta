import re, sys, time, glob
import os.path
from os import path
import os, time, datetime, sys, csv, argparse, struct, io, ipaddress

from data_structure import *
from utility import *
from datetime import datetime
from dateutil import parser
from pathlib import Path
from search_functions import *

def open_all_files():

    folders = list(open('Paths/folders.txt'))
    for i in range(len(folders)):
        folders[i] = folders[i].strip('\n')

    logs = list(open('Paths/logs_to_search.txt'))
    for i in range(len(logs)):
        logs[i] = logs[i].strip('\n')

    find_elements = list(open('Paths/what_to_search.txt'))
    for i in range(len(logs)):
        find_elements[i] = find_elements[i].strip('\n')

    print("searching into folder: " + str(folders), "searching into file: " + str(logs),
        "looking for: " + str(find_elements) + '\n')

    return folders,logs,find_elements

def open_specif_file():
    log_file_path = input("Insert the file path in which you would search: ")
    log_file_path=log_file_path.strip()

    if check_if_file_exist(log_file_path):
        file = open(log_file_path,'r')
        return file
    else:
        print("This file does not exist, please enter a valid input")
        return False


def check_date_log(line):

    error_match1 = False
    error_match2 = False
    error_match3 = False
    finale=""

    try:
        match1 = re.search(r"\s*\w{3}\s*\d{1,2}\s*\d{2}\S\d{2}\S\d{2}\s*", line) #1,2 prima era solo 2
        len(match1.group())
    except:
        error_match1 = True
    try:
        match2 = re.search(r"\s*\d{2,4}\S\d{2,4}\S\d{2,4}\s*\d{2,4}\S\d{2,4}\S\d{2,4}\s*", line)
        len(match2.group())
    except:
        error_match2 = True
    try:
        match3 = re.search(r"\s*\w{3}\s*\d{2}\s*\d{2,4}\S\d{2,4}\S\d{2,4}\s*\d{2,4}\s*", line)
        len(match3.group())
    except:
        error_match3 = True

    if error_match1 == True:
        if error_match2 == True:
            if error_match3 == True:
                # non ho trovato nessuna data
                return None
            else:
                # passa solo 3
                finale = match3.group()
        else:
            if error_match3 == True:
                # passa solo 2
                finale = match2.group()
            else:
                # passano solo 2 e 3
                if len(match2.group()) >= len(match3.group()):
                    finale = match2.group()
                else:
                    finale = match3.group()
    else:
        if error_match2 == True:
            if error_match3 == True:
                # passa solo 1
                finale = match1.group()
            else:
                # passa solo 1 e 3
                if len(match1.group()) >= len(match3.group()):
                    finale = match1.group()
                else:
                    finale = match3.group()
        else:
            if error_match3 == True:
                # passano 1 e 2
                if len(match1.group()) >= len(match2.group()):
                    finale = match1.group()
                else:
                    finale = match2.group()
            else:
                # passano 1 2 e 3
                if len(match1.group()) >= len(match2.group()) and len(match1.group()) >= len(match3.group()):
                    finale = match1.group()
                elif len(match2.group()) >= len(match1.group()) and len(match2.group()) >= len(match3.group()):
                    finale = match2.group()
                elif len(match3.group()) >= len(match1.group()) and len(match3.group()) >= len(match2.group()):
                    finale = match3.group()
    try:
        data_finale=parser.parse(finale)
        return data_finale
    except:
        #non ho trovato date
        return None

def check_date_delta(start,end,delta):
    import datetime
    if end and start:
        diff=end-start
        if diff < datetime.timedelta(minutes=int(delta)):
            return True
        else:
            return False
    else: return False

def try_open(file_path):
    try:
        with open(file_path, "r") as file_out:
            file_out.close()
            return True
    except:
        print("Error: non readable file")
        return False

def check_if_file_exist(filename):
    if path.isfile(filename):
        return True
    else:
        return False

def check_if_folder_exist(folder):
    if path.isdir(folder):
        return True
    else:
        return False

def open_dir(dir_path):
    if check_if_folder_exist(dir_path):
        dir_list = os.listdir(dir_path)
        return dir_list

def clean_dir_path(path):
    path=path.strip()
    if path.endswith("/"):
        return path
    else:
        return path+"/"

def open_dir_file_search(dir_path,pattern=""):
    levels=get_dir_depth(dir_path)
    path="/*"
    print(levels)
    for i in range(1,levels):
        print("Deepness",i,glob.glob(dir_path+i*path+pattern))

def get_dir_depth(path, depth=0):
    if not os.path.isdir(path): return depth
    maxdepth = depth
    for entry in os.listdir(path):
        fullpath = os.path.join(path, entry)
        maxdepth = max(maxdepth, get_dir_depth(fullpath, depth + 1))
    return maxdepth

def recursive_dir_search(root_path):
    root = Path(root_path)
    if root.is_dir():
        for path in root.iterdir():
            if path.is_dir():
                print(path)
                recursive_dir_search(path)
            else:
                print(path)

# parsing the utmp binary data -> in csv output
def parseutmp(input_file, ip_blacklist, ip_whitelist):  # , tsv):utmp_filesize, utmp_file

    export_file_path = r"Parser_Output/"
    time_now = str(time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()))
    name = "BinaryParsing" + "_" + time_now + ".csv"
    export_file = export_file_path + name
    row_label = ["type", "pid", "line", "id", "user", "host", "term", "exit", "session", "sec", "usec", "addr"]

    if os.path.exists(input_file):
        with open(input_file, "rb") as utmp_file:
            utmp_filesize = os.path.getsize(input_file)
            if export_file:
                tsv = open(export_file, "w", encoding='UTF-8')
                #with open (export_file, "w+") as tsv:
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
            # else:
            #     tsv = sys.stdout
            #     csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
            STATUS = {
                0: 'EMPTY',  # Record does not contain valid info (formerly known as UT_UNKNOWN on Linux)
                1: 'RUN_LVL',  # Change in system run-level (see init(8))
                2: 'BOOT_TIME',  # Time of system boot (in ut_tv)
                3: 'NEW_TIME',  # Time after system clock change
                4: 'OLD_TIME',  # Time before system clock change
                5: 'INIT_PROCESS',  # Process spawned by init(8)
                6: 'LOGIN_PROCESS',  # Session leader process for user login
                7: 'USER_PROCESS',  # Normal process
                8: 'DEAD_PROCESS',  # Terminated process
                9: 'ACCOUNTING'}  # Not implemented

            record_field = []
            list_Record = []
            pid_list = []
            offset = 0
            while offset < utmp_filesize:
                utmp_file.seek(offset)
                type = struct.unpack("<L", utmp_file.read(4))[0]
                for k, v in STATUS.items():
                    if type == k:
                        type = v
                pid = struct.unpack("<L", utmp_file.read(4))[0]
                line = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
                id = utmp_file.read(4).decode("utf-8", "replace").split('\0', 1)[0]
                user = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
                if "\n" in user:
                    user = user.replace("\n", "/n")
                host = utmp_file.read(256).decode("utf-8", "replace").split('\0', 1)[0]
                term = struct.unpack("<H", utmp_file.read(2))[0]
                exit = struct.unpack("<H", utmp_file.read(2))[0]
                session = struct.unpack("<L", utmp_file.read(4))[0]
                sec = struct.unpack("<L", utmp_file.read(4))[0]
                sec = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(float(sec)))
                usec = struct.unpack("<L", utmp_file.read(4))[0]
                addr = ipaddress.IPv4Address(struct.unpack(">L", utmp_file.read(4))[0])
                record_field.extend([type, pid, line, id, user, host, term, exit, session, sec, usec, addr])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(record_field)
                record_field = []
                offset += 384
                if len(ip_blacklist)>0 and len(ip_whitelist)==0:
                    if host in ip_blacklist:
                        record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                        term=term, exit=exit, session=session, sec=sec, usec=usec,
                                                        addr=addr)
                        list_Record.append(record_utmp_wtmp)
                        pid_list.append(pid)
                    elif pid in pid_list:
                        record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                        term=term, exit=exit, session=session, sec=sec, usec=usec,
                                                        addr=addr)
                        list_Record.append(record_utmp_wtmp)
                elif len(ip_whitelist)>0 and len(ip_blacklist)==0:
                    if host not in ip_whitelist:
                        record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                        term=term, exit=exit, session=session, sec=sec, usec=usec,
                                                        addr=addr)
                        list_Record.append(record_utmp_wtmp)
                else:
                    record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                term=term, exit=exit, session=session, sec=sec, usec=usec, addr=addr)
                    list_Record.append(record_utmp_wtmp)
        utmp_file.close()
        if "utmp" in input_file:
            list_Utmp = list_UtmpRecord(list_Record)
            return (list_Utmp, tsv)
        elif "wtmp" in input_file:
            list_Wtmp = list_WtmpRecord(list_Record)
            return (list_Wtmp, tsv)
        elif "btmp" in input_file:
            list_Btmp = list_BtmpRecord(list_Record)
            return (list_Btmp, tsv)

def type(x):
    return{
        0: 'EMPTY',  # Record does not contain valid info (formerly known as UT_UNKNOWN on Linux)
        1: 'RUN_LVL',  # Change in system run-level (see init(8))
        2: 'BOOT_TIME',  # Time of system boot (in ut_tv)
        3: 'OLD_TIME',  # Time after system clock change (invertiti)
        4: 'NEW_TIME',  # Time before system clock change
        5: 'INIT_PROCESS',  # Process spawned by init(8)
        6: 'LOGIN_PROCESS',  # Session leader process for user login
        7: 'USER_PROCESS',  # Normal process
        8: 'DEAD_PROCESS',  # Terminated process
        9: 'ACCOUNTING'  # No
    }.get(x,'UNKNOWN')

def patrizio(input_file):
    import datetime
    if os.path.exists(input_file):
        with open(input_file, "rb") as utmp_file:
            i=0
            while i<10:
                chunk = utmp_file.read(60)
                if not chunk:
                    break
                s = struct.Struct('>8s 4s 12s l h h h H l 16s L')
                unpacked = s.unpack(chunk)
                timestamp = datetime.datetime.fromtimestamp(int(unpacked[8])).strftime("%Y/%m/%d %H:%M:%S")
                strings = [str(unpacked[0].decode('utf-8')), str(unpacked[3]),
                           str(unpacked[9].decode('utf-8')), str(timestamp)]
                print(strings)
                i+=1

def parseutmp_hp_unix(input_file, ip_blacklist, ip_whitelist):  # , tsv):utmp_filesize, utmp_file

    export_file_path = r"Parser_Output/"
    time_now = str(time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime()))
    name = "BinaryParsing" + "_" + time_now + ".csv"
    export_file = export_file_path + name
    row_label = ["type", "pid", "line", "id", "user", "host", "term", "exit", "session", "sec", "usec", "addr"]

    if os.path.exists(input_file):
        with open(input_file, "rb") as utmp_file:
            utmp_filesize = os.path.getsize(input_file)

            if export_file:
                tsv = open(export_file, "w", encoding='UTF-8')
                #with open (export_file, "w+") as tsv:
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
            # else:
            #     tsv = sys.stdout
            #     csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
            STATUS = {
                0: 'EMPTY',  # Record does not contain valid info (formerly known as UT_UNKNOWN on Linux)
                1: 'RUN_LVL',  # Change in system run-level (see init(8))
                2: 'BOOT_TIME',  # Time of system boot (in ut_tv)
                3: 'OLD_TIME',  # Time after system clock change (invertiti)
                4: 'NEW_TIME',  # Time before system clock change
                5: 'INIT_PROCESS',  # Process spawned by init(8)
                6: 'LOGIN_PROCESS',  # Session leader process for user login
                7: 'USER_PROCESS',  # Normal process
                8: 'DEAD_PROCESS',  # Terminated process
                9: 'ACCOUNTING'}  # Not implemented

            record_field = []
            list_Record = []
            offset = 0

            while offset < utmp_filesize:
                utmp_file.seek(offset) #lettura da inizio file
                #8s 4s 12s l h h h H l 16s L

                user = utmp_file.read(8).decode("utf-8", "replace").split('\0', 1)[0]
                if "\n" in user:
                    user = user.replace("\n", "/n")
                id = utmp_file.read(4).decode("utf-8", "replace").split('\0', 1)[0]
                line = utmp_file.read(12).decode("utf-8", "replace").split('\0', 1)[0]
                pid = struct.unpack(">i", utmp_file.read(4))[0]

                type = struct.unpack(">h", utmp_file.read(2))[0]
                #print(type)
                for k, v in STATUS.items():
                    if type == k:
                        type = v

                term = struct.unpack(">h", utmp_file.read(2))[0]
                exit = struct.unpack(">h", utmp_file.read(2))[0]
                session = struct.unpack(">H", utmp_file.read(2))[0]

                sec = struct.unpack(">l", utmp_file.read(4))[0]
                sec = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(float(sec)))
                #usec = struct.unpack("<L", utmp_file.read(4))[0]
                usec=""

                host = utmp_file.read(16).decode("utf-8", "replace").split('\0', 1)[0]

                addr = ipaddress.IPv4Address(struct.unpack(">L", utmp_file.read(4))[0])

                record_field.extend([type, pid, line, id, user, host, term, exit, session, sec, usec, addr])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(record_field)
                #print("type, pid, line, id, user, host, term, exit, session, sec, usec, addr")
                #print(record_field)
                record_field = []
                offset += 60#384

                if len(ip_blacklist)>0 and len(ip_whitelist)==0:
                    if host in ip_blacklist:
                        record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                        term=term, exit=exit, session=session, sec=sec, usec=usec,
                                                        addr=addr)
                        list_Record.append(record_utmp_wtmp)
                elif len(ip_whitelist)>0 and len(ip_blacklist)==0:
                    if host not in ip_whitelist:
                        record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                        term=term, exit=exit, session=session, sec=sec, usec=usec,
                                                        addr=addr)
                        list_Record.append(record_utmp_wtmp)
                else:
                    record_utmp_wtmp = BinaryRecord(type=type, pid=pid, line=line, id=id, user=user, host=host,
                                                term=term, exit=exit, session=session, sec=sec, usec=usec, addr=addr)
                    list_Record.append(record_utmp_wtmp)
                #i+=1
                  # ricordati sia qua
        utmp_file.close()
        if "utmp" in input_file:
            list_Utmp = list_UtmpRecord(list_Record)
            return (list_Utmp, tsv)
        elif "wtmp" in input_file:
            list_Wtmp = list_WtmpRecord(list_Record)
            return (list_Wtmp, tsv)
        elif "btmp" in input_file:
            list_Btmp = list_BtmpRecord(list_Record)
            return (list_Btmp, tsv)


def get_user_from_line(line):
    result = re.search(r'\sfor(.*?)\sfrom|\suser=(.*?)$|\suser(.*?)\sfrom|\suser\s(.*?)\d', line)
    if result is not None:
        result = result.groups()
        for user in result:
            if user is not None and (user.strip() != "" or user.strip() != " "):
                if 'user' in user:
                    if "user user" in user:
                        user = user.partition('user')[1].strip()
                    elif user.lower().strip() == "user":
                        user = user.strip()
                    elif len(user.strip()) > len("user") and " " not in user.strip():
                        user = user.strip()
                    else:
                        user = user.partition('user')[2].strip()
                elif '=' in user:
                    user = user.partition('=')[2].strip()
                else:
                    user = user.strip()

                return user

def get_session_id(line):
    session_id = re.search(r'sshd\[(.*?)\]', line)
    try:
        if session_id.group(1):
            return session_id.group(1)
        else:
            return None
    except re.error:
        return None

def get_ip_from_line(line):
    ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    for ip in ip_found:
        if ip is not None or ip.strip() != "":
            return ip
    return None

def is_file_empty(file_name):
    os.chdir(r"Parser_Output/")
    if check_if_file_exist(file_name) and os.stat(file_name).st_size == 0:
        os.remove(file_name)
        #print('File is empty')
    #else:
     #   print('File is not empty')

    # CSV REVERT
    # with open(output_file) as fr, open("out.csv", "wb") as fw:
    #     cr = csv.reader(fr, delimiter=";")
    #     cw = csv.writer(fw, delimiter=";")
    #     cw.writerow(next(cr))  # write title as-is
    #     cw.writerows(reversed(list(cr)))


def save_output_json(name_file, object):
    import jsonpickle
    if "Temp_output" not in os.getcwd():
        os.chdir(r"Temp_output/")

    time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
    name_out = name_file+"_"+time_now+".json"

    f = open(name_out, 'w')
    json_obj = jsonpickle.encode(object)
    f.write(json_obj)
    f.close()

def save_output_json_authlog(name_file, object):
    import jsonpickle
    if "AuthLog_Output" not in os.getcwd():
        os.chdir(r"AuthLog_Output/")

    #time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
    name_out = name_file+".json"

    f = open(name_out, 'w')
    json_obj = jsonpickle.encode(object)
    f.write(json_obj)
    f.close()
    #return json_obj


def ask_for_json_file():
    from tkinter import Tk
    from tkinter.filedialog import askopenfilename
    import jsonpickle

    Tk().withdraw()  # we don't want a full GUI, so keep the root window from appearing
    filename = askopenfilename()  # show an "Open" dialog box and return the path to the selected fileprint(filename)
    while filename is None or "":
        filename = askopenfilename()
    while check_if_file_exist(filename) is False:
        filename = askopenfilename()
    f = open(filename)
    json_str = f.read()
    try:
        obj = jsonpickle.decode(json_str)
    except:
        print("Errore in conversione riprovare\n")

    return obj



def load_json_file(filename):
    import jsonpickle

    if check_if_file_exist(filename) and filename.endswith(".json"):
        f = open(filename)
        json_str = f.read()
        try:
            obj = jsonpickle.decode(json_str)
        except:
            print("Errore in conversione riprovare\n")

        return obj
    else:
        print("Insert a valid json file")
        return 0

def create_working_dir():
    path = os.getcwd()
    os.chdir(r""+path+"/")
    if not check_if_folder_exist(path+"/Temp_output"):
        # define the access rights
        access_rights = 0o755
        try:
            os.mkdir(path+"/Temp_output", access_rights)
        except OSError:
            print("Creation of the directory %s failed" % path)

    if not check_if_folder_exist(path+"/Parser_Output"):
        # define the access rights
        access_rights = 0o755
        try:
            os.mkdir(path+"/Parser_Output", access_rights)
        except OSError:
            print("Creation of the directory %s failed" % path)

    if not check_if_folder_exist(path+"/AuthLog_Output"):
        # define the access rights
        access_rights = 0o755
        try:
            os.mkdir(path+"/AuthLog_Output", access_rights)
        except OSError:
            print("Creation of the directory %s failed" % path)


def create_dir(dir):
    path = os.getcwd()
    os.chdir(r""+path+"/")
    if not check_if_folder_exist(path+"/"+dir):
        # define the access rights
        access_rights = 0o755
        try:
            os.mkdir(path+"/"+dir, access_rights)
        except OSError:
            print("Creation of the directory %s failed" % path)


def empty_folder(folder):
    import shutil
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))