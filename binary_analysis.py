#from https://gist.github.com/4n6ist/99241df331bb06f393be935f82f036a5
import copy
import os, time, datetime, sys, csv, argparse, struct, io, ipaddress

import ip_search
from ip_search import *
from data_structure import *
from dateutil import parser
import re, numpy as np
from utility import *
from termcolor import colored
import termtables as tt
#/var/run/utmp   args.input   args.output
#/var/log/wtmp

# code execution for single file
def utmp_wtmp_btmp_parse_call(input_file,threshold_BF_time,threshold_BF_count,threshold_SA_count,threshold_SA_time, ip_blacklist, ip_whitelist, hp_ux):#outputfile
    # utmp structure (data displayed)
    # sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    if check_if_file_exist(input_file):
        #(list_record_UWtmp,tsv)=parseutmp_hp_unix(input_file, ip_blacklist, ip_whitelist) #parseutmp
        #patrizio(input_file)
        if hp_ux:
            (list_record_UWtmp, tsv) = parseutmp_hp_unix(input_file, ip_blacklist, ip_whitelist)
        else:
            (list_record_UWtmp, tsv) = parseutmp(input_file, ip_blacklist, ip_whitelist)

        (host_ip_founded, pid_founded, user_founded) = binary_first_search(list_record_UWtmp, tsv)
        if isinstance(list_record_UWtmp, list_BtmpRecord):
            (failed_ip_count,failed_user_count,failed_host_name,failed_user_name)=failed_btmp_correlation(host_ip_founded, user_founded, list_record_UWtmp, tsv)
            (BF_list_host,BF_list_host_times,BF_list_user,BF_list_user_times)=\
                btmp_BF_analysis(list_record_UWtmp, tsv,host_ip_founded,user_founded,failed_ip_count,failed_user_count,threshold_BF_time,threshold_BF_count)
            (list_host_SA,list_user_SA,list_date_SA)=spray_attack(list_record_UWtmp, tsv, threshold_SA_count, threshold_SA_time)

            #btmp_output = BtmpOutput(list_record_UWtmp, failed_ip_count, failed_user_count, failed_host_name, failed_user_name,
                                     #BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times,
                                     #list_host_SA, list_user_SA, list_date_SA)
            #save_output_json(btmp_output.name, btmp_output)

        elif isinstance(list_record_UWtmp, list_WtmpRecord):
            list_wtmp_logins=wtmp_sessions_identification(list_record_UWtmp, tsv)
            #rende json l'oggetto (list_wtmp_logins)
            save_output_json(list_wtmp_logins.name,list_wtmp_logins)
            #json=ask_for_json_file()
            #for record in json.record_list:
               # print(record.host)
    else:
        print("No input file found")
        sys.exit(1)

def binary_first_search(list_record,tsv):#,threshold_BF_time,threshold_BF_count):
    host_ip_founded=[]
    pid_founded=[]
    user_founded=[]
    remote_connections=[]
    for record in list_record.record_list:
        if record.pid not in pid_founded and record.pid!="" and record.pid is not None:
            #print("PID: ",record.pid)
            pid_founded.append(record.pid)
        if record.host not in host_ip_founded and record.host!="" and record.host is not None:
            #print("HOST: ",record.host)
            host_ip_founded.append(record.host)
            if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",record.host):
                remote_connections.append(record.host)
        if record.user not in user_founded and record.user!="" and record.user is not None:
            #print("USER: ",record.user)
            user_founded.append(record.user)

    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    ip_report = "Total different IP address founded: ", len(host_ip_founded)
    #print(ip_report)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(ip_report)
    #print(host_ip_founded)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(host_ip_founded)


    remote_connection_report = "There were remote connections (or attempts) from: ", len(remote_connections)
    #print(remote_connection_report)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(remote_connection_report)
    #print(remote_connections)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(remote_connections)

    pid_report = "Total different PID founded: ", len(pid_founded)
    #print(pid_report)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(pid_report)
    #print(pid_founded)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(pid_founded)

    user_report = "Total different Users founded: ", len(user_founded)
    #print(user_report)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(user_report)
    #print(user_founded)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(user_founded)

    return (host_ip_founded,pid_founded,user_founded)


#capturing data from btmp what ip addresses and what users
def failed_btmp_correlation(host_ip_founded_btmp,user_founded_btmp,list_record_btmp,tsv):

    failed_ip_count=np.zeros(len(host_ip_founded_btmp),dtype=np.int64)
    failed_user_name=["" for x in range(len(host_ip_founded_btmp))]#user_founded_btmp
    failed_user_count=np.zeros((len(user_founded_btmp)),dtype=np.int64)
    failed_host_name = ["" for x in range(len(user_founded_btmp))]
    for record_btmp in list_record_btmp.record_list:
        if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", record_btmp.host):
            for i in range(len(host_ip_founded_btmp)):
                if host_ip_founded_btmp[i]==record_btmp.host:
                    failed_ip_count[i]+=1
                    if record_btmp.user not in failed_user_name[i]:
                        failed_user_name[i] += record_btmp.user +";"
        for i in range(len(user_founded_btmp)):
            if record_btmp.user == user_founded_btmp[i]:
                failed_user_count[i]+=1
                if record_btmp.host not in failed_host_name[i]:
                    failed_host_name[i] += record_btmp.host + ";"

    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    ip_table=[]
    user_table=[]
    reduce_host_output=False
    reduce_user_output=False
    #todo potrei metterli da config file così da decidere quanti mostrarne
    if len(host_ip_founded_btmp)>15:
        reduce_host_output=True
    if len(user_founded_btmp)>15:
        reduce_user_output=True
    for i in range(len(host_ip_founded_btmp)):
        row_ip="Tot failed attempts from ip:", host_ip_founded_btmp[i], failed_ip_count[i], "with users:", failed_user_name[i]
        if reduce_host_output:
            if failed_ip_count[i]>20:
                tot_user_ip=failed_user_name[i].split(";")
                if len(tot_user_ip)>10:
                    j=0
                    user_to_print=""
                    while j<10:
                        user_to_print+=tot_user_ip[j]+";"
                        j += 1
                    user_to_print = (user_to_print[:70] + '..') if len(user_to_print) > 70 else user_to_print
                    user_to_print+="+"+str(len(tot_user_ip)-10)+"more"
                    ip_table.append([host_ip_founded_btmp[i], failed_ip_count[i],user_to_print])
                else:
                    ip_table.append([host_ip_founded_btmp[i], failed_ip_count[i], failed_user_name[i]])
        else:
            tot_user_ip = failed_user_name[i].split(";")
            if len(tot_user_ip) > 10:
                j = 0
                user_to_print = ""
                while j < 10:
                    user_to_print += tot_user_ip[j] + ";"
                    j+=1
                user_to_print = (user_to_print[:70] + '..') if len(user_to_print) > 70 else user_to_print
                user_to_print += "+" + str(len(tot_user_ip) - 10) + "more"
                ip_table.append([host_ip_founded_btmp[i], failed_ip_count[i], user_to_print])
            else:
                ip_table.append([host_ip_founded_btmp[i], failed_ip_count[i], failed_user_name[i]])
        #print(row_ip)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_ip)
    for i in range(len(user_founded_btmp)):
        row_user="Tot failed attempts from user: ", user_founded_btmp[i], failed_user_count[i],"with hostname:", failed_host_name[i]
        if reduce_user_output:
            if failed_user_count[i]>20:
                tot_ip_user = failed_host_name[i].split(";")
                if len(tot_ip_user) > 10:
                    j = 0
                    host_to_print = ""
                    while j < 10:
                        host_to_print += tot_ip_user[j] + ";"
                        j += 1
                    host_to_print = (host_to_print[:80] + '..') if len(host_to_print) > 80 else host_to_print
                    host_to_print += "+" + str(len(tot_ip_user) - 10) + "more"
                    user_table.append([user_founded_btmp[i], failed_user_count[i], host_to_print])
                else:
                    user_table.append([user_founded_btmp[i], failed_user_count[i], failed_host_name[i]])
        else:
            tot_ip_user = failed_host_name[i].split(";")
            if len(tot_ip_user) > 10:
                j = 0
                host_to_print = ""
                while j < 10:
                    host_to_print += tot_ip_user[j] + ";"
                    j += 1
                host_to_print = (host_to_print[:80] + '..') if len(host_to_print) > 80 else host_to_print
                host_to_print += "+" + str(len(tot_ip_user) - 10) + "more"
                user_table.append([user_founded_btmp[i], failed_user_count[i], host_to_print])
            else:
                user_table.append([user_founded_btmp[i], failed_user_count[i], failed_host_name[i]])
        #print(row_user)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_user)

    #print report of IP
    if len(ip_table)>0:
        string = tt.to_string(
            [ip_table],
            header=["IP", "Failed login", "Usernames used"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)
    #print report of users
    if len(user_table)>0:
        string = tt.to_string(
            [user_table],
            header=["User", "Failed login", "IP used"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    return (failed_ip_count, failed_user_count,host_ip_founded_btmp, user_founded_btmp)


#correlating login and logout in wtmp (through pid)
def wtmp_sessions_identification(list_record_wtmp, tsv):
    # wtmp login logout correlation
    list_record_login=[]
    list_record_logout=[]
    list_wtmp_connection=[]
    row_session=""
    ip_list=[]
    user_for_ip=[]
    for record_wtmp in list_record_wtmp.record_list:
        if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", record_wtmp.host):
            list_record_login.append(record_wtmp)
        if record_wtmp.type == 'DEAD_PROCESS':
            list_record_logout.append(record_wtmp)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    session_to_print=[]
    for login_record in list_record_login:
        row_session = "There was a session from ip", login_record.host, "with user", login_record.user, "pid", \
                      login_record.pid, "start", login_record.sec
        wtmpsession = wtmp_Session(login_record.host, login_record.user, login_record.pid, login_record.sec,
                                   type=get_ip_type(login_record.host))

        for logout_record in list_record_logout:
            if logout_record.pid == login_record.pid:
                end = parser.parse(logout_record.sec)
                start = parser.parse(login_record.sec)
                if end >= start:
                    tot_time = end-start
                    #host, user, pid, start, end = None, tot_time = None
                    wtmpsession.end=logout_record.sec
                    wtmpsession.tot_time=tot_time
                    row_session+="end",logout_record.sec,"elapsed time",str(tot_time)
                    break
        if login_record.host not in ip_list:
            ip_list.append(login_record.host)
            wtmpsession.first_time = True
            user_for_ip.append(login_record.user)
        else:
            x=ip_list.index(login_record.host)
            if login_record.user not in user_for_ip[x]:
                wtmpsession.first_time = True
                user_for_ip[x]+=login_record.user+";"

        session_to_print.append([wtmpsession.host, wtmpsession.first_time, wtmpsession.type, wtmpsession.user, wtmpsession.pid,
                                 wtmpsession.start, wtmpsession.end, wtmpsession.tot_time])
        list_wtmp_connection.append(wtmpsession)
        #print(row_session)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_session)

    #for wtmpsession in list_wtmp_connection:
        #print(wtmpsession.host, wtmpsession.user, wtmpsession.pid, wtmpsession.start, wtmpsession.end, wtmpsession.tot_time)
    if len(session_to_print)>0:
        string = tt.to_string(
            [session_to_print],
            header=["Session IP", "First Login", "Type", "Username", "PID", "Start date", "End date", "Elapsed time"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    wtmp_list_session = list_wtmp_Session(list_wtmp_connection)
    return wtmp_list_session


#looking fro BF for IP or User
def btmp_BF_analysis(list_btmp_record,tsv,host_ip_founded,user_founded,failed_ip_count,failed_user_count,
                     threshold_BF_time,threshold_BF_count):

    BF_host_table = []
    BF_list_host_to_check = []
    BF_list_host=[]
    BF_list_host_times=[]
    for host in host_ip_founded:
        if failed_ip_count[host_ip_founded.index(host)] >= threshold_BF_count:
            list_times_host_attack = []
            date_host = []
            for record_btmp in list_btmp_record.record_list:
                if record_btmp.host == host:
                    date_host.append(parser.parse(record_btmp.sec))#then look for delta from first and subsequent
            if date_host != None:
                count=0
                i=0
                start = date_host[i]
                while i < len(date_host)-1:
                    end = date_host[i+1]
                    i += 1
                    if check_date_delta(start, end, threshold_BF_time):
                        count+=1
                    else:
                        start = date_host[i]
                        count=0
                    if count==threshold_BF_count:
                        list_times_host_attack.append(host)
                        count=0

            if len(list_times_host_attack)>1:
                #print("ATTENTION: Brute Force Attack","It has been found that the host",host,"has done",str(threshold_BF_count),"failed login in",str(threshold_BF_time),"minutes",
                 #     str(len(list_times_host_attack)), "times", "from", str(date_host[0]), "to", str(date_host[len(date_host)-1]))
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
                bf_report_host = ("ATTENTION: Brute Force Attack","It has been found that the host",host,"has done",str(threshold_BF_count),
                                  "failed login in",str(threshold_BF_time),"minutes",str(len(list_times_host_attack)), "times",
                                  "from", str(date_host[0]), "to", str(date_host[len(date_host)-1]))
                #print(colored(bf_report_host, "red"))
                BF_host_table.append([str(len(list_times_host_attack)),host,str(threshold_BF_count),str(threshold_BF_time),
                                      str(date_host[0]),str(date_host[len(date_host)-1])])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(bf_report_host)
                BF_list_host.append(host)
                if get_ip_type(host)=="Public":
                    BF_list_host_to_check.append(host)
                BF_list_host_times.append(date_host)

    if len(BF_host_table)>0:
        print(colored("IP Brute force attack/s founded:","red"))
        string = tt.to_string(
            [BF_host_table],
            header=["N° Brute Force Attack", "IP used", "Failed login", "In x minutes", "Start date", "End date"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    BF_list_user = []
    BF_list_user_times = []
    BF_user_table = []
    for user in user_founded:
        if failed_user_count[user_founded.index(user)] >= threshold_BF_count:
            list_times_user_attack = []
            date_user = []
            for record_btmp in list_btmp_record.record_list:
                if record_btmp.user == user:
                    date_user.append(parser.parse(record_btmp.sec))  # then look for delta from first and subsequent
            if date_user != None:
                count = 0
                i = 0
                start = date_user[i]
                while i < len(date_user) - 1:
                    end = date_user[i + 1]
                    i += 1
                    if check_date_delta(start, end, threshold_BF_time):
                        count += 1
                    else:
                        start = date_user[i]
                        count = 0
                    if count == threshold_BF_count:
                        list_times_user_attack.append(user)
                        count = 0

            if len(list_times_user_attack) > 1:
                # print("ATTENTION: Brute Force Attack","It has been found that the user \"", user, "\" has done", str(threshold_BF_count), "failed login in", str(threshold_BF_time),
                #       "minutes", str(len(list_times_user_attack)), "times", "from", str(date_user[0]), "to", str(date_user[len(date_user)-1]))
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
                bf_report_user = ("ATTENTION: Brute Force Attack","It has been found that the user \"", user, "\" has done", str(threshold_BF_count),
                                  "failed login in", str(threshold_BF_time),"minutes", str(len(list_times_user_attack)), "times",
                                  "from", str(date_user[0]), "to", str(date_user[len(date_user)-1]))
                #print(colored(bf_report_user,"red"))
                BF_user_table.append(
                    [str(len(list_times_user_attack)), user, str(threshold_BF_count), str(threshold_BF_time),
                     str(date_user[0]), str(date_user[len(date_user) - 1])])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(bf_report_user)
                BF_list_user.append(user)
                BF_list_user_times.append(date_user)

    if len(BF_user_table) > 0:
        print(colored("Username Brute Force attack/s founded:", "red"))
        string = tt.to_string(
            [BF_user_table],
            header=["N° Brute Force Attack", "Username used", "Failed login", "In x minutes", "Start date", "End date"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)


    if len(BF_list_host_to_check)>0:
        ip_search.multiple_ip_search(BF_list_host_to_check)
    if len(BF_list_host)==0:
        print(colored("Brute Force attack by IP not found","green"))
    if len(BF_list_user)==0:
        print(colored("Brute Force attack on Username not found","green"))
    # after have seen a BF attack get the hosts and usernames to check if there was a login after it
    return (BF_list_host,BF_list_host_times,BF_list_user,BF_list_user_times)


def wtmp_btmp_correlation(input_btmp, input_wtmp, input_json_wtmp, input_json_btmp, threshold_BF_time, threshold_BF_count,
                          brute_force_threshold_success, threshold_BF_time_login_search,
                          threshold_BF_time_login_search_max,threshold_SA_count, threshold_SA_time,
                          ip_black_list, ip_white_list, hp_ux):#outputfile
    # utmp structure (data displayed)
    # sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    if input_json_wtmp is not None and input_json_btmp is not None:
        list_wtmp_logins = load_json_file(input_json_wtmp)
        # BTMP
        # ANALYSIS
        export_file_path = r"Parser_Output/"
        time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
        name = "Btmp and Wtmp attack anlysis" + " " + time_now + ".csv"
        export_file = export_file_path + name
        tsv_analysis = open(export_file, "w", encoding='UTF-8')

        print("BTMP ANALYSIS OUTPUT")
        csv.writer(tsv_analysis, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(
            "BTMP ANALYSIS OUTPUT")
        btmp_analysis = load_json_file(input_json_btmp)
        check_login_after_BF(btmp_analysis.BF_list_host, btmp_analysis.BF_list_host_times,
                             btmp_analysis.BF_list_user, btmp_analysis.BF_list_user_times,
                             list_wtmp_logins, threshold_BF_time_login_search, threshold_BF_time_login_search_max,
                             tsv_analysis)

        check_login_during_SprayAttack(btmp_analysis.list_host_SA, btmp_analysis.list_user_SA,
                                       btmp_analysis.list_date_SA, list_wtmp_logins,
                                       threshold_BF_time_login_search, threshold_BF_time_login_search_max, tsv_analysis)

        print("CORRELATION BETWEEN BTMP AND WTMP INFO")
        csv.writer(tsv_analysis, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(
            "CORRELATION BETWEEN BTMP AND WTMP INFO")
        list_record_Wtmp=[]
        login_error_success(list_record_Wtmp, btmp_analysis.list_record_UWtmp, tsv_analysis, brute_force_threshold_success,
                            list_wtmp_logins, btmp_analysis.failed_ip_count, btmp_analysis.failed_user_count,
                            btmp_analysis.failed_host_name, btmp_analysis.failed_user_name,
                            ip_black_list, ip_white_list)

    elif check_if_file_exist(input_btmp) and check_if_file_exist(input_wtmp):#check if handles also hp-ux
        if hp_ux:
            (list_record_UWtmp, tsv) = parseutmp_hp_unix(input_btmp,ip_black_list, ip_white_list)
            (list_record_UWtmp, tsv) = parseutmp_hp_unix(input_wtmp, ip_black_list, ip_white_list)
        else:
            #BTMP
            (list_record_Btmp, tsv) = parseutmp(input_btmp,ip_black_list, ip_white_list)
            #WTMP
            (list_record_Wtmp, tsv) = parseutmp(input_wtmp, ip_black_list, ip_white_list)
        #ANALYSIS
        export_file_path = r"Parser_Output/"
        time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
        name = "Btmp and Wtmp attack anlysis" + " " + time_now + ".csv"
        export_file = export_file_path + name
        tsv_analysis = open(export_file, "w", encoding='UTF-8')

        print("WTMP ANALYSIS OUTPUT")
        csv.writer(tsv_analysis, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("WTMP ANALYSIS OUTPUT")
        (host_ip_founded_wtmp, pid_founded_wtmp, user_founded_wtmp) = binary_first_search(list_record_Wtmp,tsv_analysis)
        list_wtmp_logins = wtmp_sessions_identification(list_record_Wtmp, tsv_analysis)

        print("BTMP ANALYSIS OUTPUT")
        csv.writer(tsv_analysis, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("BTMP ANALYSIS OUTPUT")
        (host_ip_founded_btmp, pid_founded_btmp, user_founded_btmp) = binary_first_search(list_record_Btmp, tsv_analysis)
        (failed_ip_count, failed_user_count, failed_host_name, failed_user_name)=\
            failed_btmp_correlation(host_ip_founded_btmp, user_founded_btmp, list_record_Btmp, tsv_analysis)
        (BF_list_host_btmp, BF_list_host_times_btmp, BF_list_user_btmp, BF_list_user_times_btmp) = \
            btmp_BF_analysis(list_record_Btmp, tsv_analysis, host_ip_founded_btmp, user_founded_btmp,failed_ip_count,
                         failed_user_count, threshold_BF_time, threshold_BF_count)

        check_login_after_BF(BF_list_host_btmp, BF_list_host_times_btmp, BF_list_user_btmp, BF_list_user_times_btmp,
                             list_wtmp_logins, threshold_BF_time_login_search, threshold_BF_time_login_search_max,
                             tsv_analysis)

        (list_host_SA, list_user_SA, list_date_SA)=spray_attack(list_record_Btmp, tsv_analysis, threshold_SA_count, threshold_SA_time)
        check_login_during_SprayAttack(list_host_SA, list_user_SA, list_date_SA, list_wtmp_logins,
                         threshold_BF_time_login_search, threshold_BF_time_login_search_max, tsv)

        print("CORRELATION BETWEEN BTMP AND WTMP INFO")
        csv.writer(tsv_analysis, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("CORRELATION BETWEEN BTMP AND WTMP INFO")
        login_error_success(list_record_Wtmp,list_record_Btmp,tsv_analysis,brute_force_threshold_success,list_wtmp_logins,
                            failed_ip_count,failed_user_count, failed_host_name,failed_user_name, ip_black_list, ip_white_list)
    else:
        print("No input file found")
        sys.exit(1)


#CORRELATION OF SESSION INFO THROUGH BTMP AND WTMP FILE       --> TODO SE VUOLE SOLO IP PUBBLICI CAMBIARE L'OR
def check_login_after_BF(BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times, list_wtmp_logins,
                         threshold_BF_time_login_search, threshold_BF_time_login_search_max, tsv):
    import datetime
    ip_to_check = []
    minutes_delta = datetime.timedelta(minutes=threshold_BF_time_login_search)
    hours_delta = datetime.timedelta(hours=threshold_BF_time_login_search_max)
    if len(BF_list_host)>0:
        host_login_during_BF=[]
        for BF_host_time in BF_list_host_times:
            #for BF_host_data in BF_host_time:    #todo use only start and end of attack
            BF_host_data_start = BF_host_time[0]
            BF_host_data_end = BF_host_time[len(BF_host_time)-1]
                #host,user,pid,start,end=None,tot_time=None
            for login_record in list_wtmp_logins.record_list:
                #if ip_search.is_ip_public(login_record.host,stamp=False) or login_record.host in BF_list_host: #check if ip logged is public or in BF list
                start = BF_host_data_start #- datetime.timedelta(minutes=threshold_BF_time_login_search)
                end = BF_host_data_end + minutes_delta
                large_end = BF_host_data_end + hours_delta
                if start <= parser.parse(login_record.start) <= end:
                    login_record.is_in_attack_time_byIP = True
                    if login_record not in host_login_during_BF:
                        host_login_during_BF.append(login_record) #so i have host, time and user
                    if get_ip_type(login_record.host)=="Public" and login_record.host not in ip_to_check:
                        ip_to_check.append(login_record.host)
                    # possibile ottimizzare?
                    if login_record.host in BF_list_host:
                        login_record.IP_in_attack = True
                    if login_record.user in BF_list_user:
                        login_record.User_in_attack = True
                elif end < parser.parse(login_record.start) < large_end:
                    if login_record.host in BF_list_host:
                        login_record.IP_in_attack = True
                    if login_record.user in BF_list_user:
                        login_record.User_in_attack = True
        host_ip_report=("HOST IP LOGIN WHILE/AFTER BF:", str(len(host_login_during_BF)))
        print(host_ip_report)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(host_ip_report)
        host_login_after_BF_table=[]
        for login_record in list_wtmp_logins.record_list:
            if login_record.is_in_attack_time_byIP == True:
                #print(login_record.host,login_record.user,login_record.start,login_record.pid)
                #for i in range(len(host_login_during_BF)):
                single_ip_report=("Login found from ip:", login_record.host, "with user:",
                                  login_record.user, "pid", login_record.pid, "at" , login_record.start,
                                  "end", login_record.end,"elapsed time", str(login_record.tot_time))
                #print(single_ip_report)
                host_login_after_BF_table.append([login_record.host,
                                  login_record.user, login_record.pid,login_record.start,
                                  login_record.end, str(login_record.tot_time)])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_ip_report)

            # if login_record.IP_in_attack == True:
            #     print("IP in attack", login_record.host)
            # if login_record.User_in_attack == True:
            #     print("User in attack", login_record.user)
        #print(colored("HOST LOGIN DURING END AFTER BF:","red"))
        if len(host_login_after_BF_table)>0:
            string = tt.to_string(
                [host_login_after_BF_table],
                header=["IP logged", "Username","PID","Start date", "End date","Elapsed Time"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)

    if len(BF_list_user)>0:
        user_login_during_BF = []
        for BF_user_time in BF_list_user_times:
            #for BF_user_data in BF_user_time:  #todo use only start and end of attack
            BF_user_data_start = BF_user_time[0]
            BF_user_data_end = BF_user_time[len(BF_user_time) - 1]
            for login_record in list_wtmp_logins.record_list:
                if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", login_record.host):
                        # and(ip_search.is_ip_public(login_record.host,stamp=False) or login_record.user in BF_list_user) \
                         # check if ip logged is public or user in BF list
                    start = BF_user_data_start #- datetime.timedelta(minutes=threshold_BF_time_login_search)
                    end = BF_user_data_end + minutes_delta
                    large_end = BF_user_data_end + hours_delta
                    if start <= parser.parse(login_record.start) <= end:
                        login_record.is_in_attack_time_onUser = True
                        if login_record not in user_login_during_BF:
                            user_login_during_BF.append(login_record)  # so i have host, time and user
                        if login_record.host not in ip_to_check and get_ip_type(login_record.host) == "Public":
                            ip_to_check.append(login_record.host)
                        #possibile ottimizzare?
                        if login_record.host in BF_list_host:
                            login_record.IP_in_attack = True
                        if login_record.user in BF_list_user:
                            login_record.User_in_attack = True
                    elif end < parser.parse(login_record.start) < large_end:
                        if login_record.host in BF_list_host:
                            login_record.IP_in_attack = True
                        if login_record.user in BF_list_user:
                            login_record.User_in_attack = True
        user_report = ("USER LOGIN WHILE/AFTER BF: ",str(len(user_login_during_BF)))
        print(user_report)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(user_report)
        user_login_after_BF_table = []
        for login_record in list_wtmp_logins.record_list:
            if login_record.is_in_attack_time_onUser == True:
                #print(login_record.host, login_record.user, login_record.start, login_record.pid)
                #for i in range(len(user_login_during_BF)):
                single_user_report=("Login found from user:",login_record.user, "with ip",  login_record.host,
                                    "pid", login_record.pid, "at" , login_record.start, "end", login_record.end,
                                    "elapsed time", str(login_record.tot_time))
                #print(single_user_report)
                user_login_after_BF_table.append([login_record.user, login_record.host,
                                     login_record.pid, login_record.start, login_record.end,
                                     str(login_record.tot_time)])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_user_report)

            # if login_record.IP_in_attack == True:
            #     print("zIP in attack", login_record.host)
            # if login_record.User_in_attack == True:
            #     print("zUser in attack", login_record.user)
        #print(colored("USER LOGIN DURING END AFTER BF:", "red"))
        if len(user_login_after_BF_table)>0:
            string = tt.to_string(
                [user_login_after_BF_table],
                header=["Username", "IP logged", "PID", "Start date", "End date", "Elapsed Time"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)

    if len(ip_to_check)>0:
        print("Looking for info about the IP founded:")
        multiple_ip_search(ip_to_check)

#looking for brute force attack -> success
#probably combining these info with auth.log the bb attack will be predicted in optimal way
def login_error_success(list_record_wtmp,list_record_btmp,tsv,brute_force_threshold, list_wtmp_session, failed_ip_count,failed_user_count,
                        failed_host_name,failed_user_name, ip_black_list, ip_white_list):
    # TODO AGGIUNGERE % NELLA SEVERITY
    start_time=time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(0))
    # size=0
    # for wtmp_record in list_wtmp_session.record_list:
    #     if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", wtmp_record.host):
    #         size+=1
    size = len(list_wtmp_session.record_list)
    ip_suspicius=["" for x in range(size)]
    ip_fails_before_login=np.zeros(size,dtype=np.int64)
    date_of_login=[]
    i=0

    for wtmp_record in list_wtmp_session.record_list:
        #if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", wtmp_record.host):
        ip_suspicius[i] = wtmp_record.host
        time_of_login = wtmp_record.start #sec
        for x in range(i):
            if ip_suspicius[x]==ip_suspicius[i]:
                start_time=date_of_login[x]
            else:
                start_time = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(0))
        for record_btmp in list_record_btmp.record_list:
            if ip_suspicius[i] == record_btmp.host and start_time <= record_btmp.sec <= time_of_login:
                ip_fails_before_login[i]+=1
                wtmp_record.fail_before_login+=1
        i += 1
        #start_time=time_of_login
        date_of_login.append(time_of_login)

        if get_ip_type(wtmp_record.host)=="Public":   #valutare richiede molto tempo
            geo_response = geolocalize_ip(wtmp_record.host)
            #print(geo_response[0])
            if geo_response[1].country != "IT":
                wtmp_record.country=colored(geo_response[1].country,"red")


    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    probably_BF_table=[]
    ip_to_check = []
    for x in range(size):
        if get_ip_type(ip_suspicius[x]) == "Public":  # valutare richiede molto tempo
            geo_response = geolocalize_ip(ip_suspicius[x])
            # print(geo_response[0])
            country = geo_response[1].country
            if country!="IT":
                if ip_suspicius[x] not in ip_to_check:
                    ip_to_check.append(ip_suspicius[x])
        else: country="ZZ"
        suspect=""
        #suspect+=get_login_severity()
        if ip_fails_before_login[x] > 5*brute_force_threshold:
            suspect+=colored("HIGH","red")
            row=(suspect,"Login time:", date_of_login[x], "from ip:", ip_suspicius[x], "total try before success", ip_fails_before_login[x])
            probably_BF_table.append([suspect, date_of_login[x], ip_suspicius[x], ip_fails_before_login[x], country])
            #print(colored(row,"red"))
        elif brute_force_threshold <= ip_fails_before_login[x] <= 5*brute_force_threshold:
            suspect+=colored("MEDIUM","yellow")
            row=(suspect,"Login time:", date_of_login[x], "from ip:", ip_suspicius[x], "total try before success", ip_fails_before_login[x])
            probably_BF_table.append([suspect, date_of_login[x], ip_suspicius[x], ip_fails_before_login[x], country])
        else:
            suspect+=colored("LOW","green")
            row = (suspect, "Login time:", date_of_login[x], "from ip:", ip_suspicius[x], "total try before success",ip_fails_before_login[x])
            probably_BF_table.append([suspect, date_of_login[x], ip_suspicius[x], ip_fails_before_login[x], country])
            #print(row)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row)

    probably_BF2_table=[]
    for wtmp_record in list_wtmp_session.record_list:
        print(wtmp_record.host,wtmp_record.start,wtmp_record.fail_before_login,wtmp_record.user)
        new_suspect = get_login_severity(wtmp_record, failed_ip_count, failed_user_count, failed_host_name,failed_user_name
                                         , ip_black_list, ip_white_list)
        #new_suspect += " " + get_login_severity_by_sum(wtmp_record, failed_ip_count, failed_user_count, failed_host_name,
                                                       #failed_user_name)
        probably_BF2_table.append([new_suspect, wtmp_record.start, wtmp_record.host,wtmp_record.user, wtmp_record.fail_before_login,
                                   wtmp_record.country, colored("True","yellow") if wtmp_record.first_time==True else "False",
                                   colored("True","yellow") if wtmp_record.is_in_attack_time_byIP == True else "False",
                                   colored("True","yellow") if wtmp_record.is_in_attack_time_onUser else "False",
                                   colored("True", "yellow") if wtmp_record.is_in_SA_attack == True else "False",
                                    colored("True","red") if wtmp_record.IP_in_attack else "False",
                                   colored("True","red") if wtmp_record.User_in_attack else "False"])
        #print(new_suspect)
    if len(probably_BF_table)>0:
        string = tt.to_string(
            [probably_BF_table],
            header=["Severity","Login Time", "IP", "Failed attempts bf success", "CN"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    if len(probably_BF2_table)>0:
        string = tt.to_string(
            [probably_BF2_table],
            header=["Severity", "Login Time", "IP", "User","Failed attempts bf success", "CN", "First Time",
                    "While BF by IP","While BF on Usr","While Spray", "IP attacker", "Usr attacked"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    if len(ip_to_check)>0:
        print("Looking for info about the ip logged-in during BF")
        ip_search.multiple_ip_search(ip_to_check)

#todo affinare devo riconoscere i cicli di utenze (con numero di user differenti errati non basta)
def spray_attack(list_btmp_record, tsv, threshold_SA_count, threshold_SA_time): #, threshold_SA_user_count):
    # when attackers try same pwd for mutiple user and then change it
    SA_txt="Spray Attack Search:"
    #print(SA_txt)
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow([SA_txt])
    list_record_SA = []
    i = 1
    x = 0
    #print(len(list_btmp_record.record_list))
    while x < len(list_btmp_record.record_list) - 2:
        #print(x,i)
        count = 0
        list_user = []
        list_user_record = []
        start = parser.parse(list_btmp_record.record_list[x].sec)
        list_user.append(list_btmp_record.record_list[x])
        if x < i and i==len(list_btmp_record.record_list) - 1:
           break
        while i < len(list_btmp_record.record_list) - 1:  # and count<threshold_SA_count
            end = parser.parse(list_btmp_record.record_list[i].sec)
            i += 1
            if check_date_delta(start, end, threshold_SA_time):
                if list_btmp_record.record_list[i].user not in list_user:
                    start = parser.parse(list_btmp_record.record_list[i - 1].sec)
                    count += 1
                    list_user.append(list_btmp_record.record_list[i].user)
                    list_user_record.append(list_btmp_record.record_list[i])
            else:
                x = i
                i = x + 1
                break
            if count == threshold_SA_count:
                x = i
                i = x + 1
                list_record_SA.append(list_user_record)
                break

    list_host_SA = []
    list_user_SA = []
    list_date_SA = []
    #print(len(list_record_SA))
    for list_record in list_record_SA:
        for record in list_record:
            if record.host.strip() not in list_host_SA:  #todo qua riportare meglio i dati -> è quello il problema
                list_host_SA.append(record.host.strip())
                list_user_SA.append("")
                list_date_SA.append("")

    for host in list_host_SA:
        #print(host)
        for list_record2 in list_record_SA:
            for record2 in list_record2:
                if record2.host == host:
                    i = list_host_SA.index(host)
                    if record2.user.strip() not in list_user_SA[i]:
                        list_user_SA[i]+=record2.user.strip()+";"
                        list_date_SA[i]+=record2.sec+";"
                        #print(record2.user)

    print(len(list_record_SA)) #todo check lunghezze
    print(len(list_host_SA))
    print(len(list_user_SA))

    if len(list_host_SA)>0 and len(list_user_SA)>0:
        print(colored("Spray attack found:","red"))
        SA_table=[]
        size_to_use = min(len(list_host_SA),len(list_record_SA),len(list_user_SA)) #do better
        for i in range(size_to_use):#list_host_SA   range(len(list_record_SA)-1):#todo check

            #print(len(list_host_SA),len(list_user_SA))
            splitted=list_date_SA[i].split(";")
            report_SA=("ATTENTION probably Spray Attack found:", "IP:",list_host_SA[i],"has done at least",str(threshold_SA_count),
                       "failed login (each with different user) in",str(threshold_SA_time), "minutes",
                       str(len(list_record_SA[i])), "times with",
                       str(len(list_user_SA[i].split(";"))),"total different username",
                       "from:",splitted[0],"to:",splitted[len(splitted) - 2])
            SA_table.append([str(len(list_record_SA[i])),list_host_SA[i],str(threshold_SA_count),str(threshold_SA_time),
                             str(len(list_user_SA[i].split(";"))),splitted[0],splitted[len(splitted) - 2]])
            #print(colored(report_SA,"red"))
            #print(list_user_SA[i])

            csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(report_SA)
            csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(list_user_SA[i].split(";"))

        #if len(BF_user_table) > 0:
        if len(SA_table)>0:
            string = tt.to_string(
                [SA_table],
                header=["N° Spray Attack", "IP used", "Failed attempts with != user", "In x minutes",
                        "Tot. different username","Start date","End date"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)
    else:
        print(colored("Spray attack not found","green"))

    return (list_host_SA,list_user_SA,list_date_SA)

def check_login_during_SprayAttack(SA_list_host, SA_list_user, SA_list_times, list_wtmp_logins,
                         threshold_BF_time_login_search, threshold_BF_time_login_search_max, tsv):
    import datetime
    if len(SA_list_host)>0 and len(SA_list_user)>0:
        login_during_attack=[]
        ip_to_check=[]
        minutes_delta = datetime.timedelta(minutes=threshold_BF_time_login_search)
        hours_delta = datetime.timedelta(hours=threshold_BF_time_login_search_max)
        for SA_attack_data in SA_list_times:
            if SA_attack_data.strip()!="":#todo check
                #print(SA_attack_data)
                #print(SA_attack_data)
                specific_attack_dates=SA_attack_data.split(";")
                #print(specific_attack_dates)
                #todo check better date -> SA gets some failed attempts from near record (FP)
                if len(specific_attack_dates)>1:
                    specific_attack_dates=specific_attack_dates[0:len(specific_attack_dates) - 1]
                    specific_attack_data_start = parser.parse(specific_attack_dates[0])
                    specific_attack_data_end = parser.parse(specific_attack_dates[len(specific_attack_dates) - 1])
                else:
                    specific_attack_data_start = parser.parse(specific_attack_dates[0])
                    specific_attack_data_end = parser.parse(specific_attack_dates[0])

                #for specific_attack_data in specific_attack_dates:

                i = 0
                #print(SA_list_host,SA_list_user)
                for login_record in list_wtmp_logins.record_list:
                    #if ip_search.is_ip_public(login_record.host,stamp=False) or login_record.host in BF_list_host: #check if ip logged is public or in BF list
                    start = specific_attack_data_start #specific_attack_data #- datetime.timedelta(minutes=threshold_BF_time_login_search)
                    end = specific_attack_data_end + minutes_delta
                    large_end = specific_attack_data_end + hours_delta
                    if start <= parser.parse(login_record.start) <= end:
                        login_record.is_in_SA_attack = True
                        if login_record not in login_during_attack:
                            login_during_attack.append(login_record) #so i have host, time and user
                        if get_ip_type(login_record.host)=="Public" and login_record.host not in ip_to_check:
                            ip_to_check.append(login_record.host)
                        # possibile ottimizzare?
                        if login_record.host in SA_list_host:
                            login_record.IP_in_attack = True
                        if login_record.user in SA_list_user[i]:
                            login_record.User_in_attack = True
                    elif end < parser.parse(login_record.start) < large_end:
                        if login_record.host in SA_list_host:
                            login_record.IP_in_attack = True
                        if login_record.user in SA_list_user[i]:
                            login_record.User_in_attack = True
                    if i < len(SA_list_host)-1:
                        i+=1
        host_ip_report=("LOGIN WHILE/AFTER Spray Attack:", str(len(login_during_attack)))
        print(host_ip_report)
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
        csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(host_ip_report)
        host_login_after_BF_table=[]
        for login_record in list_wtmp_logins.record_list:
            if login_record.is_in_SA_attack == True:
                #print(login_record.host,login_record.user,login_record.start,login_record.pid)
                #for i in range(len(host_login_during_BF)):
                single_ip_report=("Login found from ip:", login_record.host, "with user:",
                                  login_record.user, "pid", login_record.pid, "at" , login_record.start,
                                  "end", login_record.end,"elapsed time", str(login_record.tot_time))
                #print(single_ip_report)
                host_login_after_BF_table.append([login_record.host,
                                  login_record.user, login_record.pid,login_record.start,
                                  login_record.end, str(login_record.tot_time)])
                csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_ip_report)

            # if login_record.IP_in_attack == True:
            #     print("IP in attack", login_record.host)
            # if login_record.User_in_attack == True:
            #     print("User in attack", login_record.user)
        #print(colored("HOST LOGIN DURING END AFTER BF:","red"))
        if len(host_login_after_BF_table)>0:
            string = tt.to_string(
                [host_login_after_BF_table],
                header=["IP logged", "Username","PID","Start date", "End date","Elapsed Time"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)


def get_login_severity(wtmp_session, failed_ip_count,failed_user_count, failed_host_name, failed_user_name, ip_black_list, ip_white_list):
    #import numpy as np
    #is new IP?
    #print(failed_ip_count, failed_user_count, failed_host_name, failed_user_name)
    # IP che logga ha fatto l'attacco
    if wtmp_session.IP_in_attack:
        tot_points = 1
    else:
        if wtmp_session.first_time == True:
            is_new_ip = 0.9 #0.9                                            # 0.9 * 1 * 1 *  1.2   login lecita durante un attacco
        else:
            is_new_ip = 0.8 #0.7
        #IP country? IT
        if wtmp_session.country=="IT" or wtmp_session.country=="ZZ":
            ip_country = 0.8 #1
        else:
            ip_country = 1#1.2
        #Data login appartiene a range attacco?
        if wtmp_session.is_in_attack_time_onUser or wtmp_session.is_in_attack_time_byIP or wtmp_session.is_in_SA_attack:
            login_date = 1
        else:
            login_date = 0.8
        #l'utenza è stata attaccata
        if wtmp_session.User_in_attack:
            attack_link = 0.9
        elif wtmp_session.host in failed_host_name and wtmp_session.user in failed_user_name:
            #attack_link = 0.5
            # #print(max(failed_user_count[failed_user_name.index(wtmp_session.user)],
            #                   failed_ip_count[failed_host_name.index(wtmp_session.host)],
            #                   wtmp_session.fail_before_login),failed_user_name.index(wtmp_session.user),failed_host_name.index(wtmp_session.host))
            attack_link = max(0.001*max(failed_user_count[failed_user_name.index(wtmp_session.user)], # max(0.5
                              failed_ip_count[failed_host_name.index(wtmp_session.host)]),
                              0.01*wtmp_session.fail_before_login)#)
        elif wtmp_session.host in failed_host_name:
            # print(max(failed_ip_count[failed_host_name.index(wtmp_session.host)],
            #     wtmp_session.fail_before_login),failed_host_name.index(wtmp_session.host))
            attack_link = max(0.001*failed_ip_count[failed_host_name.index(wtmp_session.host)], #max(0.5
                              0.01*wtmp_session.fail_before_login)#)
        elif wtmp_session.user in failed_user_name:
            # print(max(failed_user_count[failed_user_name.index(wtmp_session.user)],
            #     wtmp_session.fail_before_login),failed_user_name.index(wtmp_session.user))
            attack_link = max(0.001*failed_user_count[failed_user_name.index(wtmp_session.user)] #max(0.5,
                              ,0.01*wtmp_session.fail_before_login)#)
        else:
            attack_link = 0.5

        tot_points=is_new_ip*ip_country*login_date*attack_link
        #print("newip "+str(is_new_ip)+" CN "+str(ip_country)+" Date: "+str(login_date)+" Atk "+str(attack_link)+"\n")
    #print("Product before modify:" +str(tot_points))

    if len(ip_black_list)>0 and wtmp_session.host in ip_black_list: #increase severity
        if tot_points < 0.1:
            tot_points+= 0.45
        elif tot_points < 0.5:
            tot_points += 0.35
        elif tot_points < 0.7:
            tot_points += 0.25
        elif tot_points < 0.85:
            tot_points=0.9
    if len(ip_white_list)>0 and wtmp_session.host in ip_white_list: #decrease severity
        if tot_points > 0.85:
            tot_points -= 0.3
        elif tot_points > 0.4:
            tot_points -= 0.25


    #print("PRODUCT final"+str(tot_points))

    if 0 <= tot_points <= 0.15:
        return colored("VERY LOW","green")
    elif 0.15 < tot_points < 0.4:
        return colored("LOW", "green")
    elif 0.4 <= tot_points < 0.6:
        return colored("MEDIUM", "yellow")
    elif 0.6 <= tot_points <= 0.85:
        return colored("HIGH","magenta")
    elif tot_points > 0.85:
        return colored("VERY HIGH","red")



#todo --> test somma/valore max raggiungibile
#by anto
def get_login_severity_by_sum(wtmp_session, failed_ip_count,failed_user_count, failed_host_name, failed_user_name):#blacklist,whitelist
    if wtmp_session.first_time == True:
        is_new_ip = 1                   # 1+1+2+3/10 -> medium  login lecita (da ip nuovo) durante un attacco
    else:
        is_new_ip = 0.5
    # IP country? IT
    if wtmp_session.country == "IT" or wtmp_session.country == "ZZ":
        ip_country = 1
    else:
        ip_country = 2
    # Data login appartiene a range attacco? (BF o SA)
    if wtmp_session.is_in_attack_time_onUser or wtmp_session.is_in_attack_time_byIP or wtmp_session.is_in_SA_attack:
        login_date = 2
    else:
        login_date = 1
    # IP ha fatto l'attacco, o utenza è stata attaccata
    if wtmp_session.IP_in_attack:
        attack_link = 5
    elif wtmp_session.User_in_attack:
        attack_link = 3
    elif wtmp_session.host in failed_host_name and wtmp_session.user in failed_user_name:
        # attack_link = 0.5
        # #print(max(failed_user_count[failed_user_name.index(wtmp_session.user)],
        #                   failed_ip_count[failed_host_name.index(wtmp_session.host)],
        #                   wtmp_session.fail_before_login),failed_user_name.index(wtmp_session.user),failed_host_name.index(wtmp_session.host))
        attack_link = 0.001 * max(failed_user_count[failed_user_name.index(wtmp_session.user)],
                                          failed_ip_count[failed_host_name.index(wtmp_session.host)],
                                          wtmp_session.fail_before_login)
    elif wtmp_session.host in failed_host_name:
        # print(max(failed_ip_count[failed_host_name.index(wtmp_session.host)],
        #     wtmp_session.fail_before_login),failed_host_name.index(wtmp_session.host))
        attack_link = 0.001 * max(failed_ip_count[failed_host_name.index(wtmp_session.host)],
                                          wtmp_session.fail_before_login)
    elif wtmp_session.user in failed_user_name:
        # print(max(failed_user_count[failed_user_name.index(wtmp_session.user)],
        #     wtmp_session.fail_before_login),failed_user_name.index(wtmp_session.user))
        attack_link = 0.001 * max(failed_user_count[failed_user_name.index(wtmp_session.user)],
                                          wtmp_session.fail_before_login)
    else:
        attack_link = 0.5

    tot_points = (is_new_ip + ip_country + login_date + attack_link)/10
    #print("SUM" + str(tot_points) + "  newip" + str(is_new_ip) + "CN" + str(ip_country) + "Date:" + str(
        #login_date) + "Atk" + str(attack_link))
    if 0 <= tot_points <= 0.2:
        return colored("VERY LOW", "green")
    elif 0.2 < tot_points <= 0.4:
        return colored("LOW", "green")
    elif 0.4 <= tot_points <= 0.6:
        return colored("MEDIUM", "yellow")
    elif 0.6 < tot_points <= 0.8:
        return colored("HIGH", "magenta")
    elif tot_points > 0.8:
        return colored("VERY HIGH", "red")

#**** SUDDIVIDERE MEGLIO IN ANALISI PER SOLO WTMP E SOLO BTMP E POI UN METODO PER LE ANALISI CORRELATE#
# (utmp_filesize, utmp_file, input_file, tsv) SSH
#def login_out_correlation(wtmp_file, btmp_file, utmp_file, output_file, brute_force_threshold):#host_ip_founded

    # sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    # # utmp structure (data displayed)
    # row_label = ["type", "pid", "line", "id", "user", "host", "term", "exit", "session", "sec", "usec", "addr"]
    # # EXTRACT WTMP INFO
    # if os.path.exists(wtmp_file):
    #     with open(wtmp_file, "rb") as wtmp_file_opened:
    #         wtmp_filesize = os.path.getsize(wtmp_file)
    #         if output_file:
    #             tsv = open(output_file, "w", encoding='UTF-8')
    #             csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
    #         else:
    #             tsv = sys.stdout
    #             csv.writer(tsv, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
    #         list_record_wtmp = parseutmp(wtmp_filesize, wtmp_file_opened, wtmp_file, tsv)
    #         (host_ip_founded_wtmp,pid_founded_wtmp,user_founded_wtmp)=binary_first_search(list_record_wtmp, tsv)
    # else:
    #     print("No input file found")
    #     sys.exit(1)
    # #EXTRACT BTMP INFO  #**** sposta in altra funzione
    # if os.path.exists(btmp_file):
    #     with open(btmp_file, "rb") as btmp_file_opened:
    #         btmp_filesize = os.path.getsize(btmp_file)
    #
    #         csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    #         csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row_label)
    #
    #         list_record_btmp = parseutmp(btmp_filesize, btmp_file_opened, btmp_file, tsv)
    #         (host_ip_founded_btmp,pid_founded_btmp,user_founded_btmp)=binary_first_search(list_record_btmp, tsv)
    # else:
    #     print("No input file found")
    #     sys.exit(1)
    # # list_record_wtmp (history of login and logout) list_record_btmp (failed)
