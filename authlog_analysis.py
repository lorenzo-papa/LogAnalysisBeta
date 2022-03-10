import re, sys, time, numpy as np
import os.path
from os import path
from datetime import datetime
from dateutil import parser
from pathlib import Path

import ip_search
from search_functions import *
from utility import *
from data_structure import *
from ip_search import *


# caaling the methods for authlog analysis
def auth_log_analysis(auth_log_path, pattern_error, authlog_threshold_success, lines_to_save,
                      threshold_authlog_BF_count, threshold_authlog_BF_time, threshold_authlog_BF_time_login_search,
                      threshold_SA_count, threshold_SA_time, threshold_authlog_BF_time_login_search_max,
                      ip_blacklist, ip_whitelist):
    if check_if_file_exist(auth_log_path):
        working_path = os.getcwd()
        if check_if_folder_exist(working_path + "/" + "AuthLog_Output"):
            empty_folder(working_path + "/" + "AuthLog_Output")
        print("start session search")
        (authlog_lines, login_list_new) = auth_log_sessions(auth_log_path, ip_blacklist, ip_whitelist)
        # todo remove authlog_lines_session
        # save_output_json_authlog("authlog_session_list", login_list_new)
        # save_output_json_authlog("authlog_lines", authlog_lines)
        print("start failed attempts search",time.process_time())
        list_failed_attempts_record = parse_authlog_failed_lines(authlog_lines,auth_log_path, pattern_error, ip_blacklist,
                                                                 ip_whitelist)
        # save_output_json_authlog("failed_attempts_list", list_failed_attempts_record)

        # list_failed_attempts_record_new = load_json_file(working_path + "/AuthLog_Output/" + "failed_attempts_list.json")

        (host_ip_founded, tot_ip_fail, user_founded, tot_user_fail) = auth_log_BF_success_1(list_failed_attempts_record)
        # todo save output in 1 obj, pass failed from file not ram

        # (host_ip_founded, tot_ip_fail,user_founded, tot_user_fail)=auth_log_BF_success_old(auth_log_path, pattern_error, authlog_threshold_success,lines_to_save)
        print("start BF search", time.process_time())
        (BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times) = \
            auth_log_BF(host_ip_founded, tot_ip_fail, user_founded, tot_user_fail,
                        threshold_authlog_BF_count, threshold_authlog_BF_time, list_failed_attempts_record,
                        ip_blacklist, ip_whitelist)
        # todo save output in 1 obj, pass input from file not ram

        # todo pass from file
        authlog_check_login_after_BF(BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times,
                                     login_list_new, threshold_authlog_BF_time_login_search,
                                     threshold_authlog_BF_time_login_search_max)
        # authlog_lines,authlog_lines_session,ip_blacklist, ip_whitelist)

        # todo pass from file + out in 1 obj
        print("start spray search",time.process_time())
        (SA_list_host, SA_list_user, SA_list_times) = spray_attack_authlog(list_failed_attempts_record,
                                                                           threshold_SA_count, threshold_SA_time)

        # todo pass from file
        check_login_during_SprayAttack(SA_list_host, SA_list_user, SA_list_times, login_list_new,
                                       threshold_authlog_BF_time_login_search,
                                       threshold_authlog_BF_time_login_search_max,
                                       tsv=None)

        # todo pass from file
        # authlog_lines_new = load_json_file(working_path + "/AuthLog_Output/" + "authlog_lines.json")

        auth_log_BF_success_2(authlog_lines, auth_log_path, pattern_error, lines_to_save, login_list_new, ip_blacklist,
                              ip_whitelist, tot_ip_fail, tot_user_fail, host_ip_founded, user_founded)
    else:
        print("Exit, file not found, please insert a valid file")


def parse_authlog_failed_lines(authlog_lines, auth_log_path, pattern_error, ip_blacklist, ip_whitelist):
    error_record_list = []

    #with open(auth_log_path, "r") as file:
     #   for line in file:
    for record_check in authlog_lines.record_list:
        line=record_check.line
        ip=record_check.ip_record
        date=record_check.date_record
        username=record_check.user
        if record_check.error==True and re.search(pattern_error, line.lower()):
            if len(ip_blacklist) > 0 and len(ip_whitelist) == 0:
                #ip = get_ip_from_line(line)
                if ip in ip_blacklist:
                    new_error_record = AuthlogRecord(ip=ip, date=date,#check_date_log(line),
                                                     user=username,#get_user_from_line(line),
                                                     line=line)  # session_id=get_session_id(line))
                    if new_error_record.user and new_error_record.ip and new_error_record not in error_record_list:
                        error_record_list.append(new_error_record)
            elif len(ip_whitelist) > 0 and len(ip_blacklist) == 0:
                ip = get_ip_from_line(line)
                if ip not in ip_whitelist:
                    new_error_record = AuthlogRecord(ip=ip, date=date,
                                                     user=username,
                                                     line=line)  # session_id=get_session_id(line))
                    if new_error_record.user and new_error_record.ip and new_error_record not in error_record_list:
                        error_record_list.append(new_error_record)
            else:
                new_error_record = AuthlogRecord(ip=get_ip_from_line(line), date=date,
                                                 user=username,
                                                 line=line)  # session_id=get_session_id(line))
                if new_error_record.user and new_error_record.ip and new_error_record not in error_record_list:
                    error_record_list.append(new_error_record)
    #file.close()

    list_failed_attempts_record = list_AuthlogRecord(error_record_list)

    return list_failed_attempts_record


def auth_log_sessions(auth_log_path, ip_blacklist, ip_whitelist):
    import datetime
    print("\nSearching into: ", auth_log_path, "for SSH sessions")

    pattern_session = r"(?=.*sshd|ssh)(?=.*accepted)(?=.*(password|key))"  # attention.. could be in different format
    pattern_end_session = r = "(?=sshd.*session closed)"
    pattern_not_match = r"^((?!failed|failure|invalid|error|fail).)*$"

    login_list = []
    authlog_lines = []
    ip_list = []
    user_for_ip = []
    end_session_lines=[]
    with open(auth_log_path, "r") as file:
        for line in file:
            if re.search(pattern_session, line.lower()):  # count ip logged in
                if re.search(pattern_not_match, line.lower()):
                    #authlog_lines_session.append(line)
                    ip = get_ip_from_line(line)
                    if len(ip_blacklist) > 0 and len(ip_whitelist) == 0:
                        if ip in ip_blacklist:
                            # session_id = re.search(r'sshd\[(.*?)\]', line).group(1)
                            # username = re.search(r'for(.*?)from', line).group(1)
                            username = get_user_from_line(line)
                            # (self, ip, date, user="", line="", error_before_login=0)
                            date_save=check_date_log(line)
                            new_login = AuthlogRecord(ip=ip, date=date_save, user=username, line=line,
                                                      session_id=get_session_id(line), type=get_ip_type(ip))
                            add_record = auth_severity(ip_record=ip, date_record=date_save, line=line, user=username)
                            authlog_lines.append(add_record)
                            if new_login not in login_list:
                                login_list.append(new_login)

                            if ip not in ip_list:
                                ip_list.append(ip)
                                new_login.first_time = True
                                user_for_ip.append(username)
                            else:
                                x = ip_list.index(ip)
                                if username and username not in user_for_ip[x]:
                                    new_login.first_time = True
                                    user_for_ip[x] += username + ";"

                    elif len(ip_whitelist) > 0 and len(ip_blacklist) == 0:
                        if ip not in ip_whitelist:
                            # session_id = re.search(r'sshd\[(.*?)\]', line).group(1)
                            # username = re.search(r'for(.*?)from', line).group(1)
                            username = get_user_from_line(line)
                            # (self, ip, date, user="", line="", error_before_login=0)
                            date_save=check_date_log(line)
                            new_login = AuthlogRecord(ip=ip, date=date_save, user=username, line=line,
                                                      session_id=get_session_id(line), type=get_ip_type(ip))
                            add_record = auth_severity(ip_record=ip, date_record=date_save, line=line, user=username)
                            authlog_lines.append(add_record)

                            if new_login not in login_list:
                                login_list.append(new_login)

                            if ip not in ip_list:
                                ip_list.append(ip)
                                new_login.first_time = True
                                user_for_ip.append(username)
                            else:
                                x = ip_list.index(ip)
                                if username and username not in user_for_ip[x]:
                                    new_login.first_time = True
                                    user_for_ip[x] += username + ";"
                    else:
                        # session_id = re.search(r'sshd\[(.*?)\]', line).group(1)
                        # username = re.search(r'for(.*?)from', line).group(1)
                        username = get_user_from_line(line)
                        # (self, ip, date, user="", line="", error_before_login=0)
                        new_login = AuthlogRecord(ip=ip, date=check_date_log(line), user=username, line=line,
                                                  session_id=get_session_id(line), type=get_ip_type(ip))
                        add_record = auth_severity(ip_record=ip, date_record=date_save, line=line, user=username)
                        authlog_lines.append(add_record)
                        if new_login not in login_list:
                            login_list.append(new_login)

                        if ip not in ip_list:
                            ip_list.append(ip)
                            new_login.first_time = True
                            user_for_ip.append(username)
                        else:
                            x = ip_list.index(ip)
                            if username and username not in user_for_ip[x]:
                                new_login.first_time = True
                                user_for_ip[x] += username + ";"
            elif re.search(pattern_end_session, line.lower()):#authlog_lines[x].lower()):
                #print(line)
                date_save = check_date_log(line)
                add_record = auth_severity(ip_record=ip, date_record=date_save, line=line, user=get_user_from_line(line))
                authlog_lines.append(add_record)
                end_session = End_session(get_session_id(line), date_save, line)
                end_session_lines.append(end_session)
            else:#todo nel caso remove
                ip = get_ip_from_line(line)
                date_save = check_date_log(line)
                add_record = auth_severity(ip_record=ip, date_record=date_save, line=line, user=get_user_from_line(line),
                                           error=True)
                authlog_lines.append(add_record)
            # if re.search(pattern_error, line.lower()):

    file.close()
    login_list_new = list_AuthlogRecord(login_list)
    logout_list = list_End_session(end_session_lines)
    print(time.process_time())
    session_to_print = []
    for login in login_list_new.record_list:
        #for x in range(len(authlog_lines)):
        for logout in logout_list.record_list:
            elapsed = None
            #id_found=None
            #id_found=re.search(r'sshd\[(.*?)\]', authlog_lines[x])
            #if id_found:
            if logout.id_end and logout.end_time:
                #id_found=id_found.group(1)
                #if id_found == login.session_id:
                    #date_found=check_date_log(authlog_lines[x])
                if logout.id_end == login.session_id and logout.end_time >= login.date:
                    #if date_found and date_found >= login.date and \
                            #re.search(pattern_end_session, authlog_lines[x].lower()):
                        #print(logout.end_line)
                        login.end_date = logout.end_time
                        login.end_line = logout.end_line
                        # print(login.end_line)
                        #if login.end_date:
                        #todo check if better
                        elapsed = login.end_date - login.date
                        elapsed = colored(elapsed, "yellow") if elapsed <= datetime.timedelta(seconds=int(1)) else elapsed
                        # print("SSH session from IP:",login.ip,"with user:", login.user,"from:", login.date,"to:" ,login.end_date,
                        # "time elapsed:",login.end_date-login.date,"session_id:",login.session_id)
                        break
        session_to_print.append(
            [login.ip, login.user, login.date, login.end_date, elapsed, login.session_id, get_ip_type(login.ip)])

    print("TOT SSH SESSIONS:", len(session_to_print))
    if len(session_to_print) > 0:
        string = tt.to_string(
            [session_to_print],
            header=["SSH session: IP", "Username", "Start Date", "End Date", "Time elapsed", "Session ID", "Type"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    return (list_auth_severity(authlog_lines), login_list_new)#authlog_lines


# looking for BF in general, for ip and for user, then looking for log during that times
def auth_log_BF(host_ip_founded, tot_ip_fail, user_founded, tot_user_fail,
                threshold_authlog_BF_count, threshold_authlog_BF_time, list_failed_attempts_record, ip_blacklist,
                ip_whitelist):
    BF_list_host = []
    BF_list_host_times = []
    BF_host_table = []
    BF_list_host_to_check = []
    BF_attack_lines_host = []
    for host in host_ip_founded:
        # print(tot_ip_fail[host_ip_founded.index(host)], threshold_authlog_BF_count)
        if tot_ip_fail[host_ip_founded.index(host)] > threshold_authlog_BF_count:
            list_times_host_attack = []
            date_host = []
            attack_lines = []
            for failed_attemp in list_failed_attempts_record.record_list:
                # if re.search(pattern_error, line.lower()):
                # ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                # for ip in ip_found:
                #print(failed_attemp.date)
                if len(ip_blacklist) > 0 and len(ip_whitelist) == 0:
                    if failed_attemp.ip == host and failed_attemp.date is not None and failed_attemp.ip in ip_blacklist:
                        date_host.append(failed_attemp.date)  # then look for delta from first and subsequent
                        attack_lines.append(failed_attemp)
                elif len(ip_whitelist) > 0 and len(ip_blacklist) == 0:
                    if failed_attemp.ip == host and failed_attemp.date is not None and failed_attemp.ip not in ip_whitelist:
                        date_host.append(failed_attemp.date)  # then look for delta from first and subsequent
                        attack_lines.append(failed_attemp)
                else:
                    if failed_attemp.ip == host and failed_attemp.date is not None:
                        date_host.append(failed_attemp.date)  # then look for delta from first and subsequent
                        attack_lines.append(failed_attemp)
            if date_host != None and len(date_host)>0:#todo check
                #print(date_host)
                count = 0
                i = 0
                start = date_host[i]
                while i < len(date_host) - 1:
                    end = date_host[i + 1]
                    i += 1
                    if check_date_delta(start, end, threshold_authlog_BF_time):
                        count += 1
                    else:
                        start = date_host[i]
                        count = 0
                    if count == threshold_authlog_BF_count:
                        list_times_host_attack.append(host)
                        count = 0
            if len(list_times_host_attack) > 1:
                # report_BF=("ATTENTION: Brute Force Attack", "It has been found that the host", host, "has done",
                #       str(threshold_authlog_BF_count), "failed login in", str(threshold_authlog_BF_time), "minutes",
                #       str(len(list_times_host_attack)), "times", "from", str(date_host[0]), "to",
                #       str(date_host[len(date_host) - 1]))

                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
                bf_report_host = ("ATTENTION: Brute Force Attack", "The host", host, "has done",
                                  str(threshold_authlog_BF_count), "failed login in", str(threshold_authlog_BF_time),
                                  "minutes",
                                  str(len(list_times_host_attack)), "times", "from", str(date_host[0]), "to",
                                  str(date_host[len(date_host) - 1]))
                BF_host_table.append([str(len(list_times_host_attack)), host, str(threshold_authlog_BF_count),
                                      str(threshold_authlog_BF_time), str(date_host[0]),
                                      str(date_host[len(date_host) - 1])])
                # print(colored(bf_report_host,"red"))
                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(bf_report_host)
                if get_ip_type(host) == "Public":
                    BF_list_host_to_check.append(host)
                BF_list_host.append(host)
                BF_list_host_times.append(date_host)
                BF_attack_lines_host.append(attack_lines)

    if len(BF_host_table) > 0:
        print(colored("IP Brute force attack/s founded:", "red"))
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
    BF_attack_lines_user = []
    for user in user_founded:
        if tot_user_fail[user_founded.index(user)] >= threshold_authlog_BF_count:
            list_times_user_attack = []
            date_user = []
            attack_lines_user = []
            for failed_attemp_usr in list_failed_attempts_record.record_list:
                # if re.search(pattern_error, line.lower()):
                if len(ip_blacklist) > 0 and len(ip_whitelist) == 0:
                    if failed_attemp_usr.user == user and failed_attemp_usr.date is not None and failed_attemp.ip in ip_blacklist:
                        date_user.append(failed_attemp_usr.date)  # then look for delta from first and subsequent
                        attack_lines_user.append(failed_attemp)
                elif len(ip_whitelist) > 0 and len(ip_blacklist) == 0:
                    if failed_attemp_usr.user == user and failed_attemp_usr.date is not None and failed_attemp.ip not in ip_whitelist:
                        date_user.append(failed_attemp_usr.date)  # then look for delta from first and subsequent
                        attack_lines_user.append(failed_attemp)
                else:
                    if failed_attemp_usr.user == user and failed_attemp_usr.date is not None:
                        date_user.append(failed_attemp_usr.date)  # then look for delta from first and subsequent
                        attack_lines_user.append(failed_attemp)

            if date_user != None and len(date_user)>0:
                count = 0
                i = 0
                start = date_user[i]
                while i < len(date_user) - 1:
                    end = date_user[i + 1]
                    i += 1
                    if check_date_delta(start, end, threshold_authlog_BF_time):
                        count += 1
                    else:
                        start = date_user[i]
                        count = 0
                    if count == threshold_authlog_BF_count:
                        list_times_user_attack.append(user)
                        count = 0
            if len(list_times_user_attack) > 1:
                # print(colored("ATTENTION: Brute Force Attack", "It has been found that the user \"", user, "\" has done",
                #       str(threshold_authlog_BF_count), "failed login in", str(threshold_authlog_BF_time),
                #       "minutes", str(len(list_times_user_attack)), "times", "from", str(date_user[0]), "to",
                #       str(date_user[len(date_user) - 1]),"red"))
                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
                bf_report_user = ("ATTENTION: Brute Force Attack", "The user \"", user, "\" has done",
                                  str(threshold_authlog_BF_count), "failed login in", str(threshold_authlog_BF_time),
                                  "minutes", str(len(list_times_user_attack)), "times", "from", str(date_user[0]), "to",
                                  str(date_user[len(date_user) - 1]))
                # print(colored(bf_report_user,"red"))
                BF_user_table.append([str(len(list_times_user_attack)), user, str(threshold_authlog_BF_count),
                                      str(threshold_authlog_BF_time), str(date_user[0]),
                                      str(date_user[len(date_user) - 1])])
                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(bf_report_user)
                BF_list_user.append(user)
                BF_list_user_times.append(date_user)
                BF_attack_lines_user.append(attack_lines_user)

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

    if len(BF_list_host_to_check) > 0:
        ip_search.multiple_ip_search(BF_list_host,short_search=True)
    if len(BF_list_host) == 0:
        print(colored("Brute Force attack by IP not found", "green"))
    if len(BF_list_user) == 0:
        print(colored("Brute Force attack against User not found", "green"))

    return (BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times)


def authlog_check_login_after_BF(BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times,
                                 login_list_new, threshold_BF_time_login_search,
                                 threshold_BF_time_login_search_max):
    host_to_check = []
    import datetime
    minutes_delta = datetime.timedelta(minutes=threshold_BF_time_login_search)
    hours_delta = datetime.timedelta(hours=threshold_BF_time_login_search_max)
    if len(BF_list_host) > 0:
        print("Looking for login during BF attack:")  # TODO USE LOGIN LIST AND NOT LOGIN LINES
        print("Looking for login during BF attack:")  # TODO USE LOGIN LIST AND NOT LOGIN LINES
        host_login_during_BF = []
        lines_founded_host = []
        host_login_after_BF_table = []

        for BF_host_time in BF_list_host_times:
            # print("round", len(BF_host_time))
            # for BF_host_data in BF_host_time:
            BF_host_data_start = BF_host_time[0]
            BF_host_data_end = BF_host_time[len(BF_host_time) - 1]
            for login in login_list_new.record_list:
                # ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                # for ip in ip_found:
                if login.is_in_attack_time_byIP == False:
                #(ip_search.is_ip_public(login.ip,stamp=False) or login.ip in BF_list_host):  # check if ip logged is public or in BF list
                    start = BF_host_data_start  # - datetime.timedelta(minutes=threshold_BF_time_login_search)
                    end = BF_host_data_end + minutes_delta
                    large_end = BF_host_data_end + hours_delta
                    date_to_check = login.date
                    if date_to_check:
                        if start <= date_to_check <= end:
                            login.is_in_attack_time_byIP = True
                            if login.line not in lines_founded_host:
                                lines_founded_host.append(login.line)
                                # ip, date, user = "", line = "", error_before_login = 0, end_date = None, session_id = None):
                                #new_login = AuthlogRecord(ip=login.ip, date=date_to_check, user=login.user,
                                                          #session_id=login.session_id, end_date=login.end_date)
                                #host_login_during_BF.append(new_login)
                                # elapsed=None
                                # if new_login.end_date:
                                # elapsed=str(new_login.end_date - new_login.date)
                                # host_login_after_BF_table.append([new_login.ip,new_login.user,new_login.session_id,
                                # new_login.date,new_login.end_date,
                                # elapsed])
                                if get_ip_type(login.ip) == "Public" and login.ip not in host_to_check:
                                    host_to_check.append(login.ip)
                                if login.ip in BF_list_host:
                                    login.IP_in_attack = True
                                if login.user in BF_list_user:
                                    login.User_in_attack = True
                                #break
                        elif end < date_to_check < large_end:
                            if login.ip in BF_list_host:
                                login.IP_in_attack = True
                            if login.user in BF_list_user:
                                login.User_in_attack = True
                            #break

       # host_ip_report = ("HOST IP LOGIN AFTER BF:", str(len(host_login_during_BF)))
        #print(host_ip_report)
        tot_ip=0
        for login in login_list_new.record_list:
            if login.is_in_attack_time_byIP:
                tot_ip+=1
                # print(login.ip,login.user,login.date)
                tot_time = None
                # print(login.end_date)
                if login.end_date:
                    tot_time = str(login.end_date - login.date)
                single_ip_report = ("Login found from ip:", login.ip, "with user", login.user,
                                    "pid", login.session_id, "at", login.date, "end", login.end_date,
                                    "elapsed time", tot_time)
                # print(single_user_report)
                host_login_after_BF_table.append([login.ip, login.user, login.session_id, login.date,
                                                  login.end_date, tot_time])
                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_user_report)

        host_ip_report = ("HOST IP LOGIN AFTER BF:", str(tot_ip))
        print(host_ip_report)

        if len(host_login_after_BF_table) > 0:
            string = tt.to_string(
                [host_login_after_BF_table],
                header=["IP logged", "Username", "Session ID", "Start date", "End date", "Elapsed Time"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)

        # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
        # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(host_ip_report)
        #for login in host_login_during_BF:
            # ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
            # user = get_user_from_line(line)
            # date_login = check_date_log(line)
            # for ip in ip_found:
            #     if ip is not None:     #todo save on csv
            #single_ip_report = (
            #"Login found from ip:", login.ip, "with user:", login.user, "at", str(login.date), "with session_id:",
            #login.session_id)
            # print(single_ip_report)
            # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_ip_report)

    if len(BF_list_user) > 0:
        user_login_during_BF = []
        lines_founded_user = []
        user_login_after_BF_table = []
        for BF_user_time in BF_list_user_times:
            # for BF_user_data in BF_user_time:
            BF_user_data_start = BF_user_time[0]
            BF_user_data_end = BF_user_time[len(BF_user_time) - 1]
            for login in login_list_new.record_list:
                # if login.is_in_attack_time_onUser == False:
                # ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                # for ip in ip_found:
                user = login.user
                # todo change or if only public
                if login.is_in_attack_time_onUser == False:
                #if (ip_search.is_ip_public(login.ip,stamp=False) or user in BF_list_user):  # check if ip logged is public or user in BF list
                    start = BF_user_data_start  # - datetime.timedelta(minutes=threshold_BF_time_login_search)
                    end = BF_user_data_end + minutes_delta
                    large_end = BF_user_data_end + hours_delta
                    date_to_check = login.date
                    if date_to_check:
                        if start <= date_to_check <= end:
                            login.is_in_attack_time_onUser = True
                            if login.line not in lines_founded_user:
                                lines_founded_user.append(login.line)
                                #new_login = AuthlogRecord(ip=login.ip, date=date_to_check, user=user,
                                                          #session_id=login.session_id, end_date=login.end_date)
                                #user_login_during_BF.append(new_login)
                                # user_login_after_BF_table.append([new_login.user,new_login.ip,new_login.session_id,
                                # new_login.date, new_login.end_date,
                                # str(new_login.end_date-new_login.date)])
                                if login.ip not in host_to_check and get_ip_type(login.ip) == "Public":
                                    host_to_check.append(login.ip)
                                if login.ip in BF_list_host:
                                    login.IP_in_attack = True
                                if login.user in BF_list_user:
                                    login.User_in_attack = True
                                #break
                        elif end < date_to_check < large_end:
                            if login.ip in BF_list_host:
                                login.IP_in_attack = True
                            if login.user in BF_list_user:
                                login.User_in_attack = True
                            #break

        #user_report = ("USER LOGIN AFTER BF: ", str(len(user_login_during_BF)))
        #print(user_report)
        tot_usr=0
        for login in login_list_new.record_list:
            if login.is_in_attack_time_onUser:
                tot_usr+=1
                # print(login.ip,login.user,login.date)
                tot_time = None
                if login.end_date:
                    tot_time = str(login.end_date - login.date)
                single_user_report = ("Login found from user:", login.user, "with ip", login.ip,
                                      "pid", login.session_id, "at", login.date, "end", login.end_date,
                                      "elapsed time", tot_time)
                # print(single_user_report)
                user_login_after_BF_table.append([login.user, login.ip, login.session_id, login.date,
                                                  login.end_date, tot_time])
                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_user_report)


        user_report = ("USER LOGIN AFTER BF: ", str(tot_usr))
        print(user_report)
        if len(user_login_after_BF_table) > 0:
            string = tt.to_string(
                [user_login_after_BF_table],
                header=["Username", "IP logged", "Session ID", "Start date", "End date", "Elapsed Time"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)

        # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
        ##csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(user_report)
        #for login in user_login_during_BF:
            #single_user_report = (
            #"Login found from user:", login.user, "with ip", login.ip, "at", str(login.date), "with session_id:",
            #login.session_id)
            # print(single_user_report)
            # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_user_report)

    if len(host_to_check) > 0:
        print("Looking for info about the ip logged-in during BF")
        multiple_ip_search(host_to_check,short_search=True)


# searching for sospicius ip and for ip which succeded in login
def auth_log_BF_success_1(failed_attemp_list):

    pattern_session = r"(?=.*sshd|ssh)(?=.*accepted)(?=.*(password|key))"
    pattern_end_session = r = "(?=ssh.*session closed|session.*logged out|removed session|logged out)"
    pattern_not_match = r"^((?!failed|failure|invalid|error|fail).)*$"
    # size = 0
    # file_lines=[]
    # with open(auth_log_path, "r") as file:
    ip_suspicius = []
    user_suspicius = []
    tot_ip_fail = []
    tot_user_fail = []
    user_for_ip = []
    ip_for_user = []
    logged_ip = []
    find_end_date = False

    # for line in auth_log_lines:
    for failed_attemp in failed_attemp_list.record_list:
        # if re.search(pattern_error,line.lower()): #count ip failed
        # COUNT IP AND ERROR
        # ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        # for ip in ip_found:
        if failed_attemp.ip not in ip_suspicius and failed_attemp.ip is not None:
            ip_suspicius.append(failed_attemp.ip)
            tot_ip_fail.append(1)

            # result = re.search(r'\sfor(.*?)\sfrom|\suser=(.*?)$|\suser(.*?)\sfrom', line)
            if failed_attemp.user is not None:
                # result = result.groups()
                # for user in result:
                # if user is not None:
                # if 'user' in user:
                # user=user.partition('user')[2]
                # user_for_ip.append(user.strip() + ";")
                # elif '=' in user:
                # user = user.partition('=')[2]
                # user_for_ip.append(user.strip() + ";")
                # else:
                user_for_ip.append(failed_attemp.user + ";")
            else:
                user_for_ip.append(";")
        else:
            if failed_attemp.ip is not None:
                i = ip_suspicius.index(failed_attemp.ip)
                tot_ip_fail[i] += 1
                # result = re.search(r'\sfor(.*?)\sfrom|\suser=(.*?)$|\suser(.*?)\sfrom', line)  #\sfor(.*?)\sfrom|\suser=(.*?)$

                if failed_attemp.user is not None:
                    # result=result.groups()
                    # for user in result:
                    # if user is not None:
                    # if 'user' in user:
                    # user=user.partition('user')[2].strip()
                    # if user not in user_for_ip[i]:
                    # user_for_ip[i] += user + ";"
                    # elif '=' in user:
                    # user = user.partition('=')[2].strip()
                    # if user not in user_for_ip[i]:
                    # user_for_ip += user + ";"
                    # else:
                    if failed_attemp.user not in user_for_ip[i]:
                        user_for_ip[i] += failed_attemp.user + ";"

        # COUNT USER AND ERROR
        # result = re.search(r'\sfor(.*?)\sfrom|\suser=(.*?)$|\suser(.*?)\sfrom', line)
        if failed_attemp.user is not None:
            # result = result.groups()
            # print("RESULT: ", result, line)
            # for user in result:
            # if user is not None and user.strip() != "" and user.strip() != " ":
            # print("user found:", user.strip())
            # if 'user' in user:
            # if "user user" in user:
            # user = user.partition('user')[1].strip()
            # print("parti 1", user)
            # elif user.lower().strip()=="user":
            # user=user.strip()
            # elif len(user.strip()) > len("user") and " " not in user.strip():
            # user = user.strip()
            # else:
            # user = user.partition('user')[2].strip()
            # print("part 2", user)
            if failed_attemp.user not in user_suspicius:
                # print("USER",user, line)
                user_suspicius.append(failed_attemp.user)
                tot_user_fail.append(1)
                # ip_found = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                if failed_attemp.ip:
                    ip_for_user.append(failed_attemp.ip + ";")
                else:
                    ip_for_user.append(";")
            else:
                # print("NOT USER",user, line)
                i = user_suspicius.index(failed_attemp.user)
                tot_user_fail[i] += 1
                # ip_found = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
                if failed_attemp.ip and failed_attemp.ip not in ip_for_user[i]:
                    ip_for_user[i] += failed_attemp.ip + ";"
        # elif '=' in user:
        #     user = user.partition('=')[2].strip()
        #     if user not in user_suspicius:
        #         #print("=", user, line)
        #         user_suspicius.append(user)
        #         tot_user_fail.append(1)
        #         ip_found = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        #         if ip_found:
        #             ip_for_user.append(ip_found.group(0) + ";")
        #         else:
        #             ip_for_user.append(";")
        #     else:
        #         #print("no =",user, line)
        #         i = user_suspicius.index(user)
        #         tot_user_fail[i] += 1
        #         ip_found = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        #         if ip_found is not None and ip_found.group(0) not in ip_for_user[i]:
        #             ip_for_user[i] += ip_found.group(0) + ";"
        # else:
        #     if user.strip() not in user_suspicius:
        #         #print("else",user.strip(), line)
        #         user_suspicius.append(user.strip())
        #         tot_user_fail.append(1)
        #         ip_found = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        #         if ip_found:
        #             ip_for_user.append(ip_found.group(0) + ";")
        #         else:
        #             ip_for_user.append(";")
        #     else:
        #         #print("else no", user.strip(), line)
        #         i = user_suspicius.index(user.strip())
        #         tot_user_fail[i] += 1
        #         ip_found = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
        #         if ip_found is not None and ip_found.group(0) not in ip_for_user[i]:
        #             ip_for_user[i] += ip_found.group(0) + ";"
        # print(len(user_suspicius))

    # for line in auth_log_lines:
    #     # COUNT IP LOGGED IN
    #     if re.search(pattern_session,line.lower()):
    #         if re.search(pattern_not_match, line.lower()):
    #             ip_found = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    #             #print(line)
    #             for ip in ip_found:
    #                 username = re.search(r'for(.*?)from', line).group(1)
    #                 #(self, ip, date, user="", line="", error_before_login=0)
    #                 new_login=AuthlogRecord(ip=ip,date=check_date_log(line),user=username.strip(),line=line)
    #                 if new_login not in logged_ip:
    #                     logged_ip.append(new_login)
    #                     find_end_date=True
    #     if find_end_date==True and re.search(pattern_end_session,line.lower()) and len(logged_ip)>0 and check_date_log(line)>=logged_ip[len(logged_ip)-1].date: #that would try to catch the end date of a session (auth_log_sessions method try to be more specific)
    #         logged_ip[len(logged_ip)-1].end_date=check_date_log(line)
    #         find_end_date=False
    # #file.close()
    #
    # list_authlog_success=list_AuthlogRecord(logged_ip)

    # todo potrei mettere da config a quanti limitare
    sum_fail_ip = 0
    reduce_host_output = False
    reduce_user_output = False
    if len(ip_suspicius) > 15:
        reduce_host_output = True
    if len(user_suspicius) > 15:
        reduce_user_output = True
    ip_table = []
    user_table = []
    for i in range(len(ip_suspicius)):
        if reduce_host_output:
            if tot_ip_fail[i] > 10:
                tot_user_ip = user_for_ip[i].split(";")
                if len(tot_user_ip) > 10:
                    j = 0
                    user_to_print = ""
                    while j < 10:
                        user_to_print += tot_user_ip[j] + ";"
                        j += 1
                    user_to_print += "+" + str(len(tot_user_ip) - 10) + "more"
                    ip_table.append([ip_suspicius[i], tot_ip_fail[i], user_to_print])
                else:
                    ip_table.append([ip_suspicius[i], tot_ip_fail[i], user_for_ip[i]])
        else:
            tot_user_ip = user_for_ip[i].split(";")
            if len(tot_user_ip) > 10:
                j = 0
                user_to_print = ""
                while j < 10:
                    user_to_print += tot_user_ip[j] + ";"
                    j += 1
                user_to_print += "+" + str(len(tot_user_ip) - 10) + "more"
                ip_table.append([ip_suspicius[i], tot_ip_fail[i], user_to_print])
            else:
                ip_table.append([ip_suspicius[i], tot_ip_fail[i], user_for_ip[i]])

    for i in range(len(user_suspicius)):
        # row_user="Tot failed attemp from user: ", user_suspicius[i], tot_user_fail[i],"with hostname:", ip_for_user[i]
        if reduce_user_output:
            if tot_user_fail[i] > 10:
                tot_ip_user = ip_for_user[i].split(";")
                if len(tot_ip_user) > 10:
                    j = 0
                    host_to_print = ""
                    while j < 10:
                        host_to_print += tot_ip_user[j] + ";"
                        j += 1
                    host_to_print += "+" + str(len(tot_ip_user) - 10) + "more"
                    user_table.append([user_suspicius[i], tot_user_fail[i], host_to_print])
                else:
                    user_table.append([user_suspicius[i], tot_user_fail[i], ip_for_user[i]])
        else:
            tot_ip_user = ip_for_user[i].split(";")
            if len(tot_ip_user) > 10:
                j = 0
                host_to_print = ""
                while j < 10:
                    host_to_print += tot_ip_user[j] + ";"
                    j += 1
                host_to_print += "+" + str(len(tot_ip_user) - 10) + "more"
                user_table.append([user_suspicius[i], tot_user_fail[i], host_to_print])
            else:
                user_table.append([user_suspicius[i], tot_user_fail[i], ip_for_user[i]])

    if len(ip_table) > 0:
        string = tt.to_string(
            [ip_table],
            header=["IP", "Tot failed login", "Usernames used"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    if len(user_table) > 0:
        string = tt.to_string(
            [user_table],
            header=["User", "Tot failed login", "IP used"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    # print("Tot ip found:",len(ip_suspicius))    #todo save in output
    for i in range(len(ip_suspicius)):
        # print("IP:", ip_suspicius[i], "tot failed count:", tot_ip_fail[i], "with user:", user_for_ip[i])
        sum_fail_ip += tot_ip_fail[i]
    # print("Tot fail:",sum_fail_ip,"\n")
    sum_fail_user = 0

    # print("Tot user found:", len(user_suspicius))    #todo save in output
    for i in range(len(user_suspicius)):
        # print("User:", user_suspicius[i], "tot failed count:", tot_user_fail[i], "with ip:",ip_for_user[i])
        sum_fail_user += tot_user_fail[i]
    # print("Tot fail:", sum_fail_user, "\n")

    return (ip_suspicius, tot_ip_fail, user_suspicius, tot_user_fail)


def auth_log_BF_success_2(auth_log_lines, auth_log_path, pattern_error, lines_to_save, login_list_new, ip_watchlist,
                          ip_whitelist, tot_ip_fail, tot_user_fail, ip_for_user, user_for_ip):
    print("Searching into: ", auth_log_path, "for login severity ",time.process_time())

    for record in login_list_new.record_list:
        whats_done = []
        # print(record)
        start_time = datetime.min
        i = 0
        start = False
        for record_general in auth_log_lines.record_list:
            line = record_general.line

            if record_general.error==True and re.search(pattern_error, line.lower()):
                ip = record_general.ip_record #get_ip_from_line(line)
                date_error = record_general.date_record#check_date_log(line)

                if ip and date_error:
                    # for ip in ip_found:
                    for x in range(login_list_new.record_list.index(record)):
                        if login_list_new.record_list[x].ip == ip:
                            start_time = login_list_new.record_list[x].date
                    # thanks to <= it gets more results then previus check
                    if ip == record.ip and start_time <= date_error <= record.date:
                        record.error_before_login += 1
                    #elif record.date >= date_error:
                    #    break
            if line == record.line:
                start = True
            if start == True and i < lines_to_save:  # so if you put a high limit it captures all from start to end session
                if "COMMAND" in line:
                    line = colored(line.strip(), "yellow")
                whats_done.append([line.strip()])
                i += 1
            if line == record.end_line:

                # whats_done.append([line.strip()])
                break
        record.what_happened = whats_done
        # print(record.what_happened, login_list_new.record_list.index(record), "\n")

    # add error count   todo add save on csv
    # sum_error = 0
    # start=0
    # i = 1
    probably_BF_table = []
    for record in login_list_new.record_list:
        # print(len(record.what_happened),record.what_happened)

        if record.ip:  # not in ip_blacklist and record.ip not in ip_whitelist and record.ip:
            if record.end_date is not None:
                tot_time = record.end_date - record.date
            else:
                tot_time = "None"

            if get_ip_type(record.ip) == "Public":  # valutare richiede molto tempo
                geo_response = geolocalize_ip(record.ip)
                #print(geo_response[0])
                country = geo_response[1].country
                record.country = country

            severity, tot_points = get_login_severity(record, tot_ip_fail, tot_user_fail, ip_for_user, user_for_ip,
                                                      ip_watchlist, ip_whitelist)

            report_BF = (
            "ATTENTION high probability of Brute Force Attack", "There was a connection from ip:", record.ip,
            "with user:", record.user, "at time:", str(record.date), "to:", str(record.end_date), "elapsed time:",
            str(tot_time), "tot try before success:", record.error_before_login)
            # print("\n",colored(report_BF,"red"))
            probably_BF_table.append(
                [severity, record.date, record.ip, record.user, record.error_before_login, record.country,
                 colored("True", "yellow") if record.first_time == True else "False",
                 colored("True", "yellow") if record.is_in_attack_time_byIP == True else "False",
                 colored("True", "yellow") if record.is_in_attack_time_onUser else "False",
                 colored("True", "yellow") if record.is_in_SA_attack == True else "False",
                 colored("True", "red") if record.IP_in_attack else "False",
                 colored("True", "red") if record.User_in_attack else "False"])

        # start = lines_to_save * i
        # i += 1
        # sum_error += record.error_before_login
        # print("Tot fail:", sum_error)
    if len(probably_BF_table) > 0:
        string = tt.to_string(
            [probably_BF_table],
            header=["Severity", "Login Time", "IP", "User", "Failed attempts bf success", "CN", "First Time",
                    "While BF by IP", "While BF on Usr", "While S.A.", "IP attacker", "Usr attacked"],
            style=tt.styles.ascii_thin_double,
            # alignment="ll",
            # padding=(0, 1),
        )
        print(string)

    # print("Next lines contains a part of what happened after the connection:")
    # for x in range(start,lines_to_save*i):
    # print(whats_done[x])
    # next_lines.append([whats_done[x].strip()])
    # todo get all lines between start end session

    for record in login_list_new.record_list:
        if record.ip in ip_watchlist:

            if record.end_date is not None:
                tot_time = record.end_date - record.date
            else:
                tot_time = "None"

            if get_ip_type(record.ip) == "Public":  # valutare richiede molto tempo
                geo_response = geolocalize_ip(record.ip)
                print(geo_response[0])
                country = geo_response[1].country
                record.country = country

            severity, tot_points = get_login_severity(record, tot_ip_fail, tot_user_fail, ip_for_user, user_for_ip,
                                                      ip_watchlist, ip_whitelist)

            report_BF = (
                "ATTENTION high probability of Brute Force Attack", "There was a connection from ip:", record.ip,
                "with user:", record.user, "at time:", str(record.date), "to:", str(record.end_date), "elapsed time:",
                str(tot_time), "tot try before success:", record.error_before_login)
            # print("\n",colored(report_BF,"red"))
            probably_BF_table_rich = [severity, record.date, record.ip, record.user, record.error_before_login,
                                      record.country,
                                      colored("True", "yellow") if record.first_time == True else "False",
                                      colored("True", "yellow") if record.is_in_attack_time_byIP == True else "False",
                                      colored("True", "yellow") if record.is_in_attack_time_onUser else "False",
                                      colored("True", "yellow") if record.is_in_SA_attack == True else "False",
                                      colored("True", "red") if record.IP_in_attack else "False",
                                      colored("True", "red") if record.User_in_attack else "False"]

            string = tt.to_string(
                [probably_BF_table_rich],
                header=["Severity", "Login Time", "IP", "User", "Failed attempts bf success", "CN", "First Time",
                        "While BF by IP", "While BF on Usr", "While S.A.", "IP attacker", "Usr attacked"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)

            if len(record.what_happened) > 0:
                string = tt.to_string(
                    [record.what_happened],
                    header=["Next lines contains a part of what happened after the connection of IP: " + record.ip],
                    style=tt.styles.ascii_thin_double,
                    # alignment="ll",
                    # padding=(0, 1),
                )
                print(string)

            if get_ip_type(record.ip) == "Public":
                multiple_ip_search([record.ip],short_search=True)


def spray_attack_authlog(failed_attemp_list, threshold_SA_count, threshold_SA_time):
    # when attackers try same pwd for mutiple user and then change it
    # when attackers try same pwd for mutiple user and then change it
    SA_txt = "Spray Attack Search:"
    # print(SA_txt)
    # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
    # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow([SA_txt])

    list_record_SA = []
    i = 1
    x = 0
    # print(len(list_btmp_record.record_list))
    while x < len(failed_attemp_list.record_list) - 2:
        # print(x,i)
        count = 0
        list_user = []
        list_user_record = []
        start = failed_attemp_list.record_list[x].date  # parser.parse()
        list_user.append(failed_attemp_list.record_list[x])
        if x < i and i == len(failed_attemp_list.record_list) - 1:
            break
        while i < len(failed_attemp_list.record_list) - 1:  # and count<threshold_SA_count
            end = failed_attemp_list.record_list[i].date  # parser.parse()
            i += 1
            if check_date_delta(start, end, threshold_SA_time):
                if failed_attemp_list.record_list[i].user not in list_user:
                    start = failed_attemp_list.record_list[i - 1].date  # parser.parse()
                    count += 1
                    list_user.append(failed_attemp_list.record_list[i].user)
                    list_user_record.append(failed_attemp_list.record_list[i])
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
    # print(len(list_record_SA))
    for list_record in list_record_SA:
        for record in list_record:
            if record.ip not in list_host_SA:  # and record.ip not in ip_whitelist:
                list_host_SA.append(record.ip)
                list_user_SA.append("")
                list_date_SA.append("")

    for host in list_host_SA:
        # print(host)
        for list_record2 in list_record_SA:
            for record2 in list_record2:
                if record2.ip == host:
                    i = list_host_SA.index(record2.ip)
                    if record2.user not in list_user_SA[i]:
                        list_user_SA[i] += record2.user + ";"
                        list_date_SA[i] += str(record2.date) + ";"
                        # print(record2.user)

    if len(list_host_SA) > 0 and len(list_user_SA) > 0:
        print(colored("Spray attack found:", "red"))
        SA_table = []
        size_to_use = min(len(list_host_SA), len(list_record_SA), len(list_user_SA))
        print(size_to_use)
        for i in range(size_to_use):
            # print(len(list_host_SA),len(list_user_SA))
            splitted = list_date_SA[i].split(";")
            report_SA = ("ATTENTION probably Spray Attack found:", "IP:", list_host_SA[i], "has done at least",
                         str(threshold_SA_count),
                         "failed login (each with different user) in", str(threshold_SA_time), "minutes",
                         str(len(list_record_SA[i])), "times with",
                         str(len(list_user_SA[i].split(";"))), "total different username",
                         "from:", splitted[0], "to:", splitted[len(splitted) - 2])
            SA_table.append(
                [str(len(list_record_SA[i])), list_host_SA[i], str(threshold_SA_count), str(threshold_SA_time),
                 str(len(list_user_SA[i].split(";"))), splitted[0], splitted[len(splitted) - 2]])
            # print(colored(report_SA,"red"))
            # print(list_user_SA[i])

            # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(report_SA)
            # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(list_user_SA[i].split(";"))

        # if len(BF_user_table) > 0:
        if len(SA_table) > 0:
            string = tt.to_string(
                [SA_table],
                header=["N° Spray Attack", "IP used", "Failed attempts with != user", "In x minutes",
                        "Tot. different username", "Start date", "End date"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)
    else:
        print(colored("Spray attack not found", "green"))

    return (list_host_SA, list_user_SA, list_date_SA)


def check_login_during_SprayAttack(SA_list_host, SA_list_user, SA_list_times, login_list_new,
                                   threshold_BF_time_login_search, threshold_BF_time_login_search_max,tsv=None):
    import datetime
    print(threshold_BF_time_login_search,threshold_BF_time_login_search_max)
    if len(SA_list_host) > 0 and len(SA_list_user) > 0:
        login_during_attack = []
        ip_to_check = []
        minutes_delta = datetime.timedelta(minutes=threshold_BF_time_login_search)
        hours_delta = datetime.timedelta(hours=threshold_BF_time_login_search_max)
        for SA_attack_data in SA_list_times:
            # print(SA_attack_data)
            specific_attack_dates = SA_attack_data.split(";")
            #specific_attack_dates = specific_attack_dates[0:len(specific_attack_dates) - 2]

            #specific_attack_data_start = parser.parse(specific_attack_dates[0])
            #specific_attack_data_end = parser.parse(specific_attack_dates[len(specific_attack_dates) - 1])

            if len(specific_attack_dates) > 1:
                specific_attack_dates = specific_attack_dates[0:len(specific_attack_dates) - 1]
                specific_attack_data_start = parser.parse(specific_attack_dates[0])
                specific_attack_data_end = parser.parse(specific_attack_dates[len(specific_attack_dates) - 1])
            else:
                specific_attack_data_start = parser.parse(specific_attack_dates[0])
                specific_attack_data_end = parser.parse(specific_attack_dates[0])
            # for specific_attack_data in specific_attack_dates:
            # specific_attack_data = parser.parse(specific_attack_data)

            i = 0
            # print(SA_list_host,SA_list_user)
            for login_record in login_list_new.record_list:
                #print(login_record.date)
                if login_record.is_in_SA_attack == False:
                    # if ip_search.is_ip_public(login_record.host,stamp=False) or login_record.host in BF_list_host: #check if ip logged is public or in BF list
                    start = specific_attack_data_start  # - datetime.timedelta(minutes=threshold_BF_time_login_search)
                    end = specific_attack_data_end + minutes_delta
                    large_end = specific_attack_data_end + hours_delta
                    if start <= login_record.date <= end:
                        login_record.is_in_SA_attack = True
                        if login_record not in login_during_attack:
                            login_during_attack.append(login_record)  # so i have host, time and user
                        if get_ip_type(login_record.ip) == "Public" and login_record.ip not in ip_to_check:
                            ip_to_check.append(login_record.ip)
                        # possibile ottimizzare?
                        if login_record.ip in SA_list_host:
                            login_record.IP_in_attack = True
                        if login_record.user in SA_list_user[i]:
                            login_record.User_in_attack = True
                    elif end < login_record.date < large_end:
                        if login_record.ip in SA_list_host:
                            login_record.IP_in_attack = True
                        if login_record.user in SA_list_user[i]:
                            login_record.User_in_attack = True
                    if i < len(SA_list_host) - 1:
                        i += 1
        host_ip_report = ("LOGIN WHILE/AFTER Spray Attack:", str(len(login_during_attack)))
        print(host_ip_report)
        # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow("\n")
        # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(host_ip_report)
        host_login_after_BF_table = []
        for login_record in login_list_new.record_list:
            if login_record.is_in_SA_attack == True:
                # print(login_record.host,login_record.user,login_record.start,login_record.pid)
                # for i in range(len(host_login_during_BF)):
                elapsed = None
                if login_record.end_date:
                    elapsed = login_record.end_date - login_record.date
                single_ip_report = ("Login found from ip:", login_record.ip, "with user:",
                                    login_record.user, "pid", login_record.session_id, "at", login_record.date,
                                    "end", login_record.end_date, "elapsed time", elapsed)
                # print(single_ip_report)
                host_login_after_BF_table.append([login_record.ip,
                                                  login_record.user, login_record.session_id, login_record.date,
                                                  login_record.end_date, elapsed])
                # csv.writer(tsv, delimiter=";", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(single_ip_report)

            # if login_record.IP_in_attack == True:
            #     print("IP in attack", login_record.host)
            # if login_record.User_in_attack == True:
            #     print("User in attack", login_record.user)
        # print(colored("HOST LOGIN DURING END AFTER BF:","red"))
        if len(host_login_after_BF_table) > 0:
            string = tt.to_string(
                [host_login_after_BF_table],
                header=["IP logged", "Username", "Session ID", "Start date", "End date", "Elapsed Time"],
                style=tt.styles.ascii_thin_double,
                # alignment="ll",
                # padding=(0, 1),
            )
            print(string)


def get_login_severity(authlog_session, failed_ip_count, failed_user_count, failed_host_name, failed_user_name,
                       ip_black_list, ip_white_list):
    import numpy as np
    # is new IP?
    # print(failed_ip_count, failed_user_count, failed_host_name, failed_user_name)
    # IP che logga ha fatto l'attacco
    if authlog_session.IP_in_attack:
        tot_points = 1  # todo decidere se abbassare soglia IP attaccante dopo tot tempo
    else:
        if authlog_session.first_time == True:
            is_new_ip = 0.9  # 0.9                                            # 0.9 * 1 * 1 *  1.2   login lecita durante un attacco
        else:
            is_new_ip = 0.8  # 0.7
        # IP country? IT
        if authlog_session.country == "IT" or authlog_session.country == "ZZ":
            ip_country = 0.8  # 1
        else:
            ip_country = 1  # 1.2
        # Data login appartiene a range attacco?
        if authlog_session.is_in_attack_time_onUser or authlog_session.is_in_attack_time_byIP or authlog_session.is_in_SA_attack:
            login_date = 1
        else:
            login_date = 0.8
        # l'utenza è stata attaccata
        if authlog_session.User_in_attack:
            attack_link = 0.9
        elif authlog_session.ip in failed_host_name and authlog_session.user in failed_user_name:
            # attack_link = 0.5
            # #print(max(failed_user_count[failed_user_name.index(wtmp_session.user)],
            #                   failed_ip_count[failed_host_name.index(wtmp_session.host)],
            #                   wtmp_session.fail_before_login),failed_user_name.index(wtmp_session.user),failed_host_name.index(wtmp_session.host))
            attack_link = 0.001 * max(failed_user_count[failed_user_name.index(authlog_session.user)],  # max(0.5
                                      failed_ip_count[failed_host_name.index(authlog_session.ip)],
                                      authlog_session.error_before_login)  # )
        elif authlog_session.ip in failed_host_name:
            # print(max(failed_ip_count[failed_host_name.index(wtmp_session.host)],
            #     wtmp_session.fail_before_login),failed_host_name.index(wtmp_session.host))
            attack_link = 0.001 * max(failed_ip_count[failed_host_name.index(authlog_session.ip)],  # max(0.5
                                      authlog_session.error_before_login)  # )
        elif authlog_session.user in failed_user_name:
            # print(max(failed_user_count[failed_user_name.index(wtmp_session.user)],
            #     wtmp_session.fail_before_login),failed_user_name.index(wtmp_session.user))
            attack_link = 0.001 * max(failed_user_count[failed_user_name.index(authlog_session.user)],  # max(0.5,
                                      authlog_session.error_before_login)  # )
        else:
            attack_link = 0.5

        tot_points = is_new_ip * ip_country * login_date * attack_link
        #print("newip " + str(is_new_ip) + " CN " + str(ip_country) + " Date: " + str(login_date) + " Atk " + str(
            #attack_link) + "\n")
    #print("Product before modify:" + str(tot_points))

    if len(ip_black_list) > 0 and authlog_session.ip in ip_black_list:  # increase severity
        if tot_points < 0.1:
            tot_points += 0.45
        elif tot_points < 0.5:
            tot_points += 0.35
        elif tot_points < 0.7:
            tot_points += 0.25
        elif tot_points < 0.85:
            tot_points = 0.9
    # if len(ip_white_list)>0 and authlog_session.ip in ip_white_list: #decrease severity
    #     if tot_points > 0.85:
    #         tot_points -= 0.3
    #     elif tot_points > 0.4:
    #         tot_points -= 0.25

    #print("PRODUCT final" + str(tot_points))

    if 0 <= tot_points <= 0.15:
        return colored("VERY LOW", "green"), tot_points
    elif 0.15 < tot_points <= 0.4:
        return colored("LOW", "green"), tot_points
    elif 0.4 <= tot_points < 0.6:
        return colored("MEDIUM", "yellow"), tot_points
    elif 0.6 <= tot_points <= 0.85:
        return colored("HIGH", "magenta"), tot_points
    elif tot_points > 0.85:
        return colored("VERY HIGH", "red"), tot_points


def get_command_lines(auth_log_path=None, lines=None):
    command_lines = []

    if auth_log_path and check_if_file_exist(auth_log_path):
        with open(auth_log_path, "r") as file:
            for line in file:
                if "COMMAND" in line:
                    command_lines.append(line.strip())
        file.close()

    if lines != "":
        for line in lines:
            if "COMMAND" in line:
                command_lines.append(line.strip())

    return command_lines

# if len(ip_blacklist) > 0 and len(ip_whitelist) == 0:

# elif len(ip_whitelist) > 0 and len(ip_blacklist) == 0:


# else: