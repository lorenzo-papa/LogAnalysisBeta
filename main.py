
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

import terminalMethods as tm
import search_functions as sf
import binary_analysis as bp
import authlog_analysis as ats
import ip_search as ips
import command_input_parser as commands
import argparse, configparser
import dateutil, pprint
from datetime import datetime
import struct
from utility import create_working_dir
from texttable import Texttable
from termcolor import colored

if __name__ == '__main__':

    #calling commands and configs parser
    (args, configParser) = commands.commands_helper()
    create_working_dir()
    #start recording time performances
    start = tm.start_record_performance()

    #recognise command sent by user
    # grep case
    if args.command == 'grep':
        if args.specific:
            print('Grep Exact Match execution\n')
            sf.grep_exact_match(args.file, args.pattern)
        else:
            print('Grep execution\n')
            sf.grep(args.file, args.pattern, args.all)
    # rgrep case
    elif args.command == 'rgrep':
        if args.specific:
            print('Rgrep Exact Match execution\n')
            sf.rgrep_exact_match(args.dir, args.pattern)
        else:
            print('Rgrep execution\n')
            sf.rgrep(args.dir, args.pattern, args.all)
    # time
    elif args.command == 'time':
        print('Time execution\n')
        sf.time_search(args.file, args.start, args.end)
    # rtime
    elif args.command == 'rtime':
        print('Rtime execution\n')
        sf.rtime_search(args.dir, args.start, args.end)
    # ip_search
    elif args.command == 'single_ip_search':
        print('Single IP Search execution\n')
        ips.single_ip_search(args.ip)
    elif args.command == 'multiple_ip_search':
        print('Multiple IP Search execution\n')
        ips.multiple_ip_search(args.iplist)
    #elif args.command == 'shodan': #todo in futuro valutare se chiedere api_key qua e non nel config  (aggiungi ip abuse)
     #   print("IP reputation check")
      #  api_key = configParser.get('SHODAN', 'api_key')
       # ips.shodan_checker(args.iplist, api_key)
    # files - all dir files and sub -> for future implementation
    #elif args.command == 'files':  #todo sarà da rimuovere
        #print(sf.delete_equal_file(args.dir))
    # binary parsing -> btmp and wtmp -> search for attacks
    elif args.command == 'binary_parse':
        t = Texttable()
        t.add_rows([['Binary file parsing (wtmp,btmp,utmp), more data in \Parser_Output'],
                     ["WTMP: Analysis of system logins"],
                     ["BTMP: Analysis of failed logins, Brute Force and Spray attack search"
        ]])
        print(t.draw())

        threshold_BF_time = configParser.get('Brute Force', 'threshold_BF_time')
        threshold_BF_count = configParser.get('Brute Force', 'threshold_BF_count')
        threshold_SA_count = configParser.get('Spray Attack', 'threshold_SA_count')
        threshold_SA_time = configParser.get('Spray Attack', 'threshold_SA_time')
        bp.utmp_wtmp_btmp_parse_call(input_file=args.file, threshold_BF_time=int(threshold_BF_time),
                                     threshold_BF_count=int(threshold_BF_count),
                                     threshold_SA_count=int(threshold_SA_count),
                                     threshold_SA_time=int(threshold_SA_time), ip_blacklist=args.ip_watchlist,
                                     ip_whitelist=args.ip_whitelist, hp_ux=args.hpux)
    # correlation between login failures and success
    elif args.command == 'login_search':
        print('Parsing, brute force and spray attack search and login success and failure correlation (wtmp,btmp)\n')
        threshold_BF_time = configParser.get('Brute Force', 'threshold_BF_time')
        threshold_BF_count = configParser.get('Brute Force', 'threshold_BF_count')
        brute_force_threshold_success = configParser.get('Brute Force', 'brute_force_threshold_success')
        threshold_BF_time_login_search = configParser.get('Brute Force', 'threshold_BF_time_login_search')
        threshold_BF_time_login_search_max = configParser.get('Brute Force', 'threshold_BF_time_login_search_max')
        threshold_SA_count = configParser.get('Spray Attack', 'threshold_SA_count')
        threshold_SA_time = configParser.get('Spray Attack', 'threshold_SA_time')
        bp.wtmp_btmp_correlation(input_btmp=args.btmp, input_wtmp=args.wtmp, input_json_wtmp=args.json_wtmp,
                                 input_json_btmp=args.json_btmp,
                                 threshold_BF_time=int(threshold_BF_time), threshold_BF_count=int(threshold_BF_count),
                                 brute_force_threshold_success=int(brute_force_threshold_success),
                                 threshold_BF_time_login_search=int(threshold_BF_time_login_search),
                                 threshold_SA_count=int(threshold_SA_count), threshold_SA_time=int(threshold_SA_time),
                                 threshold_BF_time_login_search_max=int(threshold_BF_time_login_search_max),
                                 ip_black_list=args.ip_watchlist, ip_white_list=args.ip_whitelist, hp_ux=args.hpux)
    # authlog analysis -> search for sessions and brute force attacks
    elif args.command == 'secure_log_search':

        print('Authlog/Securelog brute force and spray attack search and correlation between success and failure login\n')
        auth_log_threshold_success = configParser.get('AuthLog', 'auth_log_threshold_success')
        threshold_authlog_BF_time = configParser.get('AuthLog', 'threshold_authlog_BF_time')
        threshold_authlog_BF_count = configParser.get('AuthLog', 'threshold_authlog_BF_count')
        threshold_authlog_BF_time_login_search = configParser.get('AuthLog', 'threshold_authlog_BF_time_login_search')
        log_lines_to_save = configParser.get('AuthLog', 'log_lines_to_save')
        pattern_error = configParser.get('AuthLog', 'pattern_error')
        #pattern_session = configParser.get('AuthLog', 'pattern_session')
        #pattern_not_match = configParser.get('AuthLog', 'pattern_not_match')
        threshold_authlog_BF_time_login_search_max = configParser.get('AuthLog', 'threshold_authlog_BF_time_login_search_max')
        threshold_SA_count = configParser.get('Spray Attack', 'threshold_SA_count')
        threshold_SA_time = configParser.get('Spray Attack', 'threshold_SA_time')
        ats.auth_log_analysis(auth_log_path=args.file, pattern_error=pattern_error,
                              authlog_threshold_success=int(auth_log_threshold_success),
                              lines_to_save=int(log_lines_to_save),
                              threshold_authlog_BF_count=int(threshold_authlog_BF_count),
                              threshold_authlog_BF_time=int(threshold_authlog_BF_time),
                              threshold_authlog_BF_time_login_search=int(threshold_authlog_BF_time_login_search),
                              threshold_SA_count=int(threshold_SA_count), threshold_SA_time=int(threshold_SA_time),
                              threshold_authlog_BF_time_login_search_max=int(threshold_authlog_BF_time_login_search_max),
                              ip_blacklist=args.ip_watchlist, ip_whitelist=args.ip_whitelist)#,
                              #list_show_more=args.list_show_more)
        #,pattern_session, pattern_not_match)

    tm.get_final_perfomance(start)



    # with open('/Users/lorenzopapa/Desktop/lastlog', "rb") as f:
    #     buf = f.read()
    #     for entry in utmp.read(buf):
    #         print(entry.time, entry.type, entry)

