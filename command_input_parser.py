import argparse, configparser
import dateutil
from datetime import datetime
import sys

def commands_helper():
    # creating the parser for the user input
    parser = argparse.ArgumentParser()
    parser.description= "Welcome! With LogAnalysisTool it is possible to perform forensic analysis of Wtmp, Btmp and " \
                        "Secure log (auth.log) files. Specifically, sessions and access attempts to the system are " \
                        "extracted, to detect the presence of eventual attack patterns (Brute Force or Spray) and " \
                        "the related (eventual) malicious logins. Moreover, it is possible to search from public " \
                        "sources details about the attacking IPs and/or possible IPs of interest. Finally, it is" \
                        "possible to search by keywords or by time filters within (non-binary) files."

    # group = parser.add_mutually_exclusive_group()
    subparser = parser.add_subparsers(dest='command')

    # LIST OF COMMANDS
    grep = subparser.add_parser('grep')
    rgrep = subparser.add_parser('rgrep')
    time = subparser.add_parser('time')
    rtime = subparser.add_parser('rtime')
    single_ip_search = subparser.add_parser('single_ip_search')
    multiple_ip_search = subparser.add_parser('multiple_ip_search')
    #get_files = subparser.add_parser('files')  # todo sarà da rimuovere
    binary_parse = subparser.add_parser('binary_parse')
    login_search = subparser.add_parser('login_search')
    secure_log_search = subparser.add_parser('secure_log_search')
    #shodan = subparser.add_parser('shodan')

    # GREP - data input
    grep.description = "The <grep> command is used to find keywords within a single readable (non-binary) file." \
                       " It performs a line-by-line check and extracts only those lines that match the requested pattern."
    grep.add_argument('-file', type=str, required=True,
                      help='Search for pattern in a file (word can be a subpart of other word)')
    grep.add_argument('-pattern', type=str, required=True)
    grep.add_argument('-specific', action='store_true', help='Search for pattern in file (singular word)')
    grep.add_argument('-all', action='store_true', default=False,
                      help='Search for every pattern in file (ex. match Word word wOrd)')
    # grep.print_help()

    # RecursiveGREP - data input
    rgrep.description = "The <rgrep> command is used to find keywords within readable (non-binary) files in a directory." \
                        " It performs a line-by-line check and extracts only those lines that match the requested pattern."
    rgrep.add_argument('-dir', type=str, required=True,
                       help='Search for pattern in a directory\'s files (word can be a subpart of other word)')
    rgrep.add_argument('-pattern', type=str, required=True)
    rgrep.add_argument('-specific', action='store_true', help='Search for pattern in file dir (singular word)')
    rgrep.add_argument('-all', action='store_true', default=False,
                       help='Search for every pattern in file dir (ex. match Word word wOrd)')

    # TIME - data input
    time.description = "The <time> command is used to filter logs within a single readable (non-binary) file through a requested time interval." \
                       " It performs a line-by-line check and extracts only those lines that match the requested pattern." \
                       "By default the <end time> is the locatime of the machine on which the execution is invoked"
    time.add_argument('-file', type=str, required=True,
                      help='Search through start and end time beetwen records in a file')
    time.add_argument('-start', type=str, required=True, help="select a start time (or write min in order to start from first record)")
    now = datetime.now()
    now = str(now).split(".")[0]
    default_end = dateutil.parser.parse(now)
    time.add_argument('-end', type=str, default=str(default_end), help="select a start time (deafult= now)")

    # RecursiveTIME - data input
    rtime.description = "The <rtime> command is used to filter logs within readable (non-binary) files in a directory through a requested time interval." \
                       " It performs a line-by-line check and extracts only those lines that match the requested pattern." \
                       "By default the <end time> is the locatime of the machine on which the execution is invoked"
    rtime.add_argument('-dir', type=str, required=True,
                       help='Search through start and end (default=now) time records in a directory\'s files')
    rtime.add_argument('-start', type=str, required=True)
    now = datetime.now()
    now = str(now).split(".")[0]
    default_end = dateutil.parser.parse(now)
    rtime.add_argument('-end', type=str, default=str(default_end))

    # IP SEARCH - GETWHOIS
    single_ip_search.description = "The <single_ip_search> command is used to get informations of a single IP address:" \
                                   " IP geolocalization, public info (Description, CN, ASN, etc)," \
                                   " reputation, open ports and CVE vulnerabilities." \
                                   "It uses IP2Geotools, AbuseIPDB and Shodan."
    single_ip_search.add_argument('-ip', type=str, required=True, help='Search ip infos from public getwhois')

    multiple_ip_search.description = "The <multiple_ip_search> command is used to get informations of multiple IP addresses:" \
                                     " IP geolocalization, public info (Description, CN, ASN, etc)," \
                                     " reputation, open ports and CVE vulnerabilities." \
                                     "It uses IP2Geotools, AbuseIPDB and Shodan. Due to the possible large amount of " \
                                     "IPs requested, it presents the output data in a different format" \
                                     " than the single-ip-search."
    multiple_ip_search.add_argument('-iplist', type=str, required=True, default=[],
                                    help='Search ip infos from public getwhois', nargs='+')

    #shodan.description = "If you only need to known some informations about the IP reputation you can use the <shodan>" \
    #                    "command to get them."
    #shodan.add_argument('-iplist', type=str, required=True, default=[], help='Search reputation info for a list of IP addresses from Shodan',
                        #nargs='+')
    # SEARCH FOR FILE IN FOLDER RECURSIVE
    #get_files.add_argument('-dir', type=str, required=True,
                          #help='Search for all files (.pattern) in a directory (and sub-dir)')
    # get_files.add_argument('-pattern', type=str, required=True)

    # UTMP - WTMP - BTMP PARSING
    binary_parse.description = "Through the <binary_parse> command it is possible to analyze Wtmp and Btmp files " \
                               "individually. Specifically, in the first case all the system sessions will be extracted, " \
                               "while in the second case the system access attempts will be searched to identify attack " \
                               "patterns (Brute Force and Spray) and statistical information about these attempts. " \
                               "The search for information about the attacking IPs will be performed automatically."
    binary_parse.add_argument("-file", type=str, help="specified input utmp/wtmp/btmp file", required=True)
    binary_parse.add_argument('-ip_watchlist', type=str, default=[],
                              help='Insert IP watchlist to get more attention on them', nargs='+')
    binary_parse.add_argument('-ip_whitelist', type=str, default=[],
                              help='Insert IP whitelist to reduce the attention on them', nargs='+')
    binary_parse.add_argument('-hpux', action='store_true', default=False,
                                help='Option to handle HP-UX binary wtmp and btmp files')
    # binary_parse.add_argument("-output", type=str, help="specified output file name (.csv), if none the output will be displayed in prompt", default=None)

    # CALL LOGIN SUCCESS AND FAILURE CORRELATION SEARCH
    login_search.description = "Through the <login_search> command it is possible to analyze a couple of Wtmp and Btmp files. " \
                                "All the system sessions and all system access attempts will be searched in order to identify attack " \
                                "patterns (Brute Force and Spray), statistical information about these attempts and malicious logins. " \
                                "The search for information about the attacking IPs will be performed automatically."
    login_search.add_argument("-wtmp", type=str,
                              help="Search for login success and failure correlation. specified input wtmp file",
                              required='-json_wtmp' not in sys.argv and '-json_btmp' not in sys.argv)
    login_search.add_argument("-btmp", type=str, help="specified input btmp file",
                              required='-json_wtmp' not in sys.argv and '-json_btmp' not in sys.argv)
    login_search.add_argument("-json_wtmp", type=str, help="specified input wtmp file in json format (post binary parse analysis)",
                              required='-wtmp' not in sys.argv and '-btmp' not in sys.argv)
    login_search.add_argument("-json_btmp", type=str,
                              help="specified input wtmp file in json format (post binary parse analysis)",
                              required='-wtmp' not in sys.argv and '-btmp' not in sys.argv)
    login_search.add_argument("-output", type=str, help="specified output csv file")
    login_search.add_argument('-ip_watchlist', type=str, default=[],
                                    help='Insert IP watchlist to get more attention on them', nargs='+')
    login_search.add_argument('-ip_whitelist', type=str, default=[],
                              help='Insert IP whitelist to reduce the attention on them', nargs='+')
    login_search.add_argument('-hpux', action='store_true', default=False,
                              help='Option to handle HP-UX binary wtmp and btmp files')

    # AUTHLOG SEARCH
    secure_log_search.description = "Through the <secure_log_search> command it is possible to analyze auth.log (or secure) files. " \
                                  "All the system sessions and all system access attempts will be searched in order to identify attack " \
                               "patterns (Brute Force and Spray), statistical information about these attempts and malicious logins. " \
                               "The search for information about the attacking IPs will be performed automatically."
    secure_log_search.add_argument("-file", type=str, help="specified input auth_log file (see config.txt file)",
                                 required=True)
    secure_log_search.add_argument('-ip_watchlist', type=str, default=[],
                              help='Insert IP watchlist to get more attention on them', nargs='+')
    secure_log_search.add_argument('-ip_whitelist', type=str, default=[],
                              help='Insert IP whitelist to reduce the attention on them', nargs='+')
    #auth_log_search.add_argument('-list_show_more', type=str, default=[],
                              #help='Insert IP list for which you need more details', nargs='+')

    # PARSING INPUT
    args = parser.parse_args()

    # reading configfile
    configParser = configparser.RawConfigParser()
    configFilePath = r"config.txt"
    configParser.read(configFilePath)

    return (args,configParser)
