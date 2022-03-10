class BinaryRecord:
    def __init__(self, type, pid, line, id, user, host, term, exit, session, sec, usec, addr):
        self.type=type
        self.pid=pid
        self.line = line
        self.id=id
        self.user=user
        self.host=host
        self.term = term
        self.exit = exit
        self.session = session
        self.sec = sec
        self.usec = usec
        self.addr = addr

class list_UtmpRecord:
    def __init__(self, record_list, name="utmp_list"):
        self.record_list=record_list
        self.name=name

class list_WtmpRecord:
    def __init__(self, record_list, name="wtmp_list"):
        self.record_list=record_list
        self.name=name

class list_BtmpRecord:
    def __init__(self, record_list, name="btmp_list"):
        self.record_list=record_list
        self.name=name

#it has a different binary structure from UWBtmp records
class list_lastLogRecord:
    def __init__(self, record_list, name="lastlog_list"):
        self.record_list = record_list
        self.name = name

class wtmp_Session:
    def __init__(self, host, user, pid, start, end=None, tot_time=None, type=None, first_time=False,
                 is_in_attack_time_byIP=False, is_in_attack_time_onUser=False, is_in_SA_attack=False,
                 IP_in_attack=False, User_in_attack=False, fail_before_login=0, IP_fail=0, User_fail=0, country="ZZ"):
        self.host = host
        self.user = user
        self.start = start
        self.pid = pid
        self.end = end
        self.tot_time = tot_time
        self.type = type
        self.first_time = first_time #next used for severity
        self.is_in_attack_time_byIP = is_in_attack_time_byIP
        self.is_in_attack_time_onUser = is_in_attack_time_onUser
        self.is_in_SA_attack = is_in_SA_attack
        self.IP_in_attack = IP_in_attack
        self.User_in_attack = User_in_attack
        self.fail_before_login = fail_before_login
        self.country = country
        self.IP_fail = IP_fail
        self.User_fail = User_fail

class list_wtmp_Session:
    def __init__(self, record_list, name="wtmp_session_list"):
        self.record_list = record_list
        self.name = name

class BtmpOutput:
    def __init__(self,list_record_UWtmp, failed_ip_count, failed_user_count, failed_host_name, failed_user_name,
                    BF_list_host, BF_list_host_times, BF_list_user, BF_list_user_times,
                    list_host_SA, list_user_SA, list_date_SA, name="btmp_analysis"):
        self.list_record_UWtmp = list_record_UWtmp
        self.failed_ip_count = failed_ip_count
        self.failed_user_count = failed_user_count
        self.failed_host_name = failed_host_name
        self.failed_user_name = failed_user_name
        self.BF_list_host = BF_list_host
        self.BF_list_host_times = BF_list_host_times
        self.BF_list_user = BF_list_user
        self.BF_list_user_times = BF_list_user_times
        self.list_host_SA = list_host_SA
        self.list_user_SA = list_user_SA
        self.list_date_SA = list_date_SA
        self.name = name

class AuthlogRecord:
    def __init__(self, ip, date, user="", line="", error_before_login=0, end_date=None, session_id=None,
                 type=None, first_time=False, is_in_attack_time_byIP=False, is_in_attack_time_onUser=False,
                 is_in_SA_attack=False, IP_in_attack=False, User_in_attack=False, IP_fail=0, User_fail=0,
                 country="ZZ", end_line="", what_happened = []):
        self.ip = ip
        self.date = date
        self.user = user
        self.line = line
        self.error_before_login = error_before_login
        self.end_date = end_date
        self.session_id = session_id
        self.type = type
        self.first_time = first_time  # next used for severity
        self.is_in_attack_time_byIP = is_in_attack_time_byIP
        self.is_in_attack_time_onUser = is_in_attack_time_onUser
        self.is_in_SA_attack = is_in_SA_attack
        self.IP_in_attack = IP_in_attack
        self.User_in_attack = User_in_attack
        self.IP_fail = IP_fail
        self.User_fail = User_fail
        self.country = country
        self.end_line = end_line
        self.what_happened = what_happened

class list_AuthlogRecord:
    def __init__(self, record_list, name="authlog_list"):
        self.record_list = record_list
        self.name = name

class auth_severity:
    def __init__(self, ip_record, date_record, line, user, error=False):
        self.ip_record=ip_record
        self.date_record=date_record
        self.line=line
        self.user=user
        self.error=error

class list_auth_severity:
    def __init__(self, record_list):
        self.record_list = record_list

class End_session:
    def __init__(self, id_end, end_time, end_line):
        self.id_end = id_end
        self.end_time = end_time
        self.end_line = end_line

class list_End_session:
    def __init__(self, record_list):
        self.record_list = record_list

class IP_info:
    def __init__(self, IP,IP_CIDR=None,ASN=None,Description=None,Email=None,Name=None,Country=None,
                 Region=None,City=None,AbuseScore=None,NumReports=None):
        self.IP=IP
        self.IP_CIDR = IP_CIDR
        self.ASN = ASN
        self.Description = Description
        self.Email = Email
        self.Name = Name
        self.Country = Country
        self.Region=Region
        self.City = City
        self.AbuseScore = AbuseScore
        self.NumReports = NumReports






#todo not used
class authlog_ip_founded:
    def __init__(self,ip,date,user="",error=0,end_date=None):
        self.ip=ip
        self.date=date
        self.user=user
        self.error=error
        self.end_date=end_date