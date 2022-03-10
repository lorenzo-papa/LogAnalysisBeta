import json

import ipwhois.exceptions
import requests
import shodan
from ipwhois import IPWhois, IPDefinedError  # from pip install
from pprint import pprint
import ipaddress
import whois   #from pip install
import csv, time
import collections
from ip2geotools.databases.noncommercial import DbIpCity  #pip install ip2grotools
from requests import RequestException
from termcolor import colored
import termtables as tt
from utility import *

def is_ip_public(ip,stamp=True):
    if stamp==True:
        try:
            public=False
            addr = ipaddress.IPv4Address(ip)
            if addr.is_global:
                print("\nPublic IP: ", ip)
                public=True
            elif addr.is_private:
                print("\nPrivate IP", ip)
            elif addr.is_reserved:
                print("\nReserved IP", ip)
        except ValueError:
            print("\nERROR:", ip, "is not a valid IP, please insert only valid ip addresses")
            return public
        return public

    if stamp==False: #i only want to know if is public
        try:
            public=False
            addr = ipaddress.IPv4Address(ip)
            if addr.is_global:
                public=True
        except ValueError:
            return public
        return public

def get_ip_type(ip):
    #https://datatracker.ietf.org/doc/html/rfc3330.html
    try:
        addr = ipaddress.IPv4Address(ip)
        if addr.is_global:
            return "Public"
        elif addr.is_loopback:
            return "Local"
        elif addr.is_private:
            return "Private"
        elif addr.is_reserved:
           return "Reserved"

    except ValueError:
        print("\nERROR:", ip, "is not a valid IP, please insert only valid ip addresses")
        return None


def single_ip_search(ip):
    ip = ip.strip('\n')  # Removing any new line character from the end of line
    ip = ip.strip('\r')
    print("\nSingle IP search for:",ip)
    try:
        if is_ip_public(ip):
            obj = IPWhois(ip)
            res = obj.lookup_whois()
            if res is not None:
                pprint(res)
            # w = whois.whois(ip)
            # print("\n\nOTHER DATA FOUND:\n", w)
            print("\n")
            geolocalize_ip(ip,stampa=True)
            shodan_ip=[ip]
            shodan_checker(shodan_ip,stampa=True)
            abuseIP_checker(shodan_ip,stampa=True)
    except ValueError as err:
        print("\nIP value error", err)
    except IPDefinedError as err:
        print("\nIP definition error",err)

def multiple_ip_search(ip_list, short_search=False):    #todo sposta ip check, prendilo da fuori
    print("Multiple IP search for:",ip_list)
    print("Results saved in Parser_Output\multiple_ip")
    export_file_path = r"Parser_Output/"
    time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
    name1 = "multiple_ip_search" + time_now + ".csv"
    export_file = export_file_path + name1

    with open(export_file, "w+") as outfile:
        for ip in ip_list:
            ip = ip.strip('\n')  # Removing any new line character from the end of line
            ip = ip.strip('\r')
            if is_ip_public(ip):
                try:
                    outfile.write('IP;' + 'IP_CIDR;' + 'ASN;' + 'Description;' + 'Email;' + 'Name;' + 'Country;' + 'City' + '\n')
                    #for ip in ip_list:
                    obj = IPWhois(ip)
                    res = obj.lookup_whois()
                    IP_table=[]
                    geo_response = geolocalize_ip(ip)
                    if short_search:
                        if geo_response[1].country == "IT":
                            break
                    ip_shodan = [ip]
                    abuseip_response = abuseIP_checker(ip_shodan)

                    if res is not None:
                        whois_0 = collections.namedtuple("ObjectName", res.keys())(*res.values())
                        #if len(ip_list) <= 5:
                            #print("IP DATA FOUND:",whois_0)

                        for i in range(len(whois_0.nets)):
                            whois_new = collections.namedtuple("ObjectName", whois_0.nets[i].keys())(
                                *whois_0.nets[i].values())
                            # print(whois_new.cidr, whois_new.name, whois_new.description, whois_new.country, whois_new.city, whois_new.emails)
                            if whois_new.cidr is not None:
                                cidr = str(whois_new.cidr).replace("\n", "")
                            else:
                                cidr = ""
                            if whois_0.asn_description is not None:
                                asn_description = str(whois_0.asn_description).replace("\n", "")
                                asn_description_out = (str(asn_description)[:25] + '..') if len(str(asn_description)) > 25 else str(
                                    asn_description)
                                asn_description_out.strip()
                            else:
                                asn_description = ""
                                asn_description_out = ""
                            if whois_new.description is not None:
                                description = str(whois_new.description).replace("\n", "")
                                description_out = (str(description)[:12] + '..') if len(str(description)) > 12 else str(description)
                                description_out.strip()
                            else:
                                description = ""
                                description_out = ""
                            if whois_new.emails is not None:
                                emails = str(whois_new.emails).replace("\n", "")
                                out_email=whois_new.emails[0]
                            else:
                                emails = ""
                                out_email=None
                            if whois_new.name is not None:
                                name = str(whois_new.name).replace("\n", "")
                                name_out = (str(name)[:12] + '..') if len(str(name)) > 12 else str(
                                    name)
                                name_out.strip()
                            else:
                                name = ""
                                name_out = ""
                            if whois_new.country is not None:
                                country = str(whois_new.country).replace("\n", "")
                            else:
                                country = ""
                            if whois_new.city is not None:
                                city = str(whois_new.city).replace("\n", "")
                            else:
                                city = ""
                            outfile.write(str(ip) + ';' + cidr + ';' + asn_description + ';' + description + ';' +
                                           emails + ';' + name + ';' + country + ';' + city + '\n')

                            #qua crea record
                            new_record = IP_info(IP=ip,IP_CIDR=cidr,ASN=asn_description_out,Description=description_out,
                                                 Email=out_email,Name=name_out)
                            if geo_response is not None:
                                new_record.Country=geo_response[1].country
                                new_record.Region=geo_response[1].region
                                new_record.City=geo_response[1].city
                            if abuseip_response is not None:
                                new_record.AbuseScore = abuseip_response["abuseConfidenceScore"]
                                new_record.NumReports = abuseip_response["totalReports"]
                            IP_table.append(new_record)
                    #response=geolocalize_ip(ip)
                    outfile.write('IP;' + 'City;' + 'Region;' + 'Country;' + 'Latitude;' + 'Longitude' + '\n')
                    if geo_response is not None:
                        outfile.write(geo_response[0])#write on csv
                        outfile.write('\n')
                    #ip_shodan=[ip]
                    shodan_response=shodan_checker(ip_shodan)
                    if shodan_response is not None:
                        outfile.write("Shodan output: "+str(shodan_response))
                        outfile.write('\n')
                    #abuseip_response=abuseIP_checker(ip_shodan)
                    if abuseip_response is not None:
                        outfile.write("AbuseIP output: " + str(abuseip_response))
                        outfile.write('\n')

                    IP_table_output=[]
                    for i in range(len(IP_table)):
                        IP_table_output.append([IP_table[i].IP, IP_table[i].IP_CIDR, IP_table[i].ASN, IP_table[i].Description,
                                                IP_table[i].Email,IP_table[i].Name, IP_table[i].Country, IP_table[i].Region,
                                                IP_table[i].City,IP_table[i].AbuseScore,IP_table[i].NumReports])
                    string = tt.to_string(
                        [IP_table_output],
                        header=["IP","IP_CIDR" ,"ASN","Description","Email","Name","Country",
                                "Region","City","AbuseScore","NumReports"],
                        style=tt.styles.ascii_thin_double,
                        # alignment="ll",
                        # padding=(0, 1),
                    )
                    print(string)
                except ValueError as err:
                    print("\nIP value error", err)
                except IPDefinedError as err:
                    print("\nIP definition error", err)
                except ipwhois.exceptions.WhoisLookupError as err:
                    print("\nIPWhois error", err)
                except ipwhois.exceptions.HTTPRateLimitError as err:
                    print("\nRate limit error", err)
                except ipwhois.exceptions.HTTPLookupError as err:
                    print("\nRate limit error", err)
    outfile.close()
    #is_file_empty(name1)

def geolocalize_ip(ip,stampa=False,outputfile=None):
    #todo fare gestione eccezioni se sito non risponde o altro (vedere se puoi fare reputazione)
    #https://pypi.org/project/ip2geotools/
    try:
        response = DbIpCity.get(ip, api_key='free')
        #response.ip_address #'147.229.2.90'
        #response.city #'Brno (Brno střed)'
        #response.region #'South Moravian'
        #response.country #'CZ'
        # if new_record is not None and response is not None:
        #     new_record.Country=response.country
        #     new_record.Region=response.region
        #     new_record.City=response.city
        if stampa==True:
            print("IP GEOLOCATION:",response.ip_address,"City:",response.city,"Region:",response.region,"Country:",response.country,
                  "Latitude:",response.latitude,"Longitude:",response.longitude)
        #response.latitude
        #response.longitude
        if outputfile:
            #print("entrato")
            with open(outputfile, "a") as outfile2:
                outfile2.write('IP;'+'City;'+'Region;'+'Country;'+'Latitude;'+'Longitude'+'\n')
                outfile2.write(response.to_csv(';')) #'147.229.2.90,Brno (Brno střed),South Moravian,CZ,49.1926824,16.6182105'
            return [response.to_csv(';'),response]
        else:
            return [response.to_csv(';'),response]
    except ConnectionError:
        print("Connection error")
    except TimeoutError:
    # Maybe set up for a retry, or continue in a retry loop
        print("Timeout error")
    except RequestException as e:
        # catastrophic error. bail.
        raise SystemExit(e)

# from https://causlayer.orgs.hk/d4rkflam1ngo/ip-reputation-checker if you want can add virus total or ipabuse
# https://shodan.readthedocs.io/en/latest/api.html#exceptions
def shodan_checker(ip_list,stampa=False,api_key=None):
    method_exit=False

    if api_key==None:
        try:
            import configparser
            configParser = configparser.RawConfigParser()
            configFilePath = r"config.txt"
            configParser.read(configFilePath)
            api_key = configParser.get('SHODAN', 'api_key')
            api_key = api_key.strip('\n')  # Removing any new line character from the end of line
            api_key = api_key.strip('\r')
            if api_key == None or api_key=="" or api_key==" ":
                method_exit = True
        except:
            print("Error: file config does not exist/is not readable or you don't a valid API Key for Shodan")
            method_exit = True

    if method_exit == False:
        for ip in ip_list:
            ip = ip.strip('\n')  # Removing any new line character from the end of line
            ip = ip.strip('\r')
            try:
                api = shodan.Shodan(api_key)

                # Lookup the host
                host = api.host(ip)

                # Print general info
                if stampa == True:
                    print(colored("""
                      ___ _            _           
                     / __| |_  ___  __| |__ _ _ _  
                     \__ \ ' \/ _ \/ _` / _` | ' \ 
                     |___/_||_\___/\__,_\__,_|_||_|
                    IP: {}
                    Organization: {}
                    Operating System: {}
                        """, "red").format(host["ip_str"], host.get("org", "n/a"), host.get("os", "n/a")))

                    # Print all banners
                    for item in host["data"]:
                        print(colored("""
                    Port: {}
                    Banner: {}
                            """, "red").format(item["port"], item["data"]))
                return host
            except shodan.APIError as e:
                print('Shodan Error: %s' % e, ip)

def abuseIP_checker(ip_list,stampa=False,api_key=None):
    method_exit = False

    if api_key == None:
        try:
            import configparser
            configParser = configparser.RawConfigParser()
            configFilePath = r"config.txt"
            configParser.read(configFilePath)
            api_key = configParser.get('ABUSEIP', 'api_key')
            api_key = api_key.strip('\n')  # Removing any new line character from the end of line
            api_key = api_key.strip('\r')
            if api_key == None or api_key == "" or api_key == " ":
                method_exit = True
        except:
            print("Error: file config does not exist/is not readable or you don't a valid API Key for AbuseIP")
            method_exit = True

    if method_exit == False:
        # Define API endpoint
        url = "https://api.abuseipdb.com/api/v2/check"

        for ip in ip_list:
            # Define API parameters
            querystring = {
                "ipAddress": ip
                # "verbose": true
            }

            # Define headers
            headers = {
                "Accept": "application/json",
                "Key": api_key
            }

            try:
                # Make the request
                response = requests.request(method="GET", url=url, headers=headers, params=querystring)
                response = json.loads(response.text)

                data = response["data"]
                if data["abuseConfidenceScore"] > 10:
                    color_text="red"
                else:
                    color_text="green"
                # Print data from query
                if stampa==True:
                    print(colored("""
                        _   _                 ___ ___ ___  ___ 
                       /_\ | |__ _  _ ___ ___|_ _| _ \   \| _ )
                      / _ \| '_ \ || (_-</ -_)| ||  _/ |) | _ )
                     /_/ \_\_.__/\_,_/__/\___|___|_| |___/|___/
                
                    IP: {}
                    Abuse Score: {}
                    Usage Type: {}
                    ISP: {}
                    Domain: {}
                    Number of Reports: {}
                        """, color_text).format(data["ipAddress"], data["abuseConfidenceScore"], data["usageType"], data["isp"],
                                             data["domain"], data["totalReports"]))
                return data

            except requests.exceptions.HTTPError as errh:
                print("An Http Error occurred:" + repr(errh))
            except requests.exceptions.ConnectionError as errc:
                print("An Error Connecting to the API occurred:" + repr(errc))
            except requests.exceptions.Timeout as errt:
                print("A Timeout Error occurred:" + repr(errt))
            except requests.exceptions.RequestException as err:
                print("An Unknown Error occurred" + repr(err))
            except requests.exceptions.SSLError:
                print("A SSL certificate error occured" +repr(err))
            #SSLCertVerificationError





    #response.to_json()  #'{"ip_address": "147.229.2.90", "city": "Brno (Brno střed)", "region": "South Moravian", "country": "CZ", "latitude": 49.1926824, "longitude": 16.6182105}'
    #response.to_xml()   #'<?xml version="1.0" encoding="UTF-8" ?><ip_location><ip_address>147.229.2.90</ip_address><city>Brno (Brno střed)</city><region>South Moravian</region><country>CZ</country><latitude>49.1926824</latitude><longitude>16.6182105</longitude></ip_location>'

    # py output example
    # ObjectName(nir=None, asn_registry='ripencc', asn='1273', asn_cidr='195.2.0.0/19', asn_country_code='GB',
    #            asn_date='1996-07-29', asn_description='CW Vodafone Group PLC, EU', query='195.2.3.1', nets=[
    #         {'cidr': '195.2.3.0/25', 'name': 'CW-CWINTERN-NET', 'handle': 'GSOC-RIPE',
    #          'range': '195.2.3.0 - 195.2.3.127', 'description': 'Cable & Wireless', 'country': 'EU', 'state': None,
    #          'city': None, 'address': 'Vodafone Group PLC\nMelbourne Street\nLeeds\nLS2 7PS\nUnited Kingdom',
    #          'postal_code': None, 'emails': ['ncipsupport@vodafone.com', 'ipabuse@vodafone.co.uk'],
    #          'created': '2005-11-10T11:13:28Z', 'updated': '2007-03-27T14:16:36Z'},
    #         {'cidr': '195.2.0.0/19', 'name': None, 'handle': None, 'range': '195.2.0.0 - 195.2.31.255',
    #          'description': 'Cable & Wireless Austria Netblock', 'country': None, 'state': None, 'city': None,
    #          'address': None, 'postal_code': None, 'emails': None, 'created': '1970-01-01T00:00:00Z',
    #          'updated': '2001-09-22T09:31:39Z'}], raw=None, referral=None, raw_referral=None)

    # outfile.write('IP;Registrar;Email;Name;Country;City:\n')
    # for ip in ip_list:
    #     ip = ip.strip('\n')  # Removing any new line character from the end of line
    #     ip = ip.strip('\r')
    #     w = whois.whois(ip)
    #     if len(ip) <= 3:
    #         print(w, "\n")
    #     # getting the variables to write on csv
    #     registrar = w.registrar
    #     name = w.name
    #     country = w.country
    #     city = w.city
    #     email = w.emails
    #     outfile.write(
    #         str(ip) + ';' + str(registrar) + ';' + str(email) + ';' + str(name) + ';' + str(
    #             country) + ';' + str(
    #             city) + '\n')



#   https://www.apivoid.com
#   https://spyse.com