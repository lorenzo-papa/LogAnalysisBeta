import re, sys, time
import os.path
from os import path
from datetime import datetime
from dateutil import parser
from pathlib import Path
from utility import *

def grep(file, pattern, match_case):
    file = file.strip()
    pattern=pattern.strip()
    filename=file
    if check_if_file_exist(file):
        match_list = []
        count=0
        print("Searching into: ", file, " for ", pattern)
        try:
            with open(file, "r") as file:
                for line in file:
                    if match_case == False:
                        if re.search(pattern, line):
                            count+=1
                            print("From "+ str(filename) + ": " + line)
                            match_list.append(line)
                    else:
                        if re.search(pattern.lower(), line.lower()):
                            count+=1
                            print("From "+ str(filename) + ": " + line)
                            match_list.append(line)
            print("\nTotal match found: ", str(count))
            file.close()
        except UnicodeDecodeError:
            print("File not readable, please enter a valid input")

        if len(match_list)>0:
            export_file_path = r"Parser_Output/"
            time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
            name = "Grep Output " + time_now + ".csv"
            export_file = export_file_path + name
            with open(export_file, "w+") as file_out:
                file_out.write("EXPORTED DATA FROM GREP;"+ "File:"+ filename + ";Pattern:" + pattern + ";Data:" + time_now +":\n")
                file_out.write("Total match found: "+ str(count)+"\n")
                for item in range(0, len(match_list)):
                    #print match_list_clean[item]
                    file_out.write(match_list[item] + "\n")

                #match_list_clean = list(set(match_list))
                #for item in range(0, len(match_list_clean)):
                    #print match_list_clean[item]
                    #file_out.write(match_list_clean[item] + "\n")
            file_out.close()
    else:
        print("This file does not exist, please enter a valid input")
        return 0


def grep_exact_match(file, pattern):
    file = file.strip()
    pattern = pattern.strip()
    filename=file
    pattern_specific=r"\b" +pattern + r"\b"
    print("Searching into: ", file, " for ",pattern_specific)
    if check_if_file_exist(file):
        match_list = []
        count=0
        try:
            with open(file, "r") as file:
                for line in file:
                    if re.search(pattern_specific, line):
                        count+=1
                        print("From "+ str(filename) + ": " + line)
                        match_list.append(line)
            print("\nTotal match found: ", str(count))
            file.close()
        except UnicodeDecodeError:
            print("File not readable, please enter a valid input")

        if len(match_list)>0:
            export_file_path = r"Parser_Output/"
            time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
            name = "Grep Exact Match Output " + time_now + ".csv"
            export_file = export_file_path + name
            with open(export_file, "w+") as file_out:
                file_out.write("EXPORTED DATA FROM GREP EXACT MATCH;"+ " File:"+ filename + ";Pattern:" + pattern + ";Data:" + time_now +":\n")
                file_out.write("Total match found: " + str(count) + "\n")
                for item in range(0, len(match_list)):
                    #print match_list_clean[item]
                    file_out.write(match_list[item] + "\n")
                # match_list_clean = list(set(match_list))
                # for item in range(0, len(match_list_clean)):
                #     #print match_list_clean[item]
                #     file_out.write(match_list_clean[item] + "\n")
            file_out.close()
    else:
        print("This file does not exist, please enter a valid input")
        return 0

def rgrep(directory, pattern, match_case):
    pattern = pattern.strip()
    directory = clean_dir_path(directory)

    if check_if_folder_exist(directory):

        dir_list = os.listdir(directory)
        print("Looking into files in '", directory, "' :")
        # prints all files
        print(dir_list)
        print("For directories please recall the commang rgrep with the specif location")

        match_list = []
        count=0

        for file in dir_list:
            try:
                file_count=0
                total_path=directory+file
                if check_if_file_exist(total_path):
                    print("Searching into: ",total_path)
                    with open(total_path, "r") as file:
                        for line in file:
                            if match_case == False:
                                if re.search(pattern, line):
                                    count+=1
                                    file_count+=1
                                    print("From "+ str(total_path) + ":;" + str(line))
                                    found="From "+ str(total_path) + ":;" + str(line)
                                    match_list.append(found)
                            else:
                                if re.search(pattern.lower(), line.lower()):
                                    count+=1
                                    file_count+=1
                                    print("From "+ str(total_path) + ":;" + str(line))
                                    found="From "+ str(total_path) + ":;" + str(line)
                                    match_list.append(found)
                    print("Total match found: ", str(file_count), " in ", total_path, "\n")
                    file.close()
            except UnicodeDecodeError:
                print("File not readable, please enter a valid input")
        print("\nTotal match found: ", str(count), " in ", directory)


        if len(match_list) > 0:
            export_file_path = r"Parser_Output/"
            time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
            name = "Rgrep Output " + time_now + ".csv"
            export_file = export_file_path + name

            with open(export_file, "w+") as file_out:
                file_out.write(
                    "EXPORTED DATA FROM GREP;" + "Directory:" + str(directory) + ";Pattern:" + pattern + ";Data:" + time_now + ":\n")
                file_out.write("Total match found: " + str(count) + "\n")
                for item in range(0, len(match_list)):
                    #print match_list_clean[item]
                    file_out.write(match_list[item] + "\n")
                # match_list_clean = list(set(match_list))
                # for item in range(0, len(match_list_clean)):
                #     #print match_list_clean[item]
                #     file_out.write(match_list_clean[item] + "\n")
            file_out.close()
    else:
        print("This directory does not exist, please enter a valid input")
        return 0

def rgrep_exact_match(directory, pattern):
    pattern = pattern.strip()
    directory = clean_dir_path(directory)
    if check_if_folder_exist(directory):

        dir_list = os.listdir(directory)
        pattern_specific = r"\b" + pattern + r"\b"
        print("Looking into files in '", directory, "' :")
        # prints all files
        print(dir_list)
        print("For directories please recall the commang rgrep with the specif location")

        match_list = []
        count=0

        for file in dir_list:
            try:
                file_count=0
                total_path=directory+file
                if check_if_file_exist(total_path):
                    print("Searching into: ",total_path)
                    with open(total_path, "r") as file:
                        for line in file:
                            if re.search(pattern_specific, line):
                                count+=1
                                file_count+=1
                                print("From "+ str(total_path) + ":;" + str(line))
                                found="From "+ str(total_path) + ":;" + str(line)
                                match_list.append(found)
                    print("Total match found: ", str(file_count)," in ", total_path, "\n")
                    file.close()
            except UnicodeDecodeError:
                print("File not readable, please enter a valid input")
        print("\nTotal match found: ", str(count), " in ", directory)


        if len(match_list) > 0:
            export_file_path = r"Parser_Output/"
            time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
            name = "Rgrep Output Exact Match" + time_now + ".csv"
            export_file = export_file_path + name

            with open(export_file, "w+") as file_out:
                file_out.write(
                    "EXPORTED DATA FROM GREP EXACT MATCH;" + " Directory:" + str(directory) + ";Pattern:" + pattern + ";Data:" + time_now + ":\n")
                file_out.write("Total match found: " + str(count) + "\n")
                for item in range(0, len(match_list)):
                    #print match_list_clean[item]
                    file_out.write(match_list[item] + "\n")
                # match_list_clean = list(set(match_list))
                # for item in range(0, len(match_list_clean)):
                #     #print match_list_clean[item]
                #     file_out.write(match_list_clean[item] + "\n")
            file_out.close()
    else:
        print("This directory does not exist, please enter a valid input")
        return 0


def time_search(filename, initial_time, final_time):
    filename = filename.strip()
    initial_time = initial_time.strip()
    final_time = final_time.strip()
    #datetime_object = datetime.strptime('Jun 1 2005  1:33PM', '%b %d %Y %I:%M%p')
    stop=False
    if check_if_file_exist(filename):
        if initial_time=="min":
            initial_time = datetime.min
        else:
            initial_time = parser.parse(initial_time)
        final_time = parser.parse(final_time)
        match_list = []
        count=0
        print("Searching into: ", filename)
        #line_count=0
        try:
            with open(filename, "r") as file:
                for line in file:
                    if stop==False:
                        tot_time = check_date_log(line)

                        try:
                            if initial_time <= tot_time <= final_time:
                                count += 1
                                #line_count+=1
                                print(line)
                                match_list.append(line)
                            else:
                                if count !=0:
                                    stop=True
                        except:
                            if count != 0 and stop==False:
                                #line_count += 1
                                match_list.append(line)
                                print(line)
                    else:
                        break
            print("\nTotal match found: ", str(count), " beetwen: ", str(initial_time), " and ", str(final_time))
            #print(line_count)
            file.close()
        except UnicodeDecodeError:
            print("File not readable")
        if count > 0:
            export_file_path = r"Parser_Output/"
            time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
            name = "TimeSearch Output " + time_now + ".csv"
            export_file = export_file_path + name

            with open(export_file, "w+") as file_out:
                file_out.write(
                    "EXPORTED DATA FROM TimeSearch;" + " File: " + filename + ";Start: " + str(initial_time) + ";End: "+str(final_time)+ ";Take at: " +time_now + "\n")
                file_out.write("Total match found: "+ str(count)+"\n")
                for item in range(0, len(match_list)):
                    #print match_list_clean[item]
                    file_out.write(match_list[item] + "\n")
                # match_list_clean = list(set(match_list))
                # for item in range(0, len(match_list_clean)):
                #     #print match_list_clean[item]
                #     file_out.write(match_list_clean[item] + "\n")
            file_out.close()
    else:
        print("This file does not exist, please enter a valid input")
        return 0


def rtime_search(directory, initial_time, final_time):
    #datetime_object = datetime.strptime('Jun 1 2005  1:33PM', '%b %d %Y %I:%M%p')
    initial_time = initial_time.strip()
    final_time = final_time.strip()
    directory=clean_dir_path(directory)
    if check_if_folder_exist(directory):

        dir_list = os.listdir(directory)
        print("Looking into files in '", directory, "' :")
        # prints all files
        print(dir_list)
        print("For directories please recall the commang rgrep with the specif location")

        if initial_time == "min":
            initial_time = datetime.min
        else:
            initial_time = parser.parse(initial_time)
        final_time = parser.parse(final_time)
        match_list = []
        count=0


        for filename in dir_list:
            try:
                new_file=False
                total_path=directory+filename
                if check_if_file_exist(total_path):
                    print("Searching into: ",total_path)
                    with open(total_path, "r") as file:
                        stop = False
                        file_count=0
                        for line in file:
                            if stop == False:
                                tot_time=check_date_log(line)
                                try:
                                    if initial_time <= tot_time <= final_time:
                                        new_file = True
                                        file_count+=1
                                        count += 1
                                        print(line)
                                        found = "From " + str(total_path) + ":;" + str(line)
                                        match_list.append(found)
                                    else:
                                        if file_count !=0:
                                            stop = True
                                except:
                                    if file_count!=0 and new_file==True and stop==False:
                                        found = "From " + str(total_path) + ": " + str(line)
                                        match_list.append(found)
                                        print(line)
                            else:
                                break
                    print("Total match found: ", str(file_count), " beetwen: ", str(initial_time), " and ", str(final_time), " in ",total_path, "\n")
                    file.close()
            except UnicodeDecodeError:
                print("File not readable, please enter a valid input")
        print("\nTotal match found: ", str(count), " beetwen: ", str(initial_time), " and ", str(final_time), " in ", directory)

        if count > 0:
            export_file_path = r"Parser_Output/"
            time_now = str(time.strftime("%Y-%m-%d %H-%M-%S", time.localtime()))
            name = "RTimeSearch Output " + time_now + ".csv"
            export_file = export_file_path + name

            with open(export_file, "w+") as file_out:
                file_out.write(
                    "EXPORTED DATA FROM RTimeSearch;" + "File: " + filename + ";Start: " + str(initial_time) + ";End: "+str(final_time)+ ";Take at: " +time_now + "\n")
                file_out.write("Total match found: "+ str(count)+"\n")
                for item in range(0, len(match_list)):
                    #print match_list_clean[item]
                    file_out.write(match_list[item] + "\n")
                # match_list_clean = list(set(match_list))
                # for item in range(0, len(match_list_clean)):
                #     #print match_list_clean[item]
                #     file_out.write(match_list_clean[item] + "\n")
            file_out.close()
    else:
        print("This directory does not exist, please enter a valid input")
        return 0

