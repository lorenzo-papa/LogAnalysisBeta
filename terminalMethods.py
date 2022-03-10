import subprocess
import time


def search_in_logs():
    # The command you want to execute
    folders = list(open('Paths/folders.txt'))
    for i in range(len(folders)):
        folders[i] = folders[i].strip('\n')

    logs = list(open('Paths/logs_to_search.txt'))
    for i in range(len(logs)):
        logs[i] = logs[i].strip('\n')

    find_elements = list(open('Paths/what_to_search.txt'))
    for i in range(len(logs)):
        find_elements[i] = find_elements[i].strip('\n')

    print("searching into folder: "+str(folders),"searching into file: "+ str(logs),"looking for: "+str(find_elements)+'\n')

    results=[]
    for folder in folders:
        for log in logs:
            for element_to_find in find_elements:
                output_cat = cat(folder=folder,element=log)
                results.append(grep(input=output_cat,search_for=element_to_find))

    for found in results:
        print(found)

    return results


def cat(folder,element):
    cmd='cat'
    element_cont = subprocess.Popen([cmd, element], cwd=folder, stdout=subprocess.PIPE)

    return element_cont.stdout

def grep(input,search_for):
    cmd='grep'
    element_cont = subprocess.check_output((cmd, search_for), stdin=input)
    #element_cont=parser(element_cont)
    return element_cont

def parser(text_to_pars):
    #text_to_pars=text_to_pars.decode('utf-8')#from byte to str
    text_to_pars=text_to_pars.split("\n")
    return text_to_pars

def start_record_performance():
    start=time.process_time()
    t = time.localtime()
    current_time = time.strftime("%H:%M:%S", t)
    print("start time:",current_time)
    return start
def get_final_perfomance(start):
    end=time.process_time()
    total_time=end-start
    print('\nTotal time needed for the analysis: ',str(total_time) +"s")
    return total_time

# def ping(servers):
#     # The command you want to execute
#     cmd = 'ping'
#
#     # send one packet of data to the host
#     # this is specified by '-c 1' in the argument list
#     outputlist = []
#     # Iterate over all the servers in the list and ping each server
#     for server in servers:
#         temp = subprocess.Popen([cmd, '-c 1', server], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         # get the output as a string
#         output = str(temp.communicate())
#         # store the output in the list
#         outputlist.append(output)
#
#     return outputlist



#ps = subprocess.Popen(['cat', 'system.log'], cwd='/var/log', stdout=subprocess.PIPE)
#output = subprocess.check_output(('grep', 'sshd'), stdin=ps.stdout)