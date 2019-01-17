#!/usr/bin/env python
# encoding: utf-8

import sys
import re
import logging
import csv
#import ctypes
import time

from sense_hat import SenseHat

programname = "mySyringe"
HUMIDITY_PUSH_THRESHOLD=38.0


##load eFSA model
def load_model_file (programname):
    #load the model which has been built in the training phrase
    EFSAfile = "./model/%s_statetrans_event_frequency.pfsm" % (programname)
    EFSA_fp=open(EFSAfile, "r")
    EFSA_data = csv.reader(EFSA_fp, delimiter=' ')
    EFSA_table = [row for row in EFSA_data]
    EFSA_fp.close()
    return EFSA_table

EFSA_table = load_model_file(programname)
print ("Start eFSA anomaly detector")


def statetranschecking(lastpc, pc, syscall):
    for index in range(len(EFSA_table)):#if cmp(row[0:3], model_table[index][0:3]) ==0:
        if lastpc == EFSA_table[index][0] and pc == EFSA_table[index][1] and syscall == EFSA_table[index][2]:
            #print model_table[index][0:3]
            #print ('ture for statetrans {}->{} syscall:{}'.format(lastpc, pc, lastsyscall))
            return True, EFSA_table[index]
    return False, EFSA_table[0]

def event_push():
    sense = SenseHat()
    sense.clear()
    humidity = sense.get_humidity()
    print('current humidity: {}'.format(humidity))
    if humidity>HUMIDITY_PUSH_THRESHOLD :
        return True
    else:
        return False
#sys.exit()

def event_checking(event,flag):
    print ('doing event checking for {} {}'.format(event,flag))
    if int(flag)==0:
        #alarm
        if event_push()==True:
            print ('[ALERT] Event_push is not executed, but it should happen')
            #ctypes.windll.user32.MessageBoxW(0, "Event_push anomaly", "Alert", 1)
        else:
            print('pass event checking')
    elif int(flag)==1:
        #alarm
        if event_push()==False:
            print ('[ALERT] Event_push is triggered, but it should NOT happen')
        else:
            print('pass event checking')



pcdict = {}
start_flag=False
lastsyscall=""
hop2lastsyscall=""
pc=""
lastpc=""
hop2lastpc=""
directpc=""
lastdirectpc=""
lasttimespent=""
lastcalltime=""
hop2lasttimespent=""
hop2lastcalltime=""
sum_line=0
compactFSA_StateTrans=[]   #need disable ASLR, echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
FSA_StateTrans=[]
max_pc_number=0

for eachline in sys.stdin:
    #print (eachline)
    if "SIGINT" in eachline and not (":" in eachline and "." in eachline and "[" in eachline and "(" in eachline and "<" in eachline):
        continue

    if "exit_group" in eachline:
        break

    if ":" in eachline and "." in eachline and "[" in eachline and "(" in eachline and "<" in eachline:   #the basic pattern must be matched
        #pattern 1 11:53:02.905477 [00007f30908081e7] execve("../source/gzip.exe.static", ["../source/gzip.exe.static", "-h"], [/* 68 vars */]) = 0 <0.000241>
#store previous info
        if start_flag==True:
            #update the pcdict
            if lastpc not in pcdict:
                pcdict[lastpc] = str(max_pc_number)
                max_pc_number +=1

            #get direct PC
            temp_line=eachline
            str_split=re.split('[\[\]]', temp_line)
            directpc=str_split[1]

            #dump into log
            if sum_line>=2: #for Call Stack FSA
                #note that, Call Stack FSA has one less trans than the compact FSA, since we can only print the trans one hop after the printed state-trans.
                #So, we delete the last item of compactFSA_StateTrans to make two models both omit the last trans.
                FSA_StateTrans.append( [hop2lastpc, lastpc, hop2lastsyscall, int(pcdict[hop2lastpc]), int(pcdict[lastpc]), hop2lastcalltime, hop2lasttimespent] )
                #print ('Call Stack FSA statetrans {}->{} syscall:{}'.format(hop2lastpc, lastpc, hop2lastsyscall))
                #testing the state trans integrity
                result, statetrans = statetranschecking(hop2lastpc, lastpc, hop2lastsyscall)
                if result == False:
                    #anomaly_flag=True
                    print("statetrans anomaly happens")
                    #now check the event
                else:
                    if len(statetrans)>4 and "event" in statetrans[4]:
                        print("will do event checking")
                        t_start_eventcheck = time.process_time()
                        event_checking(statetrans[4],statetrans[5])
                        elapsed_time = time.process_time() - t_start_eventcheck
                        print("event checking delay: {}".format(elapsed_time))

                #here record the delay of event checking

#if check_rt_event(statetrans[4]) == False:
#update_statetrans_prob(index)
#                                print("event anomaly happens, set event dependent state-trans probability to a very low value", trace_table[index])reak
#                    print('fire an alarm')


            #dump end
            sum_line+=1

        #store previous info end
        hop2lastpc = lastpc
        hop2lastsyscall = lastsyscall
        hop2lasttimespent = lasttimespent
        hop2lastcalltime = lastcalltime
        #get call time
        temp_line=eachline
        str_split=temp_line.split(' ')
        lastcalltime=str_split[0]
        #get time spent in system call
        temp_line=eachline
        str_split=re.split('[<>]', temp_line)
        lasttimespent=str_split[1]
        #get syscall
        temp_line=eachline
        str_split=re.split(r'[ (]', temp_line)
        lastsyscall = str_split[2]

        #print ('FSA lastpc:{}, hop2lastpc:{}, lastsyscall:{}, hop2lastsyscall:{}, current systemcall:{}'.format(lastpc, hop2lastpc, lastsyscall, hop2lastsyscall, str_split[2]))
        #get direct PC
        temp_line=eachline
        str_split=re.split('[\[\]]', temp_line)
        lastdirectpc=str_split[1]#if sum_line>5:

        #return FSA_StateTrans, compactFSA_StateTrans

    if "> /" in eachline and "[0x" in eachline :
        #if exename in eachline and start_flag==False:
        if start_flag==False:  #this only applied for CPS program, we neglect the frist multiple entries since they are generated for loading program before the main function
            start_flag=True
            logging.debug('Start preprocess_trace, Set start_flag=True')

        #pattern 2
        #get source_pc from last call stack
        temp_line=eachline
        str_split=re.split('[\[\]]', temp_line)
        lastpc=str_split[1]




















































































































































































































































































































































































































