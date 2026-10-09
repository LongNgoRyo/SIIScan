import os
import subprocess

# Backdoor nhan lenh tu command line
cmd = input("Nhap lenh: ")
os.system(cmd)
subprocess.Popen(cmd, shell=True)
