# OSIGATER
FYP Project - Unified osint tool for red team operations and penetraton testing: Enhancing Integration and Functionality Across OSINT Tools

Note that this OSINT Tool was only designed to be run in linux, especially Kali Linux. Make sure you have your Kali Linux OS to run this OSINT Tool.

In order to setup this OSINT Tool, just git clone this repository into your directory. (Recommended to clone the code again as the code submitted in moodle is not as complete as the current one here since it still had bug errors but not enough time to fix it.)

Make sure the shodan_module.py is there as well as it is used to perform the shodan feature function.

Once done cloning, there is 1 thing you need to do in order to run the OSINT Tool smoothly.

1. Make sure you are in sudo mode so that the OSINT Tool can run nmap scans with sudo privileges.

After entering into sudo/bash mode, simply go to the folder you cloned and enter the command:

python3 OSIGATER.py

The above command will run the python file which runs the OSIGATER OSINT Tool. (It's either python or python2 or python3, depends on the python version installed on your linux).
Screenshot Below:
![image](https://github.com/user-attachments/assets/2b486773-9e9d-4794-b69f-5ac928004f93)
