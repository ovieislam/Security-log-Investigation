# Security Log Investigation

## Project Overview

The purpose of this project is to investigate security logs and to identify suspicious activity and potential security threats. The program checks firewall and authentications logs to examine the network traffic,failed login attempts,successful logins and account lockouts.it also identifies the most frequently blocked ip address and targeted network ports.The results help in highlighting unsual activity  and can assess the overall security risk.

## Project Files

main.py  = it has the python code and it is used for to check the security logs and create a report.
firewall.log  = this one contains network traffic  information , including  allowed  and blocked connections
authentication.log = in this file contains user authentication events for example successful  logins and failed logins , account lockouts.
suspicious_ips.txt = it has a list of ip address provided with  dataset for investigation.
README.txt  = in this file it has the instructions  that are supplied with the dataset

## Requirments

- Python 3
- no external libaries are needed
- this program uses  python bulit in  ipaddress and datetime modules.

## How to run the program 

1. make sure you have python 3 installed
2.Open the project folder
3.open the terminal in the project folder
4.Run the following command
     python main.py

5. The Program  can analyses the firewall and authentication logs
6. the result are displayed in the terminal and saved to investigation_report.txt.

## Program Features
Analyses allowed  and blocked  firewall events.
Counts successful and failed login attempts.
Identifies account lockout and logout events.
Identifies the most frequently targeted usernames.
Identifies the most frequently targeted  destination ports.
Finds the IP address generating the most blocked events.
Validates IP address
Calculates an overall security risk level.
Generates an investigation report.

## Risk Assessment

The program calculates a security risk level based on a failed login  attempts  and account lockouts.

High: if it 50 or more failed login attempts or 5  or more account lockouts
Medium: 20 or more failed attempt
Low: less than 20  failed login attempts , with less than 5 fewer account lockout.

## Output

The program display  the analysis results in the terminal  and creates a file called investigation.txt. this report  contains  firewall  statistics, authentication results, calculated security risk level and important security observations.

## Error handling

The program handles malformed and unrecognised  log entries and during  analysis. it counts malformed  lines instead of  allowing it to interrupt  the investigation. it also validates ip address to identify invalid entries.

