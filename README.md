Scanning-tool
=============

Colman Assignment - basic scanning tool implemented in python 2.7
Created by Tal Peretz And Shiran Michali
Lecture : Nir Valtman
License : MIT

Host on GitHub : https://github.com/talp101/Scanning-tool

Requirements:
Os - Unix like - tested on Ubuntu (Inside VM)
Python - 2.7.6 +
Installed Packeges - Scapy 2.2.0, argparse, urllib2, logging

How To Make It Running:

1 ) Extract The 'Scannig-tool' Folder
2 ) cd to 'Scanning-tool'
3 ) Run the next commnad : sudo python menu.py -h
4 ) Now you should see the help section enjoy

Ex:

1 ) tal@ubuntu:~/PycharmProjects/Scanning-tool/Menu$ sudo python menu.py -h - Will Enter to help
2 ) tal@ubuntu:~/PycharmProjects/Scanning-tool/Menu$ sudo python menu.py -ip 82.166.60.130 -p TCP -type t -t 2 -b 1
        - This will run Banner Grabber, and tcp connection scan on colman.ac.il

Enjoy!!!

