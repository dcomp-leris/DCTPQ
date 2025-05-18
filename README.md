# DCTPQ: Dynamic Cloud Gaming Traffic Prioritization Using Machine Learning and Multi-Queueing for QoE Enhancement

[![Conference](https://img.shields.io/badge/submitted-SBRC2025-blue)](https://sbrc.sbc.org.br/2025/pt_br/)
[![Presentation](https://img.shields.io/badge/Conference-2025/03/14-yellow)](https://sbrc.sbc.org.br/2025/en/sessoes-tecnicas-trilha-principal/)
[![Paper](https://img.shields.io/badge/Paper-2025/03/14-green)](https://github.com/dcomp-leris/DCTPQ/blob/main/SBRC_Paper_2025.pdf)
[![Presentation](https://img.shields.io/badge/Presentation-2025/05/20-red)](https://docs.google.com/presentation/d/1Uf3-jqGcS5jzvVHAQUK10RCGRnfMvfmotK1VZRjJLzE/edit?usp=sharing)


### **Note:**
This paper has been submitted to the SBRC 2025 Conference and is under review!



![image](https://github.com/user-attachments/assets/6c81c53a-d220-4ad2-96b0-6c5303e119af)

## Repository Contents
![image](https://github.com/user-attachments/assets/355715e7-7a9f-438c-97b9-32cb9232c45e)

## Requirements
- Install P4Pi [https://github.com/p4lang/p4pi)]
- Python3 [https://www.python.org/downloads/release/python-3123/]

To run the data plane (P4 code), controller, and classifier ...




## (1) Setup P4Pi 
**Note:** Ensure the P4Pi's Ethernet interface is connected to a network with DHCP enabled for internet access!

    ssh pi@192.168.4.1  # default P4Pi IP address is 192.168.4.1 and Username is `pi' 
    pass: ****          # Password    
    sudo su             # change to root user
    cd ~                # home directory
    ./setup_eth_wlan_bridge.sh

**Output:**

![image](https://github.com/user-attachments/assets/908fbf99-b0d6-4a2e-919a-de39bb7f0d20)

**Note:** It is recommended to be disconnected and connect again with the local IP assigned by DHCP (e.g., 200.18.102.14/25 using wireless or 200.18.102.32/25 using wired interface) and after
ssh connection and entering the password, change the user to root and go to the home directory as we did! (run the previous instructions except './setup_eth_wlan_bridge.sh')

**Note:** Copy the DCTPQ to the P4Pi from your computer! 
These instruction is running on your PC!

    # Run on your computer 
    git clone https://github.com/dcomp-leris/DCTPQ.git
    scp -r ./DCTPQ pi@200.18.102.14:/home/pi/    # Copy the DCTPQ folder to P4Pi 
    pass: ****                                   # Enter your computer password
    
    # Attention ==> change the IP address (200.18.102.14) to your local network address!


**Note:** To compile and run, keep it memorized that you copied files "/home/pi/DCTPQ"! if you change the addree be aware of changing the address! 

## (2) Reinstall BMv2 & P4C

To run our project, it is necessary to have the newest version of BMv2 and P4C, installing them from source.

First of all, unistall the current installed package versions:

    sudo apt remove p4lang-bmv2 # It will remove both BMv2 and P4C

To install BMv2 from source, run:

    # Clone the official repository
    git clone https://github.com/p4lang/behavioral-model.git

    # Install dependencies
    sudo apt-get install -y automake cmake libgmp-dev \
        libpcap-dev libboost-dev libboost-test-dev libboost-program-options-dev \
        libboost-system-dev libboost-filesystem-dev libboost-thread-dev \
        libevent-dev libtool flex bison pkg-config g++ libssl-dev
    
    # Install BMv2
    cd behavioral-model
    ./autogen.sh
    ./configure
    make
    sudo make install

To install P4C from source, run:

    cd .. # Leave the BMv2 dir

    # Clone the official repository
    git clone --recursive https://github.com/p4lang/p4c.git

    # Install dependencies
    sudo apt-get install cmake g++ git automake libtool libgc-dev bison flex \
        libfl-dev libboost-dev libboost-iostreams-dev \
        libboost-graph-dev llvm pkg-config python3 python3-pip \
        tcpdump

    # Install P4C
    mkdir build
    cd build
    cmake .. <optional arguments>
    make -j2
    make -j2 check
    sudo make install

Now you have the newest versions of BMv2 and P4C installed on your computer!

## (3) Enable priority queues on BMv2

You will need to edit a bash script:

    nano /usr/bin/bmv2-start

In the line 19, add "-- --priority-queues 3" in the end, like this:

    p4c-bm2-ss -I /usr/share/p4c/p4include --std p4-16 --p4runtime-files ${BM2_WDIR}/bin/${P4_PROG}.p4info.txt -o ${BM2_WDIR}/bin/${P4_PROG}.json ${BM2_WDIR}/examples/${P4_PROG}/${P4_PROG}.p4 -- --priority-queues 3

Save and close the file.

## (4) Compile & Run the P4 code!
    p4c-bm2-ss --target bmv2 --arch v1model -o /home/pi/DCTPQ/P4Pi/DCTPQ.json /home/pi/DCTPQ/P4Pi/DCTPQ.p4   # Compile the code
    # Note: Be sure the forward.json was generated in the address you set!

    # create the folder in bmv2 to run P4 
    mkdir  bmv2/examples/DCTPQ        
    cp /home/pi/DCTPQ/P4Pi/DCTPQ.p4 ./bmv2/examples/DCTPQ      # P4 file name must be "DCTPQ.p4"
    cp /home/pi/DCTPQ/P4Pi/DCTPQ.json ./bmv2/examples/DCTPQ    # json file name must be "DCTPQ.json"

    # Set the name of the project/folder P4Pi will run
    echo "DCTPQ" > /root/t4p4s-switch

    # Restart the simple switch 
    systemctl restart bmv2.service                             # Run the current P4
    systemctl status bmv2.service                              # Check the running config 

**Output:**

![image](https://github.com/user-attachments/assets/424b39e1-2576-4ee6-b646-38c17f518067)

## (5) Run the controller + Classfier 

    # Classifier
    sudo python3 /home/pi/DCTPQ/P4Pi/flow_classifier.py

**Output:**
![image](https://github.com/user-attachments/assets/45b61843-afbf-4e35-b28a-2db24482e6cc)

    

**Note:** The classifier is listenning the ports in parallel with dataplane forwarding and the match/action table is filled by the flow_classifier.py running in the controller!

## (6) Using INT
**Note:** Run on your computer!

    # First -> INT sender
    python3 send3.py

    # Second -> INT Receiver
    python3 receive_Showing.py     # To show
    python3 receive_logging.py     # To store the log


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

**DCTPQ is running as your Access Point (AP)!**

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

