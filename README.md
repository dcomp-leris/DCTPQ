# DCTPQ: Dynamic Cloud Gaming Traffic Prioritization Using Machine Learning and Multi-Queueing for QoE Enhancement

This repository is organized for the paper submitted and it is under construction!


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

## (2) Compile & Run the P4 code!
    p4c-bm2-ss --target bmv2 --arch v1model -o /home/pi/DCTPQ/P4Pi/DCTPQ.json /home/pi/DCTPQ/P4Pi/DCTPQ.p4   # Compile the code
    # Note: Be sure the forward.json was generated in the address you set!

    # create the folder in bmv2 to run P4 
    mkdir  bmv2/examples/DCTPQ        
    cp /home/pi/DCTPQ/P4Pi/DCTPQ.p4 ./bmv2/examples/DCTPQ      # P4 file name must be "DCTPQ.p4"
    cp /home/pi/DCTPQ/P4Pi/DCTPQ.json ./bmv2/examples/DCTPQ    # json file name must be "DCTPQ.json"

    # Restart the simple switch 
    systemctl restart bmv2.service                             # Run the current P4
    systemctl status bmv2.service                              # Check the running config 

**Output:**

![image](https://github.com/user-attachments/assets/424b39e1-2576-4ee6-b646-38c17f518067)

## (3) Run the controller + Classfier 

    # Classifier
    sudo python3 /home/pi/DCTPQ/P4Pi/flow_classifier.py

**Output:**
![image](https://github.com/user-attachments/assets/45b61843-afbf-4e35-b28a-2db24482e6cc)

    

**Note:** The classifier is listenning the ports in parallel with dataplane forwarding and the match/action table is filled by the flow_classifier.py running in the controller!

## (4) Using INT
**Note:** Run on your computer!

    # First -> INT sender
    python3 send3.py

    # Second -> INT Receiver
    python3 receive_Showing.py     # To show
    python3 receive_logging.py     # To store the log



**DCTPQ is running and serving as your Access Point (AP)!**

