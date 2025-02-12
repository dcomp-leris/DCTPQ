# DCTPQ: Dynamic Cloud Gaming Traffic Prioritization Using Machine Learning and Multi-Queueing for QoE Enhancement

This repository is organized for the paper submitted and it is under construction!


![image](https://github.com/user-attachments/assets/6c81c53a-d220-4ad2-96b0-6c5303e119af)


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

    git clone https://github.com/dcomp-leris/DCTPQ.git
    scp -r ./DCTPQ pi@200.18.102.14:/root/       # Copy the DCTPQ folder to P4Pi / Note: change the IP address (200.18.102.14) to your local network address! 
    pass: ****                                   # Enter your computer password

## (2) 

