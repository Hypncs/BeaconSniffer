import argparse
from Sniffer import BeaconSniffer

# First, get the wifi interface to sniff on as input from the user

def get_wifi_interface():

    #Read in the command line arguments
    parser = argparse.ArgumentParser(description="Sniff beacon frames on a given wireless interface")

    parser.add_argument('interface', type=str, help='The wireless interface used for sniffing')
    parser.add_argument('-c', '--channel', type=int, help='The channel you want to listen on', default=1)
    parser.add_argument('-o', '--output', type=int, help='specify how many packets you want to save to a pcap for debugging', default=0)
    parser.add_argument('-s', '--sniff', type=str, help='SSID of a trusted network you want to save a signature for. It will also tell you if any duplicate signatures are detected for any trusted SSIDs', default=None)
    parser.add_argument('-p', '--prevention', type=bool, help='Enables prevention functionality which removes suspicious SSIDs from the PNL', default=False)
    
    args = parser.parse_args()
    return args

if __name__ == "__main__": #Main code

    #Put the args into variables
    
    args = get_wifi_interface()
    interface = args.interface
    channel = args.channel
    output = args.output
    sniffing = args.sniff
    prevention = args.prevention

    #Pass the arguments as parameters to the main detection module
    detector = BeaconSniffer(interface, channel, output, sniffing, prevention)
    #Start detecting rogue access points
    detector.find_beacons()
    
    

    