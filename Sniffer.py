from scapy.all import *
from scapy.layers.dot11 import *
import os
import hashlib
import json
import time

class BeaconSniffer:
    
    def __init__(self, interface, channel, output, sniffing, prevention): #Sets up functionality sniffing beacons

        self.interface = interface # The wireless interface to use

        self.channel = channel # Specified channel

        self.output = output # How many packets should be saved to a PCAP

        self.load_known_signatures() # Loads the stored legitimate signatures 

        self.sample_packets = [] # Buffer of packets to be saved to a PCAP

        self.debug_complete = False # Variable used to check if required number of packets for a PCAP has been 

        self.sniffing = sniffing # Whether not the code is saving new signatures 

        self.prevention = prevention # Prevention mode - whether or not detected SSIDs should be removed from the PNL

        self.detected = {} # Used to keep track of detected SSIDs so that the terminal is not flooded with the same alert

        self.start_time = time.time() # Measures the start of program execution - used to see how long detection takes

    def find_beacons(self):

        # Put WIFI interface into monitor mode
        os.system('ifconfig {0} promisc && ifconfig {0} down && iwconfig {0} mode monitor && ifconfig {0} up && iwconfig {0} channel {1}'
                .format(self.interface, self.channel))
        # create an INET, raw socket that filters specifically for beacons
        capture_filter = "link[0] == 0x80"
        
        if self.output != 0: #Debug mode, saves captured packets to a PCAP
            packets = sniff(iface=self.interface, prn=self.debug_packets, filter=capture_filter, stop_filter=self.check_stop)
            wrpcap(f'debug/packets_channel_{str(self.channel)}', self.sample_packets)
            print(f"[DEBUG] Saved {str(self.output)} packets for channel {self.channel}")
        
        else: # Default mode - only looking for signature mismatches
            packets = sniff(iface=self.interface, prn=self.read_packets, filter=capture_filter)
            

    def read_packets(self, beacon: packet):
        ###ABOUT:
        # This Function is where beacon frames are sent for processing. It will first check if the SSID is trusted (in the PNL)
        # And then extracts the relevant values for comparison 


        ssid = beacon[Dot11Elt].info.decode()
        if ((ssid in self.trusted) or self.sniffing):

            ### REQUIRED VALUES TO EXTRACT: SSID, BSSID, Country, BasicBitRates, ExtendedBitRates, VendorInfo, 
            # RMCapabilities, HTCapabilities, NumElements

        

            bssid = beacon[Dot11].addr2
            extended_capabilities = 0
            basic_rates = 0
            extended_rates = 0
            vendor_oui = ''
            rm_capabilities = 0
            ht_capabilities = 0
            count = 0

            elts = beacon[Dot11Elt]

            

            while isinstance(elts, Dot11Elt):
                
                if elts.ID ==127:
                    try:
                        extended_capabilities = elts.info.hex()
                    except:
                        pass
                elif elts.ID ==221:
                     vendor_oui += elts.info[:3].hex()
                
                elif elts.ID == 1:
                    basic_rates = elts.info.hex()
                     
                elif elts.ID == 50:
                    extended_rates = elts.info.hex()
                elif elts.ID == 45:
                    ht_capabilities = elts.info.hex()
                elif elts.ID == 70:
                    rm_capabilities = elts.info.hex()
                    
                elts = elts.payload
                count += 1


            ###OUTPUT MESSAGE FOR DEMONSTRATION PURPOSES. UNCOMMENT IF REQUIRED###

            # isvalidSSID = (ssid.strip() != '') and (b'\x00' not in ssid.encode())
            # if ssid not in self.detected.keys() and isvalidSSID:
            #     print(f'''
            # SSID: {ssid}
            # BSSID: {bssid}
            # Extended Capabilities: {extended_capabilities}
            # Basic Rates: {basic_rates}
            # Extended Rates: {extended_rates}
            # Vendor oui: {vendor_oui} 
            # HT Capabilities: {ht_capabilities}
            # RM Capabilities: {rm_capabilities}
            # Number of Elements: {count}
            # ''')

            basic_identification = f"{ssid}:{bssid}"
            complex_identification = f"{extended_capabilities}:{basic_rates}:{extended_rates}:{vendor_oui}:{ht_capabilities}:{rm_capabilities}:{count}"
            # if isvalidSSID:
            #     print(basic_identification, complex_identification) # UNCOMMENT FOR DEMONSTRATION PURPOSES
           
            

            #Note, we are using complex_identification here as we want to be able to identify an access point 
            #Independently from the SSID and BSSID.

            signature = self.compute_hash(complex_identification) # Generates the hash (signature) for an SSID
            

            if self.sniffing is not None:
                self.capture_signature(signature, ssid, bssid) # If in sniffing mode, save the specified SSID's signature to the database
            else:
                self.check_signature(signature, ssid, bssid) # If in default mode, check signature matches 

    def check_signature(self, signature, ssid, bssid):
        trustedSignatures = self.trusted[ssid].values() # Get the known signatures for an SSID
        
        if ssid not in self.detected.keys(): # Check if SSID has been seen during current execution. This ensures alert is only sent once
            self.detected[ssid] = [] # Log that the SSID has been seen
            print(f'[0]Seen {ssid} with signature {signature}') # Alert the user that a known SSID has been seen in the area

        

        if (signature in trustedSignatures): # If signature matches the known signatures, do nothing.
            pass
        
        
        else: # Otherwise, alert the user that signature is different and may be a KARMA attack
            print(f'''[!]Potential Karma Attack AP Detected for {ssid}. 
                  Unknown Signature Detected: {signature}
                  MAC: {bssid}
                  ''')
            
            #Display how long it took to detect
            end_time = time.time()
            duration = end_time - self.start_time
            print(f"detected in {duration} seconds")
            
            #Remove SSID from PNL if this mode is active
            if self.prevention:
                if ssid in self.get_profile_names():
                    self.remove_ssid(ssid)
                else:
                    print(f"[!]{ssid} not found in PNL. No risk of automatic connection.")
 
    def compute_hash(self, input):

        #Hashes an access point's signature
        hash_object = hashlib.sha256(input.encode())
        return hash_object.hexdigest()
    
    def load_known_signatures(self):

        self.trusted = {} # Used to store database of known SSIDs and their signatures

        # Load the dictionary from the JSON file
        with open('signatures.json', 'r') as json_file:
            self.trusted = json.load(json_file)

    def debug_packets(self, beacon: packet):

        ##This function is where packets are sent for processing when debug mode is active

        if beacon[Dot11Elt].info.decode() in self.trusted: # Checks if SSID is known as normal
            self.sample_packets.append(beacon) # Adds packet to buffer of packets to be saved
            self.read_packets(beacon) # Continues with default packet processing
            print(f'[+] Logged {beacon[Dot11Elt].info.decode()} with bssid: {beacon[Dot11].addr2}') # Tells user the packet has been logged
        else:
            pass # Do nothing if not a known SSID

        self.check_stop(beacon) # Check if number of packets to capture has been reached

    def check_stop(self, beacon: packet):
        return len(self.sample_packets) == self.output # Checks if number of logged packets is the same as number requested by the user
      
    def capture_signature(self, signature, ssid, bssid):

        #Check if it is a new signature and is not a hidden network which does not broadcast an SSID
        #A hidden network will send beacon frames, but the SSID field will be blank or a string of \x00 bytes
        isvalidSSID = (ssid.strip() != '') and (b'\x00' not in ssid.encode())
        specifiedSSID = self.sniffing
        if isvalidSSID:

            #Alert the user that an SSID has been detected
            if ssid not in self.detected.keys():
                self.detected[ssid] = []
                print(f'[0] Seen {ssid} with bssid {bssid} and signature {signature}')

            if ssid == specifiedSSID:
                #If this is a new SSID, add to the runtime database
                if (ssid not in self.trusted):
                    self.trusted[ssid] = {}

                #If the signature has not been seen before, add it to runtime database and save to file
                if (signature not in self.trusted[ssid].values()):

                    self.trusted[ssid][bssid] = signature

                    ## Save specified SSID to json database ##
                
                    with open("signatures.json", 'w') as file:
                        json.dump(self.trusted, file, indent=4)
                        print(f"[+]Captured signature for {ssid}: {signature}")
            
            # Check for signature collisions
            for trusted_ssid in self.trusted:
                if signature in self.trusted[trusted_ssid].values() and ssid != trusted_ssid:
                    if trusted_ssid not in self.detected[ssid]:
                        self.detected[ssid].append(trusted_ssid)
                        print(f'[!]Signature collision between {ssid} and {trusted_ssid} Likely the same hardware.')

    def get_profile_names(self):

        # Gets the PNL of the device

        profiles = []
        try:
            output = subprocess.check_output("nmcli -t -f name connection show", shell=True, text=True)
            profiles = output.strip().split('\n')
        except subprocess.CalledProcessError as e:
            print(f"Failed to get NM connections: {e}", file=sys.stderr)
        return profiles

    def remove_ssid(self, ssid):

        #Removes an SSID from the PNL

        try:
            subprocess.check_call(f"nmcli connection delete id \"{ssid}\"", shell=True)
            print(f"Connection {ssid} has been removed.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to remove connection {ssid}: {e}", file=sys.stderr)              


