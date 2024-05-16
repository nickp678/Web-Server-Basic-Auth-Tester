#!/usr/bin/env python3

#Created by: Nicholas Park
import asyncio
import aiohttp
import ipaddress
import resource
import os
import socket
import csv
import argparse
import ssl

class WebServerScannerCLI:
    """
    A class dedicated to testing basic authentication on various web servers.

    Attributes:
    self.hosts : list 
        store hosts we want to test
    self.ports : list
        store ports we want to test
    self.csv_storage : nested list
        store all scanning results that will be converted to csv report (Check "create_output_files" function for usage)
    self.true_positives : dict
        store true positive results
    self.true_negatives : dict 
        store true negative results
    self.potential_positives : dict 
        store potential positive results
    self.server_error : dict 
        store results due to server error
    self.deep_dive : boolean 
        used to check whether to perform either simple (fast) scan or in-depth (longer) scan

    Methods:
    __init__(): 
        initialize class attributes
    start():
        main menu for overall scanning config and scanning
    settings_menu():
        menu dedicated to modify host or port values
    add_ports():
        add ports to self.ports list
    remove_ports():
        remove ports from self.ports list
    load_from_file():
        load hosts via text file
    manual_input():
        load hosts via manual user input
    load_from_subnet():
        load hosts via subnet range
    handle_request():
        function responsible for sending request and handling response for each port within each host
    scan_host():
        function responsible for handling each host
    create_output_files():
        creates output text files and a csv file based on scanned information
    scan_hosts():
        function responsible for halnding multiple hosts and managing overall scanning and results including calling the "create_output_files()" function.
    """

    def __init__(self, args):
        self.hosts = args.hosts
        self.ports = args.ports
        self.csv_storage = []
        self.true_positives = {}
        self.true_negatives = {}
        self.potential_positives = {}
        self.server_error = {}
        self.deep_dive = args.deep_dive
        self.semaphore = asyncio.Semaphore(10)

    def start(self):
        """
        We will provide the user with a user-friendly CLI in which they can choose different options.
        Options include:
        - Loading hosts in 3 different ways (file, manual input, subnet range)
        - Advanced host and port configuration via "Settings" option
        - Start scanning
        - Exiting program 
        """
        print("Welcome to Basic Auth Web Server Scanner")
        while True:
            print("\nMain Menu:")
            print("1. Load hosts from File")
            print("2. Manual Input")
            print("3. Load hosts from Subnet")
            print("4. Settings")
            print("5. Start Scanning")
            print("6. Exit")
            choice = input("Enter your choice: ")
            match choice:
                case '1':
                    self.load_from_file()
                case '2':
                    self.manual_input()
                case '3':
                    self.load_from_subnet()
                case '4':
                    self.settings_menu()
                case '5':
                    depth_choice = input("Do you want to scan in depth? (y/n): ").lower()
                    if depth_choice == 'y':
                        self.deep_dive = True
                    elif depth_choice == 'n':
                        self.deep_dive = False
                    else:
                        print("Invalid choice. Please enter 'y' or 'n'.")
                        continue
                    asyncio.run(self.scan_hosts())
                case '6':
                    print("Exiting program...")
                    break
                case _:
                    print("Invalid choice. Please try again.")

    def settings_menu(self):
        """
        This is a special menu used to configure the number of ports or remove hosts that have been added.
        By selecting option 5, user will be able to return to main menu once they have finished configuring hosts and ports.
        """
        while True:
            print("\nSettings Menu:")
            print("Ports:", self.ports)
            print("1. Add ports")
            print("2. Remove ports")
            print("3. Clear hosts")
            print("4. Clear ports")
            print("5. Return")
            choice = input("Enter your choice: ")
            match choice:
                case '1':
                    self.add_ports()
                case '2':
                    self.remove_ports()
                case '3':
                    self.hosts = []
                    print("Hosts cleared.")
                case '4':
                    self.ports = []
                    print("Ports cleared.")
                case '5':
                    break
                case _:
                    print("Invalid choice. Please try again.")

    def add_ports(self):
        """
        This is a simple function that takes multiple port values seprated by commas.
        It will then append each port into "self.ports" which the class attributes that hold the ports used for scanning
        """
        ports = input("Enter port(s) to add (comma-separated): ").split(',')
        for port in ports:
            try:
                self.ports.append(int(port.strip()))
            except ValueError:
                print("Invalid port number:", port)
        
    def remove_ports(self):
        """
        Similar to add_ports, but removes ports from "self.ports" instead.
        """
        if not self.ports:
            print("No ports loaded.")
            return
        port = input("Enter port to remove: ")
        try:
            port = int(port)
            if port in self.ports:
                self.ports.remove(port)
                print("Port removed successfully.")
            else:
                print("Port not found.")
        except ValueError:
            print("Invalid port number.")
        

    def load_from_file(self):
        """
        This is an option to load hosts using a text file within the same directory of this program.
        Note that file type must be .txt and should have each line as either a valid hostname or a valid ipv4 address
        """
        filename = input("Enter filename: ")
        if not os.path.isfile(filename):
            print("File not found.")
            return
        if not filename.endswith('.txt'):
            print("Invalid file format. Only text files (.txt) are supported.")
            return
        try:
            with open(filename, 'r') as file:
                for line in file:
                    host = line.strip()
                    if self.is_valid_ipv4(host) or self.is_valid_hostname(host):
                        self.hosts.append(host)
                    else:
                        print(f"Invalid host or IPv4 address: {host}")
        except Exception as e:
            print(f"Error reading file: {e}")

    def manual_input(self):
        """
        This is an option to load hosts using manual user input.
        Note that input should be either a valid hostname or a valid ipv4 address
        """
        print("Enter host IP addresses. Enter 's' to stop.")
        while True:
            host = input("Enter host IP address: ")
            if host.lower() == 's':
                break
            if self.is_valid_ipv4(host) or self.is_valid_hostname(host):
                self.hosts.append(host)
            else:
                print(f"Invalid host or IPv4 address: {host}")
            
    def load_from_subnet(self):
        """
        This is an option to load hosts using subnet ranges
        Note that subnet range should be a valid subnet range.
        """
        subnet_str = input("Enter subnet range (e.g., '10.0.0.0/24'): ")
        try:
            subnet = ipaddress.ip_network(subnet_str)
            for host in subnet.hosts():
                self.hosts.append(str(host))
        except ValueError:
            print("Invalid subnet range.")

    async def handle_request(self, session, host, port, method, csv_input):
        """
        Parameter Explanation:
        This is probably the most important function, the one that actually deals with sending the request and handling the response for a chosen host and port.
            Thus it naturally takes host and port as part of its argument to know where it should send its request.
        It is also called within the "scan_host()" function where the client session is established with the host which is why it takes session as an argument as well.
        Method is also a parameter due to this needing to be a recursive function in the case of a 405 status code response.
        Finally it takes csv_input as a parameter too. This value is from the "scan_host()" function too and is used to build the scan summary of each host as a list.
            Based on results in this function we will add values to csv_input.


        The main logic is to formulate our results based on the response status code. Some are easier in giving decisive results, such as 401 status code which lets us know immediately that credentials were wrong.
        Others might not be too decisive. For example, 200 might result in false positives so I had to add extra verifications to increase confidence in deciding whether credentials actually worked.
        I have commented a bit more on the status code cases that are not decisive to explain my logic in detail.
        """
        csv_input.append(port)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname= True
        ssl_context.verify_mode= ssl.CERT_REQUIRED

        try:
            async with session.request(method, f"http://{host}:{port}/", auth=aiohttp.BasicAuth('root', 'root')) as response:

                match response.status:
                    case 200:
                        #If we chose to scan in-depth
                        if self.deep_dive: 
                            response_text = await response.text()
                            response_headers = response.headers
                            csv_input.append(response.status)

                            #Confidence index used to determine whether to add in potential positives or not
                            confidence = 0
                            #Used to check if any result was added during second request handling
                            added_already = False

                            #Indicators that may boost confidence level of true positive
                            content_indicators = [
                                "Welcome", 
                                "Hello", 
                                "Login successful",
                                "User Profile",
                                "Account Settings",
                                "Success",
                                "Logged in"
                            ]
                            header_indicators = [
                                "Session-Token",
                                "Set-Cookie",
                                "X-Authenticated-User",
                                "X-Authenticated-Role"
                            ]
                            
                            
                            
                            if response_text and any(indicator in response_text for indicator in content_indicators):
                                confidence += 1

                            if response_headers and any(indicator in response_headers for indicator in header_indicators):
                                confidence += 1

                            #Second request with root:root1 credentials to test "wrong" credentials
                            async with session.request(method, f"http://{host}:{port}/", auth=aiohttp.BasicAuth('root', 'root1')) as response2:

                                response2_text = await response2.text()
                                response2_headers = response2.headers
                                if response2.status == 200:
                                    #If the same "true positive"-like results are in this response too, decrease confidence value
                                    if response2_text and any(indicator in response2_text for indicator in content_indicators):
                                        confidence -= 1
                                    if response2_headers and any(indicator in response2_headers for indicator in header_indicators):
                                        confidence -= 1
                                elif response2.status == 401:
                                    self.true_positives[host] = str(port)
                                    added_already = True
                                else:
                                    confidence += 1

                            #Add if there's at least one indicator of potential positive AND nothing has been added yet from second request above
                            if confidence >= 1 and added_already == False:
                                self.potential_positives[host] = str(port)
                        
                        #Simple scanning mode, same in terms of sending second request but no confidence value checking.
                        else:
                            csv_input.append(response.status)
                            async with session.request(method, f"http://{host}:{port}/", auth=aiohttp.BasicAuth('root', 'root1')) as response2:
                                if response2.status == 401:
                                    self.true_positives[host] = str(port)
                                else:
                                    self.potential_positives[host] = str(port)

                    #In the case of disallowed method (405), run handle_requests() recursively with allowed methods we find in the response
                    case 405: 
                        allow_header = response.headers.get('Allow')
                        if allow_header:
                            allowed_methods = allow_header.split(',')
                            for allowed_method in allowed_methods:
                                await self.handle_request(session, host, port, allowed_method.strip(),csv_input)
                        else:
                            self.true_negatives[host] = str(port)
                            csv_input.append(response.status)

                    case 401:
                        self.true_negatives[host] = str(port)
                        csv_input.append(response.status)

                    case 403:
                        self.true_negatives[host] = str(port)
                        csv_input.append(response.status)

                    case 404:
                        self.true_negatives[host] = str(port)
                        csv_input.append(response.status)

                    case 500:
                        self.server_error[host] = str(port)
                        csv_input.append(response.status)

                    case 501:
                        self.server_error[host] = str(port)
                        csv_input.append(response.status)

                    case 502:
                        self.server_error[host] = str(port)
                        csv_input.append(response.status)

                    case 503:
                        self.server_error[host] = str(port)
                        csv_input.append(response.status)

                    case 504:
                        self.server_error[host] = str(port)
                        csv_input.append(response.status)

                    case 505:
                        self.server_error[host] = str(port)
                        csv_input.append(response.status)
        
        
        except Exception as e:
            #print(f"Error handling request: {e}")

            #In case of error connecting to certain port of host just add "-1" for status code field in csv file
            csv_input.append("-1") 

    async def scan_host(self, host):
        """
        Function that deals with each individual host. Calls handle_request() function (above) to process request on each port and is called within scan_hosts() function (below). Middle of the hierarchy of called functions.

        Main goal is to loop through each port that we need to test and let the handle_request function do its thing. Once csv_input is modified completely by handle_request() then append that list into "self.csv_storage" which will be later used to be converted into a csv output.
        """
        csv_input = []
        csv_input.append(host)
        try:
            async with self.semaphore:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=180)) as session:
                    for port in self.ports:
                        try:
                            await self.handle_request(session, host, port, "GET", csv_input)
                        
                        except Exception as e:
                            print(f"Error on {host}:{port}", e)
                            #csv_input += ["-1"]
                self.csv_storage.append(csv_input)
                        


        except asyncio.TimeoutError:
            print(f"Timeout occurred while scanning {host}")

        except Exception as e:
            print(f"Error while scanning {host}:", e)
            
    def create_output_files(self):
        """
        Creates a text file output for true_positives, true_negatives, potential_positives, and server_error cases if any of them exists.
        Also creates an overall "Report.csv" file which contains what the status code returned was for each port within each host.
        """
        for name, dictionary in [('true_positives', self.true_positives),
                                 ('true_negatives', self.true_negatives),
                                 ('potential_positives', self.potential_positives),
                                 ('server_error', self.server_error)]:
            
            filename = f"{name}.txt"
            if dictionary:
                with open(filename, 'w') as file:
                    for key, value in dictionary.items():
                        file.write(f"{key}:{value}\n")

        #Extend our csv header row based on how many ports we ended up using
        header_row = ["Host"]
        for port in self.ports:
            header_row.extend([f"Port", "Status Code"])
        self.csv_storage.insert(0, header_row)

        with open("Report.csv", "w", newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerows(self.csv_storage)
        
    async def scan_hosts(self):
        """
        Function that is the mastermind behind the scanning. 
        Calls the scan_host function for each host within "self.hosts" 
        Is also responsible for calling create_output_files after everything is done
        """
        if not self.hosts:
            print("No hosts loaded. Please load hosts before scanning.")
            return
        if not self.ports:
            print("No ports loaded. Please load ports before scanning.")
            return
        
        tasks = [self.scan_host(host) for host in self.hosts]
        await asyncio.gather(*tasks)
        print("Done scanning!")
        print("Creating Output...")
        self.create_output_files()
        print("Output Created!")

    @staticmethod
    def is_valid_ipv4(host):
        """
        Check if input is valid ipv4 address
        """
        try:
            ipaddress.IPv4Address(host)
            return True
        except ipaddress.AddressValueError:
            return False
    
    @staticmethod
    def is_valid_hostname(host):
        """
        Check if input is valid hostname 
        """
        try:
            socket.gethostbyname(host)
            return True
        except socket.error:
            return False
    
def main():
    parser = argparse.ArgumentParser(description="Basic Auth Web Server Scanner")
    parser.add_argument('--hosts', nargs='+', default=[], help="List of hosts to scan")
    parser.add_argument('--ports', type=int, nargs='+', default=[80,8080,443], help="List of ports to scan")
    parser.add_argument('--deep-dive', action='store_true', help="Add this if you want to do a deep dive scan")
    args = parser.parse_args()

    scanner_cli = WebServerScannerCLI(args)
    scanner_cli.start()

if __name__ == "__main__":
    # Increase resource limit for file descriptors to prevent potential issues
    resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
    
    main()
