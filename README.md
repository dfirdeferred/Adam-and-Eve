# Adam-and-Eve
Adam and Eve is a Remote Access tool, socket (and HTTP) server used to interact with Active Directory Environments across the Internet via a Flask API.

Stay tuned..... more prebuilt commands and Dockerized version on the way.

####### Instructions ##########

Run aande.py
The socket server by default will host on 0.0.0.0:9999
The flask api by default will host on 0.0.0.0:80  (noraml port for http)

Once the server is running, run aande_agent.ps1 on the machine. You should see a message on the server informing you that the client has connected.

In a web browser, navigate to the ip address of the server and enjoy. 


More functionality to come shortly.