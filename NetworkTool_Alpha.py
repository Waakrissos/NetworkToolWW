from cgitb import text
from logging import LoggerAdapter
import tkinter as tk #Styling
from tkinter import * #Design
import requests
import re
import base64 #Encoding
import json
import os
import uuid

ApiApp = "vIyvNdjNBLD1"
CompanyNum = "6527-0646-0392-1547-0171"


    
def login(event=None):
    
    global SecretID
    
    if "@" not in tbxEmail.get():
        lblMessage.config(text="Please enter a valid E-Mail")
    
    else:

        #Encoding to Base64
        message = tbxEmail.get() + "::" + tbxPw.get()    
        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        
        
        url = "https://api.ayayot.com/access-tokens?fields=secretId"

        payload = {"expiresIn": 3600}

        headers = {
            "Accept": "application/json",
            "Api-Version": "2",
            "Content-Type": "application/json",
            "Authorization": "Basic " + base64_message,
            "Api-Application": ApiApp
        }

        response = requests.request("POST", url, json=payload, headers=headers)
        print(response.text)

        if response.status_code == 201:
            FindSecretID = re.search('"secretId": "([a-zA-Z0-9]*)"', response.text)            
            SecretID = FindSecretID.group(1)
            
            
            url = "https://api.ayayot.com:443/users/me"

            headers = {
                "Accept": "application/json",
                "Api-Version": "2",
                "Api-Application": ApiApp,
                "Authorization": "Bearer " + SecretID
            }

            response = requests.request("GET", url, headers=headers)
            print(response.text)

            filterName = re.search('"name": "([a-zA-Z0-9\.\s\|]*)"', response.text)
            findName = filterName.group(1)
            lblUser.configure(text="User: " + findName)
            
            
            btnShowPw.pack_forget()
            lblEmail.pack_forget()
            tbxEmail.pack_forget()
            lblPw.pack_forget()
            tbxPw.pack_forget()
            lblMessage.pack_forget()
            btnShowPw.pack_forget()
            btnLogin.pack_forget()
            
            lblName.pack()
            tbxName.pack()
            lblAddr.pack()
            tbxAddr.pack()
            lblMask.pack()
            tbxMask.pack()
            lblGateway.pack()
            tbxGateway.pack()
            lblResult.pack()
            btnSubmit.pack()
            btnShowRouteList.pack()
            btnCommit.pack(side=BOTTOM, anchor=SE)
            btnConn2VPN.pack(side=BOTTOM, anchor=SE)
            btnVPN.pack(side=BOTTOM, anchor=SE)
            lblVPN.pack(side=BOTTOM, anchor=SE)
            
            window.bind('<Return>', submit)

        else:
            lblMessage.config(text="Wrong E-Mail or Password")



def showPw():
    
    #Hide
    if tbxPw.cget("show") == "*":
        tbxPw.config(show="")
        btnShowPw.config(text="Hide Password")
    #Show
    elif tbxPw.cget("show") == "":
        tbxPw.config(show="*")
        btnShowPw.config(text="Show Password")



def submit(event=None):
    
    lblRouteList.pack_forget()
    
    address = tbxAddr.get()
    mask = tbxMask.get()
    gw = tbxGateway.get()
    
    url = "https://portal.ixon.cloud:443/api/agents?fields=custom&fields=name&filters=&page-size=1000"

    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "authorization": "Bearer " + SecretID
    }

    response = requests.get(url, headers=headers) 
    
    reAgents = re.search('publicId": "([a-zA-Z0-9]*)", "name": "([a-zA-Z0-9\-\s\/\|\"\\\\]*), .{30}[0-9a-zA-Z\"\-]*", .{16}[a-zA-Z0-9]*, "comKommissionsnummer": "[0-9\/\s]*(' + tbxName.get() + ')[0-9\/\s]*', response.text)
    publicId = reAgents.group(1)
    name = reAgents.group(2)
    commNum = reAgents.group(3)
    print(commNum)
    print(name)
    print(publicId)
    
    
    if reAgents is not None:   
             
        
        url = 'https://portal.ixon.cloud:443/api/agents/' + publicId + '/router-additional-subnets'

        payload = [
            {
                "networkAddress": address,
                "networkMask": mask,
                "gatewayAddress": gw
            }
        ]
        
        
        headers = {
            "Accept": "application/json",
            "Api-Version": "2",
            "Api-Application": ApiApp,
            "Api-Company": CompanyNum,
            "Content-Type": "application/json",
            "Authorization": "Bearer " + SecretID
        }

        response = requests.post(url, json=payload, headers=headers)
        print(response.text)
        
        
        if response.status_code == 200:
            lblResult.configure(text="Success")
        if response.status_code == 201:
            lblResult.configure(text="Success")
        if response.status_code != 200 and response.status_code != 201:
            reMessage = re.search('message": "([a-zA-Z0-9\s\w]*)', response.text)
            lblResult.configure(text=str(reMessage.group(1)))
            
        
        tbxAddr.configure(text="")
        tbxMask.configure(text="")
        tbxGateway.configure(text="")
        tbxName.configure(text="")
        
    else:
        lblResult.configure(text="No machine with this Commission number.")
        


def printAddrs():
    
    routeList = ""
    lblResult.configure(text="")
    
    url = "https://portal.ixon.cloud:443/api/agents?fields=custom&fields=name&filters=&page-size=1000"

    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "authorization": "Bearer " + SecretID
    }

    response = requests.get(url, headers=headers)  
    
    reAgents = re.search('publicId": "([a-zA-Z0-9]*)", "name": "([a-zA-Z0-9\-\s\/\|\"\\\\]*), .{30}[0-9a-zA-Z\"\-]*", .{16}[a-zA-Z0-9]*, "comKommissionsnummer": "[0-9\/\s]*(' + tbxName.get() + ')[0-9\/\s]*', response.text)
    publicId = reAgents.group(1)
    name = reAgents.group(2)
    commNum = reAgents.group(3)
    
    
    
    if publicId is not None:   
        
    
        url = "https://portal.ixon.cloud:443/api/agents/" + publicId + "/router-additional-subnets?fields=%2A"

        headers = {
            "accept": "application/json",
            "Api-Version": "2",
            "Api-Application": ApiApp,
            "Api-Company": CompanyNum,
            "authorization": "Bearer " + SecretID
        }

        response = requests.get(url, headers=headers)
        print(response.text)
        
        reAddresses = re.findall('publicId": "([a-zA-Z0-9]+)", "networkAddress": "([0-9\.]+)", "networkMask": "([0-9\.]+)", "gatewayAddress": "([0-9\.]+)', response.text)
        
        listNum = 0
        
        routeList = ""
        
        for i in reAddresses:
            listNum = listNum + 1
            routeList += str(listNum) + ". " + str(i) + "\n"
            
        edit1 = routeList.replace("(", "")
        finalEdit = edit1.replace(")", "")
        
        if finalEdit == "":
            lblResult.configure(text="No Routes")
            lblRouteList.pack()
        else:
            lblRouteList.configure(text=finalEdit)
            btnShowRouteList.pack_forget()
            btnSubmit.pack_forget()
            btnHideRouteList.pack()
            lblRouteList.pack()
            btnDeleteRouteList.pack()
        
        
    else:
        lblResult.configure(text="No machine with this name.")
        


def hideAddrs():
    
    btnHideRouteList.pack_forget()
    lblRouteList.pack_forget()
    btnShowRouteList.pack()
    btnHideRouteList.pack_forget()
    btnDeleteRouteList.pack_forget()
    btnShowRouteList.pack_forget()
    btnSubmit.pack()
    btnShowRouteList.pack()
    


def delAddrs():
    
    url = "https://portal.ixon.cloud:443/api/agents?fields=custom&fields=name&filters=&page-size=1000"

    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "authorization": "Bearer " + SecretID
    }

    response = requests.get(url, headers=headers)  
    
    reAgents = re.search('publicId": "([a-zA-Z0-9]*)", "name": "([a-zA-Z0-9\-\s\/\|\"\\\\]*), .{30}[0-9a-zA-Z\"\-]*", .{16}[a-zA-Z0-9]*, "comKommissionsnummer": "[0-9\/\s]*(' + tbxName.get() + ')[0-9\/\s]*', response.text)
    publicId = reAgents.group(1)
    name = reAgents.group(2)
    commNum = reAgents.group(3)
    
    
    addrs = re.findall('\'([a-zA-Z0-9]+)\'', lblRouteList.cget("text"))
    
    routesId = "["

    for i in addrs:
        routesId +='{"publicId": "' + str(i) + '"}, '
    
    routesId += ']'
    routesId = routesId.replace(', ]', ']')
    
    routesIdJson = json.loads(routesId)
        
    
        
    url = "https://portal.ixon.cloud:443/api/agents/" + publicId + "/router-additional-subnets"

    payload = routesIdJson
    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "content-type": "application/json",
        "authorization": "Bearer " + SecretID
    }

    response = requests.delete(url, json=payload, headers=headers)
    print(response.text)
    
    if response.status_code == 200 or response.status_code == 201:
        lblResult.configure(text="Routes deleted")
    
    btnDeleteRouteList.pack_forget()
    btnHideRouteList.pack_forget()
    lblRouteList.pack_forget()
    btnSubmit.pack()
    btnShowRouteList.pack()
    
    
    

def commit():
    
    url = "https://portal.ixon.cloud:443/api/agents?fields=custom&fields=name&filters=&page-size=1000"

    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "authorization": "Bearer " + SecretID
    }

    response = requests.get(url, headers=headers)  
    
    reAgents = re.search('publicId": "([a-zA-Z0-9]*)", "name": "([a-zA-Z0-9\-\s\/\|\"\\\\]*), .{30}[0-9a-zA-Z\"\-]*", .{16}[a-zA-Z0-9]*, "comKommissionsnummer": "[0-9\/\s]*(' + tbxName.get() + ')[0-9\/\s]*', response.text)
    publicId = reAgents.group(1)
    name = reAgents.group(2)
    commNum = reAgents.group(3)

    response = requests.get(url, headers=headers)
    print(response.text)

    
    
    if publicId is None:   
        
        lblResult.configure(text="No machine with this name found")
        

    
    url = "https://portal.ixon.cloud:443/api/agents/configuration/push"

    payload = [{"publicId": publicId}]
    headers = {
        "Accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "Content-Type": "application/json",
        "Authorization": "Bearer " + SecretID
    }

    response = requests.post(url, json=payload, headers=headers)
    
    print(response.text)
    print(response.status_code)
    
    

def VPN():
    
    
    url = "https://portal.ixon.cloud:443/api/agents?fields=custom&fields=name&filters=&page-size=1000"

    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "authorization": "Bearer " + SecretID
    }

    response = requests.get(url, headers=headers)  
    print(response.text)
    
    reAgents = re.search('publicId": "([a-zA-Z0-9]*)", "name": "([a-zA-Z0-9\-\s\/\|\"\\\\]*), .{30}[0-9a-zA-Z\"\-]*", .{16}[a-zA-Z0-9]*, "comKommissionsnummer": "[0-9\/\s]*(' + tbxName.get() + ')[0-9\/\s]*', response.text)
    publicId = reAgents.group(1)
    name = reAgents.group(2)
    commNum = reAgents.group(3)


    
    if response.status_code == 200 or response.status_code == 201:
    
    
        if lblVPN.cget("text") != "Opened":
            
            
            url = "https://portal.ixon.cloud:443/api/agents/" + publicId + "/connection/openvpn"

            payload = [
                {
                    "action": "connect",
                }
            ]
            headers = {
                "Accept": "application/json",
                "Api-Version": "2",
                "Api-Application": ApiApp,
                "Api-Company": CompanyNum,
                "Content-Type": "application/json",
                "Authorization": "Bearer " + SecretID
            }

            response = requests.post(url, headers=headers, json=payload)
            print(response.text)
            
            if response.status_code == 200 or response.status_code == 201:
            
                lblVPN.configure(text="Opened")
                btnVPN.configure(text="Close VPN Tunnel")
            
            elif response.status_code == 503:
                lblVPN.configure(text="No MQTT Connection")
            
            else:
                lblVPN.configure(text="There was an Error")
                
        else:
            
            url = "https://portal.ixon.cloud:443/api/agents/" + publicId + "/connection/openvpn"

            payload = [
                {
                    "action": "disconnect",
                }
            ]
            headers = {
                "Accept": "application/json",
                "Api-Version": "2",
                "Api-Application": ApiApp,
                "Api-Company": CompanyNum,
                "Content-Type": "application/json",
                "Authorization": "Bearer " + SecretID
            }

            response = requests.post(url, headers=headers, json=payload)
            print(response.text)
            
            if response.status_code == 200 or response.status_code == 201:
                
                lblVPN.configure(text="Closed")
                btnVPN.configure(text="Open VPN Tunnel")
            
            else:
                lblVPN.configure(text="There was an Error")
    else:
        lblVPN.configure(text="No such machine found")
        
        
        
def Conn2VPN():
    
    url = "https://portal.ixon.cloud:443/api/agents?fields=custom&fields=name&filters=&page-size=1000"

    headers = {
        "accept": "application/json",
        "Api-Version": "2",
        "Api-Application": ApiApp,
        "Api-Company": CompanyNum,
        "authorization": "Bearer " + SecretID
    }

    response = requests.get(url, headers=headers)  
    
    reAgents = re.search('publicId": "([a-zA-Z0-9]*)", "name": "([a-zA-Z0-9\-\s\/\|\"\\\\]*), .{30}[0-9a-zA-Z\"\-]*", .{16}[a-zA-Z0-9]*, "comKommissionsnummer": "[0-9\/\s]*(' + tbxName.get() + ')[0-9\/\s]*', response.text)
    publicId = reAgents.group(1)
    
    if btnConn2VPN.cget("text") == "Connect to VPN":
          
        UUID = str(uuid.uuid1())
        
        url = "https://localhost:9250/connect"
        
        headers = {
            "Accept": "application/json",
            "Api-Application": ApiApp,
            "Api-Company": CompanyNum,
            "Api-Version": "2",
            "Api-Access-Token": SecretID,
            "VPN-Client-Controller-Identifier": UUID
            }
        
        data = {
            "agentId": publicId,
            "companyId": CompanyNum
            
        }
        
        response = requests.post(url=url, headers=headers, verify=False, json=data)
        
        if response.status_code == 200 or response.status_code == 201:
            btnConn2VPN.configure(text="Disconnect from VPN", bg="#FF0000")
            lblVPN.configure(text="")
        else:
            lblVPN.configure(text="Error")
    
    elif btnConn2VPN.cget("text") == "Disconnect from VPN":
        
        url = "https://localhost:9250/disconnect"
    
        response = requests.post(url=url, verify=False)
        
        if response.status_code == 200 or response.status_code == 201:
            btnConn2VPN.configure(text="Connect to VPN", bg="#00FF00")
            lblVPN.configure(text="")
        else:
            lblVPN.configure(text="Error")

        
window = tk.Tk()
    
window.title('Network Tool')

window.geometry('620x500')
window.resizable(True, True)

window.configure(bg='white')   

lblUser = tk.Label(bg='white', font=('gotham light',16))
lblUser.pack()

lblEmail = tk.Label(text="Email:", bg='white', font=('gotham light',11))
lblEmail.pack()

tbxEmail = tk.Entry(fg="black", bg="white", width=30, font=('gotham light',11), justify='center')
tbxEmail.pack()

lblPw = tk.Label(text="Password:", bg='white', font=('gotham light',11))
lblPw.pack()

tbxPw = tk.Entry(fg="black", bg="white", width=30, font=('gotham light',11), justify='center', show="*")
tbxPw.pack()

btnShowPw = tk.Button(text="Show Password", width=11, height=1, bg="#2457a0", fg="white", command=showPw, font=('gotham light',8))
btnShowPw.pack()

btnLogin = tk.Button(text="Log In", width=15, height=2, bg="#2457a0", fg="white", command=login, font=('gotham light',11))
btnLogin.pack()

lblMessage = tk.Label(bg='white', font=('gotham light',11))

lblName = tk.Label(text="Commission Number:", bg='white', font=('gotham light',11))

tbxName = tk.Entry(fg="black", bg="white", width=30, font=('gotham light',11), justify='center')

lblAddr = tk.Label(text="Address:", bg='white', font=('gotham light',11))

tbxAddr = tk.Entry(fg="black", bg="white", width=30, font=('gotham light',11), justify='center')
tbxAddr.insert(-1, "192.168.")

lblMask = tk.Label(text="Mask:", bg='white', font=('gotham light',11))

tbxMask = tk.Entry(fg="black", bg="white", width=30, font=('gotham light',11), justify='center')
tbxMask.insert(-1, "255.255.255.0")

lblGateway = tk.Label(text="Gateway:", bg='white', font=('gotham light',11))

tbxGateway = tk.Entry(fg="black", bg="white", width=30, font=('gotham light',11), justify='center')
tbxGateway.insert(-1, "192.168.")

btnSubmit = tk.Button(text="Submit", width=15, height=2, bg="#2457a0", fg="white", command=submit, font=('gotham light',11))

lblResult = tk.Label(bg='white', font=('gotham light',11))

btnShowRouteList = tk.Button(text="Show Routes", width=15, height=2, bg="#2457a0", fg="white", command=printAddrs, font=('gotham light',11))
btnHideRouteList = tk.Button(text="Hide Routes", width=15, height=2, bg="#2457a0", fg="white", command=hideAddrs, font=('gotham light',11))

btnDeleteRouteList = tk.Button(text="Delete Routes", width=15, height=2, bg="#2457a0", fg="white", command=delAddrs, font=('gotham light',11))

lblRouteList = tk.Label(bg='white', font=('gotham light',11), justify=LEFT)

btnCommit = tk.Button(text="Commit Changes", width=15, height=1, bg="#2457a0", fg="white", command=commit, font=('gotham light',11))

btnVPN = tk.Button(text="Open VPN Tunnel", width=15, height=1, bg="#2457a0", fg="white", command=VPN, font=('gotham light',11))
lblVPN = tk.Label(bg='white', font=('gotham light',11))

btnConn2VPN = tk.Button(text="Connect to VPN", width=15, height=1, bg="#00FF00", fg="black", command=Conn2VPN, font=('gotham light',11))

window.bind('<Return>', login)

window.mainloop()
