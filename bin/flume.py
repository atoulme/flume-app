import sys
import os
import xml.dom.minidom, xml.sax.saxutils
import json
import base64
import datetime
import requests


SCHEME = """<scheme>
    <title>Flume CLI</title>
    <description>Leverage https://github.com/ScriptBlock/flumecli to report Flume stats</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>simple</streaming_mode>
    <endpoint>
        <args>
            <arg name="clientid">
                <title>Client ID</title>
                <description>You have to get this through the flumetech portal: https://portal.flumetech.com/#dashboard</description>
            </arg>
            <arg name="clientsecret" type="password">
                <title>Client Secret</title>
                <description>You have to get this through the flumetech portal: https://portal.flumetech.com/#dashboard</description>
            </arg>
            <arg name="username">
                <title>Username</title>
                <description>Portal username</description>
            </arg>
            <arg name="password" type="password">
                <title>Password</title>
                <description>Portal password</description>
            </arg>
        </args>
    </endpoint>
</scheme>
"""
def obtainCredentials(config):
    if config["verbose"]: print("Getting auth token")

    if config["clientid"] and config["clientsecret"] and config["username"] and config["password"]:
        if config["verbose"]: print("all required parameters passed for auth token")
        url = "https://api.flumetech.com/oauth/token"
        payload = '{"grant_type":"password","client_id":"' + config["clientid"] + '","client_secret":"' + config["clientsecret"] + '","username":"' + config["username"] + '","password":"' + config["password"] + '"}'
        headers = {'content-type': 'application/json'}

        resp = requests.request("POST", url, data=payload, headers=headers)
        if config["verbose"]: print("response from server: " + resp.text)
        dataJSON = json.loads(resp.text)

        if dataJSON["http_code"] == 200:
            if config["verbose"]: print("Got 200 response from auth token request")
            config["access_token"] = dataJSON["data"][0]["access_token"]
            config["refresh_token"] = dataJSON["data"][0]["refresh_token"]

        else:
            quit("failed to obtain creds")

def buildRequestHeader(config):
    header = {"Authorization": "Bearer " + config["access_token"]}
    return header


def testAuthorizationToken(config):
    resp = requests.request('GET', "https://api.flumetech.com/users/11382", headers=buildRequestHeader(config))
    #print(resp.text);
    dataJSON = json.loads(resp.text)
    return dataJSON["http_code"] == 200

def previousminute():
    return (datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')

def currentminute():
    #return (datetime.datetime.now() - datetime.timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S');
    return (datetime.datetime.now()).strftime('%Y-%m-%d %H:%M:%S');


def base64url_decode(input):
    input = input.encode("ascii")
    rem = len(input) % 4

    if rem > 0:
        input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(input)

def readJWTTokenPayload(jwt):

    signing_input, crypto_segment = jwt.rsplit(b".", 1)
    header_segment, payload_segment = signing_input.split(b".", 1)
    payload = base64url_decode(payload_segment)

    return payload

def getUserID(config):
    if config["verbose"]: print("Getting user ID from JWT")
    decoded = json.loads(readJWTTokenPayload(config["access_token"]))
    config["user_id"] = decoded["user_id"]
    if config["verbose"]:
        print("JWT Details: ")
        print(decoded)

def getDevices(config):
    if config["verbose"]: print("Getting devices")
    resp = requests.request('GET', 'https://api.flumetech.com/users/' + str(config["user_id"]) + '/devices', headers=buildRequestHeader(config))

    dataJSON = json.loads(resp.text)

    if config["verbose"]: print("Executed device search")

    config["device_id"] = []
    if dataJSON["http_code"] == 200:
        for bridge in dataJSON["data"]:
            if config["verbose"]:
                print("JSON Data from device")
                print(dataJSON["data"])
            if bridge["type"] == 2:
                config["device_id"].append(bridge["id"])


def getWaterFlowLastMinute(config, deviceId):
    payload = '{"queries":[{"request_id":"perminute","bucket":"MIN","since_datetime":"' + previousminute() + '","until_datetime":"' + currentminute() + '","group_multiplier":"1","operation":"SUM","sort_direction":"ASC","units":"GALLONS"}]}'
    #print(payload)
    headers = buildRequestHeader(config);
    headers["content-type"] = "application/json"
    resp = requests.request("POST", "https://api.flumetech.com/users/" + str(config["user_id"])  + "/devices/" + str(deviceId)  + "/query", data=payload, headers=headers)
    data = json.loads(resp.text)
    #print(data)
    if data["http_code"]==200:
        return data["data"][0]["perminute"][0]["value"]
    else:
        return None


def parameters():
    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        if param_name and param.firstChild and \
                                param.firstChild.nodeType == param.firstChild.TEXT_NODE and \
                                param_name == "clientid":
                            clientid = param.firstChild.data
                        if param_name and param.firstChild and \
                                param.firstChild.nodeType == param.firstChild.TEXT_NODE and \
                                param_name == "clientsecret":
                            clientsecret = param.firstChild.data
                        if param_name and param.firstChild and \
                                param.firstChild.nodeType == param.firstChild.TEXT_NODE and \
                                param_name == "username":
                            username = param.firstChild.data
                        if param_name and param.firstChild and \
                                    param.firstChild.nodeType == param.firstChild.TEXT_NODE and \
                                    param_name == "password":
                            password = param.firstChild.data
        return [clientid, clientsecret, username, password]
    except Exception as e:
        raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))

    return ""

def do_scheme():
    print(SCHEME)
# Empty validation routine. This routine is optional.
def validate_arguments():
    pass


def run_script():
    params = parameters()
    config = {}
    config["verbose"] = False
    config["clientid"] = params[0]
    config["clientsecret"] = params[1]
    config["username"] = params[2]
    config["password"] = params[3]
    config["tokenfile"] = '/tmp/token'
    obtainCredentials(config)
    getUserID(config)
    getDevices(config)
    for device in config["device_id"]:
        print("{\"time\":\"" + currentminute() + "\",\"device\":\"" + str(device) + "\",\"value\":\"" + str(getWaterFlowLastMinute(config, device)) + "\"}")



# Script must implement these args: scheme, validate-arguments
if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            validate_arguments()
        else:
            pass
    else:
        run_script()

    sys.exit(0)

