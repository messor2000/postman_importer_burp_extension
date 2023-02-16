import json
import re
import base64
import ast
from Postman import Postman

variables = []
postman = Postman()

def setUpHost(host, variable):
    host = ".".join(host)
    if re.search("{{.*}}", host):
        match = re.search("{{(.*?)}}", host)
        key = match.group(1)
        for var in variable:
            if isinstance(var, dict) and var['key'] == key:
                host = var['value']
                break
            else:
                continue
    return host


def setUpUrl(url, protocol, host, variable):
    pattern = "{{(.*?)}}"
    if re.search(pattern, url):
        match = re.search(pattern, url)
        key = match.group(1)
        for var in variable:
            if isinstance(var, dict) and var['key'] == key:
                url = re.sub(pattern, var['value'], url)
                break

    if not re.search("https://", url):
        url = re.sub("^(.*?)/", protocol + "://" + host + "/", url)

    return url


def extract_collection_variables(script):
    variable_list = []
    for line in script['exec']:
        if "pm.collectionVariables.set" in line:
            match = re.search("'(.*?)','(.*?)'", line)
            if match:
                variable_list.append({'key': match.group(1), 'value': match.group(2)})
    return variable_list


def replaceVariables(body, variables):
    matches = re.findall(r'{{(.*?)}}', body)
    for match in matches:
        # Check if the key is in the variable list
        variable = next((var for var in variables if var['key'] == match), None)
        if variable is not None:
            # Replace the match with the value
            body = body.replace("{{" + match + "}}", variable['value'])

    return body


def addEndpointToList(self, event):
    endpointKey = self.endpointKeyField.getText()
    endpointValue = self.endpointValueField.getText()

    newEntry = {"type": "string", "value": endpointValue, "key": endpointKey}
    self.variables.append(newEntry)
    print(self.variables)
    self.logArea.append(
        '\nEnvironment variable with key: %s and value: %s was successfully added \n' % (
            endpointKey, endpointValue))


def parsePostmanCollection(collection):
    if 'item' in collection:
        items = collection['item']
        result = []
        for item in items:
            if 'item' in item:
                result += parsePostmanCollection(item)
            else:
                result.append(item)
        return result
    else:
        return [collection]


def getScriptResult(data):
    pre_request_scripts = []
    for item in data["item"]:
        if "event" in item and item["event"][0]["listen"] == "prerequest":
            script = item["event"][0]["script"]["exec"]
            if isinstance(script, str):
                pre_request_scripts.append(script)

    # Run the Pre-request scripts
    result_data = []
    for script in pre_request_scripts:
        # Evaluate the script using exec()
        exec (script)

        # Append the result data to the list
        result_data.append(script)

    # Print the result data
    print(result_data)


def getAuthorizationFromRequest(request, variables):
    auth_type = None
    auth_params = {}

    if 'request' in request and 'auth' in request['request']:
        if request["request"]["auth"]["type"] in ["basic", "bearer"]:
            auth_type = request["request"]["auth"]["type"]
            auth_params = request["request"]["auth"][auth_type]

    username = ""
    password = ""
    token = ""
    for param in auth_params:
        if param.get("key") == "username":
            username = replaceVariablesInAuth(param["value"], variables)
        elif param.get("key") == "password":
            password = replaceVariablesInAuth(param["value"], variables)
        elif param.get("key") == "token":
            token = replaceVariablesInAuth(param["value"], variables)
            break

    if auth_type == "basic":
        return "Basic " + base64.b64encode((username + ":" + password).encode("utf-8")).decode("utf-8")
    elif auth_type == "bearer":
        return "Bearer " + token
    elif auth_type in ["oauth1", "oauth1.0a"]:
        # Implement OAuth 1.0 or 1.0a specific authorization
        pass
    elif auth_type == "oauth2":
        # Implement OAuth 2 specific authorization
        pass



def replaceVariablesInAuth(value, variables):
    match_pattern = r"{{.*}}"
    pattern = r"{{(.*)}}"
    if re.match(match_pattern, value):
        match = re.search(pattern, value)
        key = match.group(1)
        for var in variables:
            if isinstance(var, dict) and var['key'] == key:
                value = re.sub(value, var['value'], value)
                break
    else:
        value = value

    return value


def parse_postman_collection_scripts(data):
    result = []
    for item in data["item"]:
        if "event" in item:
            events = item["event"]
            for event in events:
                if "script" in event and "exec" in event["script"]:
                    exec_script = event["script"]["exec"]
                    exec_script = [line for line in exec_script if not line.startswith("//") if
                                   not line.startswith("console.log")]
                    exec_script = "\n".join(exec_script)

                    exec_script_lines = exec_script.split("\n")

                    for exec_sc in exec_script_lines:
                        if exec_sc.startswith("pm.collectionVariables.set"):
                            key, value = exec_sc[len("pm.collectionVariables.set("):-2].split(",")
                            key = key.strip("'")
                            value = value.strip("'")
                            variables.append({'key': key, 'value': value, 'type': 'string'})

                    exec_script = '\n'.join(
                        [line for line in exec_script.split('\n') if not line.startswith("pm.collectionVariables.set")])
                    print("SCRIPT" + exec_script)
                    try:
                        exec (ast.literal_eval(exec_script))
                        result.append(ast.literal_eval(exec_script))
                    except:
                        print("Error while executing script: " + exec_script)
    return result


def checkAuthField(collection):
    if isinstance(collection, dict):
        if "auth" in collection:
            return True
        elif "request" in collection and "auth" in collection["request"]:
            return True
        elif "item" in collection:
            return checkAuthField(collection["item"])
    elif isinstance(collection, list):
        for item in collection:
            if checkAuthField(item):
                return True
    return False


class PostmanImporter:
    f = open('/Users/oovcharenko/Downloads/billing-core-self-bill.postman_collection.json')

    data = json.load(f)

    if data.get('variable'):
        variables = data['variable']
        line = {'type': 'string', 'value': 'example.com', 'key': 'url'}
        line2 = {'type': 'string', 'value': 'example.com', 'key': 'url_CEM'}
        line3 = {'type': 'string', 'value': 'AAAA', 'key': 'login'}
        line4 = {'type': 'string', 'value': 'BBBB', 'key': 'password'}
        variables.append(line)
        variables.append(line2)
        variables.append(line3)
        variables.append(line4)
    # print(variables)

    items = data['item']
    requests = [item for item in items if 'name' in item]

    parsedCollection = parsePostmanCollection(data)

    for request in parsedCollection:
        url = request['request']['url']['raw']
        host = request['request']['url']['host']
        port = request['request']['url'].get('port', None)
        protocol = request['request']['url'].get('protocol', None)

        if 'event' in request and request['event'] and request['event'][0].get('listen') == "prerequest":
            try:
                postman.runPreRequestScripts(request)
            except Exception, e:
                print("An error occurred while evaluating the JavaScript code: %s" % e)
                continue

        variables.append(postman.get_script_variables())
        print(variables)

        if checkAuthField(data):
            authorization = getAuthorizationFromRequest(request, variables)

        if not protocol:
            protocol = "http"

        if port == -1 or not port:
            if protocol == "http":
                port = 80
            elif protocol == "https":
                port = 443

        host = setUpHost(host, variables)

        url = setUpUrl(url, protocol, host, variables)

        if not re.search("https://", url):
            url = re.sub("^(.*?)/", protocol + "://" + host + "/", url)

        if request['request'].get('body'):
            body = request['request']['body']['raw']
            print(replaceVariables(body, variables))

        # print(url)
        # print(host)
        # print(port)
        # print(protocol)
        # print(request['request']['method'])
