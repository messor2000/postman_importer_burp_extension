import json
import re
import os
import urlparse
from javax import swing
from java.awt import Font
import base64
import thread
from burp import IBurpExtender, IExtensionStateListener, ITab
from burp import IHttpService
from burp import IHttpRequestResponse
from postman import Postman

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


def getQueryFromUrl(url):
    match = re.search(r'\?(.*)', url)
    if match:
        query_string = match.group(1)
        return query_string
    else:
        return None


def getPathFromUrl(url):
    match = re.search(r'https?://[^/]+([^?]+)', url)
    if match:
        return match.group(1)
    return None


def getRequestContentType(headers):
    for header in headers:
        if header['key'] == "Content-Type":
            return header['value']
    return None


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


def createRequestWithoutAuth(method, path_name, query, host, body, contentType):
    if not body or body == "":
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r\n\r'

    else:
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r' \
            + 'Content-Type: ' + contentType + '\n\r' \
            + '\n\r' + body + '\n\r'


def createRequestWithAuth(method, path_name, query, host, body, contentType, auth):
    if not body or body == "":
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r' \
            + 'Authorization: ' + auth + '\n\r'
    else:
        return method + ' ' + path_name + query + ' HTTP/1.1\n\r' \
            + 'Host: ' + host + '\n\r' \
            + 'Content-Type: ' + contentType + '\n\r' \
            + 'Authorization: ' + auth + '\n\r' \
            + '\n\r' + body + '\n\r'


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


def variables_enumerating(environment_variables, variable, endpointKey):
    for i, entry in enumerate(environment_variables):
        if entry['key'] == endpointKey:
            environment_variables[i] = variable
            break
    else:
        environment_variables.append(variable)


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    file = None
    pattern = "{{(.*?)}}"
    postman = Postman()

    def __init__(self):
        self.callbacks = None
        self.gui = None

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("Postman Importer")
        self.callbacks.registerExtensionStateListener(self)
        self.helpers = callbacks.getHelpers()

        self.initGui()
        self.setUpJsCode()
        self.callbacks.addSuiteTab(self)
        print("Extension Loaded")

    def initGui(self):
        self.tab = swing.JPanel()
        self.titleLabel = swing.JLabel("Postman Importer")
        self.titleLabel.setFont(Font("Tahoma", 1, 17))
        self.infoLabel1 = swing.JLabel(
            "To get JSON file from postman you need to import, you should follow these steps: ")
        self.infoLabel2 = swing.JLabel(
            "Open collection, push export button, download .json file and upload this file to Burp")
        self.parseFileButton = swing.JButton("Load File to Parse", actionPerformed=self.loadFile)
        self.addButton = swing.JButton("Add requests to site map", actionPerformed=self.addRequestsToSiteMap)
        self.infoLabelEndpoint = swing.JLabel("You can add variables for your requests, auth or body")
        self.infoEndpointKeyField = swing.JLabel("Variable: ")
        self.endpointKeyField = swing.JTextField()
        self.infoEndpointValueField = swing.JLabel("Initial value: ")
        self.endpointValueField = swing.JTextField()
        self.addVariableButton = swing.JButton("Add variable to list", actionPerformed=self.add_variable_to_list)
        self.removeButton = swing.JButton("Remove selected variable", actionPerformed=self.remove)
        self.clearButton = swing.JButton("Clear all variables", actionPerformed=self.clear)
        self.urlListModel = swing.DefaultListModel()
        self.urlList = swing.JList(self.urlListModel)
        self.urlListPane = swing.JScrollPane(self.urlList)
        self.infoLabel3 = swing.JLabel(
            "NOTE: If you add new requests from another collection, but their will be duplicat, they will be "
            "overwritten")
        self.logLabel = swing.JLabel("Log:")
        self.logPane = swing.JScrollPane()
        self.logArea = swing.JTextArea("Postman Importer Log - Parsing and Run details will be appended here.\n")
        self.infoLabel11 = swing.JLabel(
            "If you need to get some values from pre-request scripts in Postman you should read instruction below.")
        self.infoLabel11.setFont(Font("Tahoma", 1, 12))
        self.infoLabel12 = swing.JLabel(
            "To give able this extension run pre-request scripts you should deploy Node JS server local on you computer.")
        self.infoLabel13 = swing.JLabel(
            "Node JS server must have specific configuration to receive requests and return response.")
        self.infoLabel14 = swing.JLabel(
            "To run such specific server follow these steps:")
        self.infoLabel15 = swing.JLabel("1: Copy Node js code below.")
        self.infoLabel16 = swing.JLabel("2: Create new .js file and past code inside of it.")
        self.infoLabel17 = swing.JLabel("3: Using terminal, open folder"
                                        " your file placed and run command: node your-file.js")
        self.jsLabel = swing.JLabel("Node JS code:")
        self.jsPane = swing.JTextPane()
        self.infoNoteJs = swing.JLabel("NOTE: You can change Node JS server port as you want")
        self.logArea.setLineWrap(True)
        self.logPane.setViewportView(self.logArea)
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(layout.createSequentialGroup()
                                  .addGap(30)
                                  .addGroup(layout.createParallelGroup()
                                            .addGap(15)
                                            .addComponent(self.titleLabel)
                                            .addComponent(self.infoLabel1)
                                            .addComponent(self.infoLabel2)
                                            .addComponent(self.parseFileButton)
                                            .addComponent(self.addButton)
                                            .addComponent(self.infoLabelEndpoint)
                                            .addComponent(self.infoEndpointKeyField)
                                            .addComponent(self.endpointKeyField, swing.GroupLayout.PREFERRED_SIZE, 400,
                                                          swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.infoEndpointValueField)
                                            .addComponent(self.endpointValueField, swing.GroupLayout.PREFERRED_SIZE,
                                                          400,
                                                          swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.addVariableButton)
                                            .addComponent(self.urlListPane, swing.GroupLayout.PREFERRED_SIZE, 400,
                                                          swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.clearButton)
                                            .addComponent(self.removeButton)
                                            .addComponent(self.infoLabel3)
                                            .addComponent(self.logLabel)
                                            .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 625,
                                                          swing.GroupLayout.PREFERRED_SIZE))
                                  .addGap(40)
                                  .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(self.infoLabel11)
                                            .addComponent(self.infoLabel12)
                                            .addComponent(self.infoLabel13)
                                            .addComponent(self.infoLabel14)
                                            .addComponent(self.infoLabel15)
                                            .addComponent(self.infoLabel16)
                                            .addComponent(self.infoLabel17)
                                            .addComponent(self.jsLabel)
                                            .addComponent(self.jsPane, swing.GroupLayout.PREFERRED_SIZE, 400,
                                                          swing.GroupLayout.PREFERRED_SIZE)
                                            .addComponent(self.infoNoteJs)
                                            )
                                  )

        layout.setVerticalGroup(layout.createParallelGroup()
                                .addGap(30)
                                .addGroup(layout.createSequentialGroup()
                                          .addGap(15)
                                          .addComponent(self.titleLabel)
                                          .addGap(10)
                                          .addComponent(self.infoLabel1)
                                          .addGap(10)
                                          .addComponent(self.infoLabel2)
                                          .addGap(10)
                                          .addComponent(self.parseFileButton)
                                          .addGap(10)
                                          .addComponent(self.addButton)
                                          .addGap(20)
                                          .addComponent(self.infoLabelEndpoint)
                                          .addGap(10)
                                          .addComponent(self.infoEndpointKeyField)
                                          .addComponent(self.endpointKeyField, swing.GroupLayout.PREFERRED_SIZE, 30,
                                                        swing.GroupLayout.PREFERRED_SIZE)
                                          .addGap(10)
                                          .addComponent(self.infoEndpointValueField)
                                          .addComponent(self.endpointValueField, swing.GroupLayout.PREFERRED_SIZE, 30,
                                                        swing.GroupLayout.PREFERRED_SIZE)
                                          .addGap(10)
                                          .addComponent(self.addVariableButton)
                                          .addGap(10)
                                          .addComponent(self.urlListPane, swing.GroupLayout.PREFERRED_SIZE, 150,
                                                        swing.GroupLayout.PREFERRED_SIZE)
                                          .addGap(10)
                                          .addComponent(self.removeButton)
                                          .addGap(10)
                                          .addComponent(self.clearButton)
                                          .addGap(20)
                                          .addComponent(self.infoLabel3)
                                          .addGap(15)
                                          .addComponent(self.logLabel)
                                          .addGap(10)
                                          .addComponent(self.logPane, swing.GroupLayout.PREFERRED_SIZE, 225,
                                                        swing.GroupLayout.PREFERRED_SIZE)
                                          )
                                .addGap(40)
                                .addGroup(layout.createSequentialGroup()
                                          .addGap(40)
                                          .addComponent(self.infoLabel11)
                                          .addGap(15)
                                          .addComponent(self.infoLabel12)
                                          .addGap(10)
                                          .addComponent(self.infoLabel13)
                                          .addGap(10)
                                          .addComponent(self.infoLabel14)
                                          .addGap(10)
                                          .addComponent(self.infoLabel15)
                                          .addGap(10)
                                          .addComponent(self.infoLabel16)
                                          .addGap(10)
                                          .addComponent(self.infoLabel17)
                                          .addGap(15)
                                          .addComponent(self.jsLabel)
                                          .addGap(10)
                                          .addComponent(self.jsPane, swing.GroupLayout.PREFERRED_SIZE, 600,
                                                        swing.GroupLayout.PREFERRED_SIZE)
                                          .addGap(15)
                                          .addComponent(self.infoNoteJs)
                                          )
                                )
        return

    def getRequestsFromPostman(self):
        environment_variables = self.getUrlList()
        if self.file is None:
            self.callbacks.printError('\nYou did not select file, try agine \n')
            self.logArea.append('\nERROR: You did not select file, try agine \n')
            return

        selectedFile = open(str(self.file))

        data = json.load(selectedFile)

        if data.get('variable'):
            for element in data['variable']:
                environment_variables.append(element)

        requests = parsePostmanCollection(data)

        self.logArea.append(
            '\nRequests from Postman collection: \n')

        for request in requests:
            url = request['request']['url']['raw']
            host = request['request']['url']['host']
            protocol = request['request']['url'].get('protocol', None)
            method = request['request']['method']
            contentType = request['request']['header']
            if request['request'].get('body'):
                body = request['request']['body']['raw']
            else:
                body = ""

            if not protocol:
                protocol = "http"

            if 'event' in request and request['event'] and request['event'][0].get('listen') == "prerequest":
                try:
                    self.postman.run_pre_request_scripts(request)
                except Exception, e:
                    self.logArea.append("\nERROR: An error occurred while evaluating the JavaScript code: %s\n" % e)
                    continue

            environment_variables += self.postman.append_list_to_variables(environment_variables,
                                                                           self.postman.get_script_variables(), 'script')
            for variable in environment_variables:
                if self.is_entry_unique(variable):
                    self.add_variable_to_list_from_scripts(variable, None)

            host = self.setUpHost(host)
            url = self.setUpUrl(url, protocol, host)
            path = getPathFromUrl(url)
            query = getQueryFromUrl(url)
            contentType = getRequestContentType(contentType)
            body = self.replaceVariables(body)

            if path is None or path == "":
                path = "/"

            if query is None:
                query = ""
            else:
                query = '?' + query

            if contentType is None:
                contentType = ""

            if self.check_url(url):
                authorization, found = None, None
                if checkAuthField(data):
                    authorization, found = self.getAuthorization(request, data)
                    if not found:
                        self.logArea.append(
                            '\nERROR: Request: %s was not added to the site map because of incorrect variables in '
                            'authorization \n' % url)
                        continue
                if found is None or found:
                    if authorization:
                        newRequest = createRequestWithAuth(method, path, query, host, body, contentType, authorization)

                    else:
                        newRequest = createRequestWithoutAuth(method, path, query, host, body, contentType)

                    if self.check_test(request):
                        try:
                            self.postman.run_tests(request, url, body, host, contentType, method, authorization)
                            environment_variables += self.postman.append_list_to_variables(
                                environment_variables, self.postman.get_script_variables(), 'test')
                        except Exception, e:
                            self.logArea.append(
                                "\nERROR: An error occurred while evaluating tests from Postman request: "
                                "%s : In request %s\n" % (e, request))
                            continue

                    self.addToSiteMap(url, newRequest, "")
                    self.logArea.append(
                        '\nRequest: %s was successfully added to the site map \n' % url)
                else:
                    self.logArea.append(
                        '\nRequest: %s was not added to the site map \n' % url)
            else:
                pass

        self.logArea.append(
            '\n -------------------------------------- \n')

    def setUpHost(self, host):
        environment_variables = self.getUrlList()
        host = ".".join(host)
        if re.search("{{.*}}", host):
            match = re.search(self.pattern, host)
            key = match.group(1)
            found = False
            for var in environment_variables:
                if isinstance(var, dict) and var['key'] == key:
                    host = var['value']
                    found = True
                    break
            if not found:
                self.logArea.append('\nERROR: There is problem with reading this host in your request %s '
                                    % host)
                self.callbacks.printError('\nERROR: There is problem with reading this host in your request %s '
                                          % host)
        return host

    def setUpUrl(self, url, protocol, host):
        environment_variables = self.getUrlList()
        if re.search(self.pattern, url):
            match = re.search(self.pattern, url)
            key = match.group(1)
            found = False
            for var in environment_variables:
                if isinstance(var, dict) and var['key'] == key:
                    url = re.sub(self.pattern, var['value'], url)
                    found = True
                    break
            if not found:
                self.logArea.append('\nERROR: There is problem with reading url in your request %s ' % url)
                self.callbacks.printError('\nERROR: There is problem with reading url in your request %s ' % url)

        if not re.search("https://", url):
            url = re.sub("^(.*?)/", protocol + "://" + host + "/", url)
        return url

    def add_variable_to_list(self, event):
        environment_variables = self.getUrlList()
        endpointKey = self.endpointKeyField.getText()
        endpointValue = self.endpointValueField.getText()

        newEntry = {"value": endpointValue, "key": endpointKey}

        variables_enumerating(environment_variables, newEntry, endpointKey)

        currentList = self.getUrlList()
        currentList.append(newEntry)
        self.urlList.setListData(currentList)

        self.logArea.append(
            '\nEnvironment variable with key: %s and value: %s was successfully added \n' % (
                endpointKey, endpointValue))

    def add_variable_to_list_from_scripts(self, variable, event):
        endpointKey = variable['key']

        environment_variables = self.getUrlList()

        variables_enumerating(environment_variables, variable, endpointKey)

        currentList = self.getUrlList()
        currentList.append(variable)
        self.urlList.setListData(currentList)

    def replaceVariables(self, body):
        environment_variables = self.getUrlList()
        matches = re.findall(self.pattern, body)
        for match in matches:
            variable = next((var for var in environment_variables if var['key'] == match), None)
            if variable is not None:
                body = body.replace("{{" + match + "}}", variable['value'])

        return body

    def is_entry_unique(self, entry):
        environment_variables = self.getUrlList()

        for item in environment_variables:
            if item['key'] == entry['key'] and item['value'] == entry['value']:
                return False
        return True

    def refresh_variables_list(self, event):
        currentList = self.getUrlList()
        self.urlList.setListData(currentList)

    def check_url(self, url):
        if re.search(self.pattern, url):
            self.logArea.append(
                '\nERROR: Request: %s was not added to the site map because of incorrect url \n' % url)
            self.callbacks.printError(
                '\nRequest: %s was not added to the site map because of incorrect url \n' % url)
            return False
        else:
            return True

    def check_test(self, request):
        for event in request.get('event', []):
            if event.get('listen') == 'test':
                script = event.get('script', {})
                if 'exec' in script:
                    return True
        return False

    def getAuthorization(self, request, data):
        auth_type = None
        auth_params = {}
        foundVariables = True

        if 'request' in request and 'auth' in request['request']:
            if request["request"]["auth"]["type"] in ["basic", "bearer"]:
                auth_type = request["request"]["auth"]["type"]
                auth_params = request["request"]["auth"][auth_type]
        else:
            auth = data["auth"]
            auth_type = auth.get("type", None)
            auth_params = auth.get("params", {})

        username = ""
        password = ""
        token = ""
        for param in auth_params:
            if param.get("key") == "username":
                username = self.replaceVariablesInAuth(param["value"])
            elif param.get("key") == "password":
                password = self.replaceVariablesInAuth(param["value"])
            if param.get("key") == "token":
                token = self.replaceVariablesInAuth(param["value"])
                break

        if '{{' in username or '{{' in password or '{{' in token:
            foundVariables = False

        if auth_type == "basic":
            return "Basic " + base64.b64encode((username + ":" + password).encode("utf-8")).decode("utf-8") \
                , foundVariables
        elif auth_type == "bearer":
            return "Bearer " + token, foundVariables
        elif auth_type in ["oauth1", "oauth1.0a"]:
            oauth_consumer_key = ""
            oauth_token = ""
            oauth_signature_method = ""
            oauth_timestamp = ""
            oauth_nonce = ""
            oauth_version = ""
            oauth_signature = ""

            for param in auth_params:
                if param.get("key") == "oauth_consumer_key":
                    oauth_consumer_key = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_token":
                    oauth_token = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_signature_method":
                    oauth_signature_method = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_timestamp":
                    oauth_timestamp = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_nonce":
                    oauth_nonce = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_version":
                    oauth_version = self.replaceVariablesInAuth(param["value"])
                elif param.get("key") == "oauth_signature":
                    oauth_signature = self.replaceVariablesInAuth(param["value"])

            oauth_header = "OAuth oauth_consumer_key=\"{}\", oauth_token=\"{}\", oauth_signature_method=\"{}\", " \
                           "oauth_timestamp=\"{}\", oauth_nonce=\"{}\", oauth_version=\"{}\", oauth_signature=\"{" \
                           "}\"".format(oauth_consumer_key, oauth_token, oauth_signature_method, oauth_timestamp,
                                        oauth_nonce, oauth_version, oauth_signature)
            return oauth_header, foundVariables
        elif auth_type == "oauth2":
            return "Bearer " + token, foundVariables
        else:
            if auth_type:
                raise ValueError("Unsupported auth type: " + auth_type)
            else:
                pass

    def replaceVariablesInAuth(self, value):
        environment_variables = self.getUrlList()
        match_pattern = r"{{.*}}"
        pattern = r"{{(.*)}}"

        if re.match(match_pattern, value):
            match = re.search(pattern, value)
            key = match.group(1)
            for var in environment_variables:
                if isinstance(var, dict) and var['key'] == key:
                    value = re.sub(value, var['value'], value)

        else:
            value = value

        return value

    def loadFile(self, event):
        chooseFile = swing.JFileChooser()
        fileDialog = chooseFile.showDialog(self.tab, "Choose file")

        if fileDialog == swing.JFileChooser.APPROVE_OPTION:
            self.file = chooseFile.getSelectedFile()
            filename = self.file.getCanonicalPath()
            fileExtension = os.path.splitext(filename)[1]

            if fileExtension == '.json':
                self.logArea.append(
                    '\nFile %s was successfully loaded \n' % filename)
            else:
                self.callbacks.printError('\nFile %s was read but does not have the correct extension (.json) \n'
                                          % filename)
                self.logArea.append(
                    '\nERROR: File %s was read but does not have the correct extension (.json) \n' % filename)

    def addToSiteMap(self, url, request, response):
        request_response = HttpRequestResponse(request, response, HttpService(url), "", "")
        self.callbacks.addToSiteMap(request_response)

    def addRequestsToSiteMap(self, event):
        thread.start_new_thread(self.getRequestsFromPostman, ())
        return

    def getTabCaption(self):
        return "Postman Importer"

    def getUiComponent(self):
        return self.tab

    def getUrlList(self):
        model = self.urlList.getModel()
        currentList = []

        for i in range(0, model.getSize()):
            currentList.append(model.getElementAt(i))

        return currentList

    def clear(self, e):
        emptyList = []
        self.urlList.setListData(emptyList)

    def remove(self, e):
        indices = self.urlList.getSelectedIndices().tolist()
        currentList = self.getUrlList()

        for index in reversed(indices):
            del currentList[index]

        self.urlList.setListData(currentList)

    def setUpJsCode(self):
        with open('jsCode.txt', 'r') as f:
            code = f.read()

        self.jsPane.setText(code)


class HttpService(IHttpService):
    def __init__(self, url):
        x = urlparse.urlparse(url)
        if x.scheme in ("http", "https"):
            self._protocol = x.scheme
        else:
            raise ValueError()
        self._host = x.hostname
        if not x.hostname:
            self._host = ""
        self._port = None
        if x.port:
            self._port = int(x.port)
        if not self._port:
            if self._protocol == "http":
                self._port = 80
            elif self._protocol == "https":
                self._port = 443

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def getProtocol(self):
        return self._protocol


class HttpRequestResponse(IHttpRequestResponse):

    def __init__(self, request, response, http_service, cmt, color):
        self.setRequest(request)
        self.setResponse(response)
        self.setHttpService(http_service)
        self.setHighlight(color)
        self.setComment(cmt)

    def getRequest(self):
        return self.req

    def getResponse(self):
        return self.resp

    def getHttpService(self):
        return self.serv

    def getComment(self):
        return self.cmt

    def getHighlight(self):
        return self.color

    def setHighlight(self, color):
        self.color = color

    def setComment(self, cmt):
        self.cmt = cmt

    def setHttpService(self, http_service):
        self.serv = http_service

    def setRequest(self, message):
        self.req = message

    def setResponse(self, message):
        self.resp = message
