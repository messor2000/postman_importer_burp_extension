import requests
import re
from java.net import URL
from javax import swing
from java.awt import Font
import thread
from burp import IBurpExtender, IExtensionStateListener, ITab

try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.callbacks.setExtensionName("Postman Importer")
        self.callbacks.registerExtensionStateListener(self)
        self.helpers = callbacks.getHelpers()

        self.initGui()
        self.callbacks.addSuiteTab(self)
        print("Extension Loaded")

    def initGui(self):
        self.tab = swing.JPanel()
        self.titleLabel = swing.JLabel("Postman Importer")
        self.titleLabel.setFont(Font("Tahoma", 1, 17))
        self.infoLabel1 = swing.JLabel(
            "To get necessary tokens from postman you need to import, you should follow these steps: ")
        self.infoLabel2 = swing.JLabel(
            "1. Select collection you want to import, Go Share -> Via API.")
        self.infoLabel3 = swing.JLabel(
            "Copy first long value which is you collection id and copy your access token which you should generate.")
        self.infoLabel4 = swing.JLabel(
            "Put them to the fields and push the button to import all requests from the collection to the site map.")
        self.infoLabel5 = swing.JLabel(
            "Put your Postman collection id which you want add to the site map")
        self.infoLabel51 = swing.JLabel(
            "Example: 25184041-c1537769-f598-4c0e-b8ae-8cd185a79c00")
        self.collectionIdField = swing.JTextField()
        self.infoLabel6 = swing.JLabel("Put your Postman access token")
        self.infoLabel61 = swing.JLabel("Example: PMAT-01GP39X3DRS6A8A0FG1S9BTDF2")
        self.accessTokenField = swing.JTextField()
        self.addButton = swing.JButton("Add requests to site map", actionPerformed=self.addRequestsToSiteMap)
        self.infoLabel7 = swing.JLabel(
            "NOTE: If you add new requests from another collection, but their will be duplicat, they will be "
            "overwritten")
        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)

        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                      .addGap(15)
                      .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                .addComponent(self.titleLabel)
                                .addComponent(self.infoLabel1)
                                .addComponent(self.infoLabel2)
                                .addComponent(self.infoLabel3)
                                .addComponent(self.infoLabel4)
                                .addComponent(self.infoLabel5)
                                .addComponent(self.infoLabel51)
                                .addComponent(self.collectionIdField, swing.GroupLayout.PREFERRED_SIZE, 300,
                                              swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.infoLabel6)
                                .addComponent(self.infoLabel61)
                                .addComponent(self.accessTokenField, swing.GroupLayout.PREFERRED_SIZE, 300,
                                              swing.GroupLayout.PREFERRED_SIZE)
                                .addComponent(self.addButton)
                                .addComponent(self.infoLabel7))))

        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                      .addGap(15)
                      .addComponent(self.titleLabel)
                      .addGap(10)
                      .addComponent(self.infoLabel1)
                      .addComponent(self.infoLabel2)
                      .addComponent(self.infoLabel3)
                      .addComponent(self.infoLabel4)
                      .addGap(10)
                      .addComponent(self.infoLabel5)
                      .addComponent(self.infoLabel51)
                      .addGap(15)
                      .addComponent(self.collectionIdField, swing.GroupLayout.PREFERRED_SIZE, 30,
                                    swing.GroupLayout.PREFERRED_SIZE)
                      .addGap(10)
                      .addComponent(self.infoLabel6)
                      .addComponent(self.infoLabel61)
                      .addGap(10)
                      .addComponent(self.accessTokenField, swing.GroupLayout.PREFERRED_SIZE, 30,
                                    swing.GroupLayout.PREFERRED_SIZE)
                      .addGap(10)
                      .addComponent(self.addButton)
                      .addGap(15)
                      .addComponent(self.infoLabel7)))
        return

    def getRequestsFromPostman(self):
        collectionId = self.collectionIdField.getText()
        accessToken = self.accessTokenField.getText()

        self.checkInputData(collectionId, accessToken)

        postman_api_endpoint = "https://api.getpostman.com/collections"
        headers = {"access_key": accessToken}

        # Get all requests from Postman collection
        response = requests.get("{}/{}".format(postman_api_endpoint, collectionId), headers)
        requests_data = response.json().get("collection", {}).get("item", [])

        # Add requests to Burp sitemap
        for request_data in requests_data:
            request_url = request_data["request"]["url"]["raw"]

            url = URL(request_url)
            host = url.getHost()
            port = url.getPort()
            protocol = url.getProtocol()

            if port == -1:
                if protocol == "http":
                    port = 80
                elif protocol == "https":
                    port = 443

            newRequest = self.helpers.buildHttpRequest(url)
            requestResponse = self.callbacks.makeHttpRequest(
                self.helpers.buildHttpService(host, port, protocol), newRequest)

            response = requestResponse.getResponse()
            if response:
                self.callbacks.addToSiteMap(requestResponse)

    def addRequestsToSiteMap(self, event):
        thread.start_new_thread(self.getRequestsFromPostman, ())
        return

    def getTabCaption(self):
        return "Postman Importer"

    def getUiComponent(self):
        return self.tab

    def checkInputData(self, collectionId, accessToken):
        collectionIdRegex = r'[0-9a-f]{8}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        accessTokenRegex = r'PMAT-[0-9A-Z]{26}'

        if re.search(collectionIdRegex, collectionId) is None:
            self.callbacks.printError("Your collection id is wrong: " + collectionId +
                                      ". Must be like: 25184041-c1537769-f598-4c0e-b8ae-8cd185a79c03")

        if re.search(accessTokenRegex, accessToken) is None:
            self.callbacks.printError("Your access token is wrong: " + accessToken +
                                      ". Must be like: PMAT-01GP39X3DRS6A8A0FG1S9BTDF2")
