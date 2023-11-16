package pii.finder.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.http.Http;


public class Main implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("PII Finder");

        Logging logging = api.logging();
        Scanner scanner = api.scanner();
        Http httpHandler = api.http();

        logging.logToOutput("Extension Started");

        httpHandler.registerHttpHandler(new PIIFinderHTTPHandler(api));
        scanner.registerScanCheck(new PIIFinderScanner(api));
    }
}