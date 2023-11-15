package pii.finder.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.Scanner;

public class Main implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("PII Finder");

        Logging logging = api.logging();
        Scanner scanner = api.scanner();

        logging.logToOutput("Extension Started");

        scanner.registerScanCheck(new PIIFinderScanner(api));
    }
}