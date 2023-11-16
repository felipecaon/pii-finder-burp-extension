package pii.finder.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

public class PIIFinderHTTPHandler implements HttpHandler{

    private final MontoyaApi api;

    PIIFinderHTTPHandler(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return requestToBeSent.hasHeader("If-None-Match")
            ? RequestToBeSentAction.continueWith(requestToBeSent.withRemovedHeader("If-None-Match"))
            : RequestToBeSentAction.continueWith(requestToBeSent);
    }
    

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return null;
    }
    
}
