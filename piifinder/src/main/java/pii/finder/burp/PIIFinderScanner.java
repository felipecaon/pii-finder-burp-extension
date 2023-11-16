package pii.finder.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PIIFinderScanner implements ScanCheck{

    private final MontoyaApi api;

    PIIFinderScanner(MontoyaApi api)
    {
        this.api = api;
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        throw new UnsupportedOperationException("Unimplemented method 'activeAudit'");
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {

        List<AuditIssue> auditIssueList = new ArrayList<>();
        try {

            ObjectMapper objectMapper = new ObjectMapper();
            InputStream inputStream = PIIFinderScanner.class.getClassLoader().getResourceAsStream("pii/finder/burp/rules.json");

            if (inputStream == null) {
                api.logging().logToOutput("File not found");
            }

            JsonNode rootNode = objectMapper.readTree(inputStream);

            for (JsonNode ruleNode : rootNode) {
                String name = ruleNode.get("name").asText();

                if (ruleNode.has("keywords")) {
                    JsonNode keywordsNode = ruleNode.get("keywords");
                    Iterator<JsonNode> keywordsIterator = keywordsNode.elements();

                    while (keywordsIterator.hasNext()) {
                        String keyword = keywordsIterator.next().asText();

                        List<Marker> responseHighlights = matchKeyword(baseRequestResponse, keyword);

                        if (!responseHighlights.isEmpty()){

                            AuditIssue newAuditIssue = auditIssue(
                                "Possible PII Detected",
                                "The response contains the string: " + keyword,
                                null,
                                baseRequestResponse.request().url(),
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.TENTATIVE,
                                null,
                                null,
                                AuditIssueSeverity.HIGH,
                                baseRequestResponse.withResponseMarkers(responseHighlights)
                            );

                            auditIssueList.add(newAuditIssue);
                        }
                    }
                }

                if (ruleNode.has("regex")) {
                    String regexPattern = ruleNode.get("regex").asText();
                    Pattern pattern = Pattern.compile(regexPattern);
                    Matcher matcher = pattern.matcher(baseRequestResponse.response().toString());

                    while (matcher.find()) {

                        List<Marker> responseHighlights = matchKeyword(baseRequestResponse, matcher.group());

                        if (!responseHighlights.isEmpty()){

                            AuditIssue newAuditIssue = auditIssue(
                                "PII Detected",
                                "The response contains a string that matched with the regex: " + name,
                                null,
                                baseRequestResponse.request().url(),
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.CERTAIN,
                                null,
                                null,
                                AuditIssueSeverity.HIGH,
                                baseRequestResponse.withResponseMarkers(responseHighlights)
                            );

                            auditIssueList.add(newAuditIssue);
                        }
                    }
                }
            }

        } catch (IOException e) {
            api.logging().logToOutput(e.getMessage());
        }
       
        return auditResult(auditIssueList);
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        return existingIssue.name().equals(newIssue.name()) ? KEEP_EXISTING : KEEP_BOTH;
    }

    private static List<Marker> matchKeyword(HttpRequestResponse requestResponse, String match)
    {
        List<Marker> highlights = new LinkedList<>();
        String response = requestResponse.response().toString();

        int start = 0;

        while (start < response.length())
        {
            start = response.indexOf(match, start);

            if (start == -1)
            {
                break;
            }

            Marker marker = Marker.marker(start, start+match.length());
            highlights.add(marker);

            start += match.length();
        }

        return highlights;
    }

}
