/**
 * Created by Virvales on 20/06/15.
 */
package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.*;
import java.util.concurrent.Exchanger;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, IScannerCheck, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private Set<String> ScannedHosts = new HashSet<String>();
    private String uuid;


    private static final Pattern PHP_ON_LINE = Pattern.compile("\\.php on line [0-9]+");
    private static final Pattern PHP_FATAL_ERROR = Pattern.compile("Fatal error:");
    private static final Pattern PHP_LINE_NUMBER = Pattern.compile("\\.php:[0-9]+");
    private static final Pattern MSSQL_ERROR = Pattern.compile("\\[(ODBC SQL Server Driver|SQL Server)\\]");
    private static final Pattern MYSQL_SYNTAX_ERROR = Pattern.compile("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near");
    private static final Pattern JAVA_LINE_NUMBER = Pattern.compile("\\.java:[0-9]+");
    private static final Pattern JAVA_COMPILED_CODE = Pattern.compile("\\.java\\((Inlined )?Compiled Code\\)");
    private static final Pattern ASP_STACK_TRACE = Pattern.compile("[A-Za-z\\.]+\\(([A-Za-z0-9, ]+)?\\) \\+[0-9]+");
    private static final Pattern PERL_STACK_TRACE = Pattern.compile("at (\\/[A-Za-z0-9\\.]+)*\\.pm line [0-9]+");
    private static final Pattern PYTHON_STACK_TRACE = Pattern.compile("File \"[A-Za-z0-9\\-_\\./]*\", line [0-9]+, in");
    private static final Pattern ASP_NET = Pattern.compile("in [^\\s]\\.cs:[0-9]+");
    private static final Pattern RUBY = Pattern.compile("\\.rb:[0-9 ]+:in ");
    private static final Pattern NODEJS = Pattern.compile("[\\w\\/]+\\.js:[0-9]+:[0-9]+");
    private static final Pattern ORA = Pattern.compile("ORA-[0-9]{4,}");

    //CRLF variables
    private static final String CRLFHeader = "Burp-Verification-Header: ";
    private static final Pattern CRLFPattern = Pattern.compile("\\n\\s*" + CRLFHeader);
    private static final List<String> CRLFSplitters = new ArrayList<String>();
    private static List<String> DirbExtensions = new ArrayList<String>();
    private static String dirbRequest = "GET %s HTTP/1.1\nHOST: %s\n\n";
    private Set<String> scannedURLS = new HashSet<String>();
    private HashMap<String, Boolean> custom404 = new HashMap<String, Boolean>();
    private Set<String> FoundTracebacks = new HashSet<String>();
    private static final List<MatchRule> rules = new ArrayList();




    private static String CRLFDescription = "";


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)  {
        this.callbacks = callbacks;

        this.helpers = callbacks.getHelpers();
        this.output = callbacks.getStdout();


        callbacks.setExtensionName("Burp enforcer");
        callbacks.registerScannerCheck(BurpExtender.this);
        callbacks.registerHttpListener(BurpExtender.this);
        println("Burp enforcer 0.3");

        initCRLFSplitters();
        initDirBuster();
        applyRules();

        CRLFDescription = "HTTP response splitting occurs when:<br/><ul>" +
                "<li>Data enters a web application through an untrusted source, most frequently an HTTP request.</li>\n" +
                "<li>The data is included in an HTTP response header sent to a web user without being validated for malicious characters.</li></ul>\n" +
                "HTTP response splitting is a means to an end, not an end in itself. At its root, the attack is straightforward: \n" +
                "an attacker passes malicious data to a vulnerable application, and the application includes the data in an HTTP response header.<br/><br/>\n" +
                "To mount a successful exploit, the application must allow input that contains CR (carriage return, also given by %0d or \\r) \n" +
                "and LF (line feed, also given by %0a or \\n)characters into the header AND the underlying platform must be vulnerable to the injection\n" +
                "of such characters. These characters not only give attackers control of the remaining headers and body of the response the application intends"+
                "to send, but also allow them to create additional responses entirely under their control.<br/><br/>\n" +
                "The example below uses a Java example, but this issue has been fixed in virtually all modern Java EE application servers." +
                "If you are concerned about this risk, you should test on the platform of concern to see if the underlying platform allows for CR or LF characters"+
                "to be injected into headers. We suspect that, in general, this vulnerability has been fixed in most modern application servers, regardless of what language the code has been written in.";

    }

    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        String scanDomain = baseRequestResponse.getHttpService().getHost();
        doLog(scanDomain);
        List<IScanIssue> results = new ArrayList<IScanIssue>();
        checkResult res = doCRLF(baseRequestResponse, insertionPoint);
        if (res!=null)
        {
            IHttpRequestResponse attack = res.getAttack();
            results.add(new CustomScanIssue(attack.getHttpService(),
                    this.helpers.analyzeRequest(attack).getUrl(),
                    new IHttpRequestResponse[]{attack},
                    "HTTP Response Splitting",
                    "Vulnerability detected by <b>BurpEnforcer</b> <br/><br/>" + res.getAttackDetails(),
                    CRLFDescription, res.getPriority(), "Firm"));
        }

        //just do 4096 "A" as payload, hoping application to crash and provide some usefull information. You'd better install
        //some plugin for stacktrace's catching.
        doAAA(baseRequestResponse, insertionPoint);

        URL domainUrl = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String domain = domainUrl.getProtocol() + "://" + domainUrl.getHost() + ":" +
                ((domainUrl.getPort() == -1) ? Integer.toString(domainUrl.getDefaultPort()):Integer.toString(domainUrl.getPort()));
        if (!custom404.containsKey(domain)){
            custom404.put(domain,detectCustom404(baseRequestResponse, domainUrl.getHost()));
            //println("custom404 contains:");
            //println(custom404.toString());
        }

        if (custom404.get(domain) == false)  {
            res = doDirbuster(baseRequestResponse);
            if (res!=null)
            {
                IHttpRequestResponse attack = res.getAttack();
                results.add(new CustomScanIssue(attack.getHttpService(),
                        this.helpers.analyzeRequest(attack).getUrl(),
                        new IHttpRequestResponse[]{attack},
                        "Temporary file",
                        "Vulnerability detected by <b>BurpEnforcer</b> <br/><br/>" + res.getAttackDetails(),
                        CRLFDescription, res.getPriority(), "Firm"));
            }

        }
        return results;
    }

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse){
        return null;
    }


    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        return 0;
    }


    public checkResult doCRLF(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint){

        String uuid = UUID.randomUUID().toString().replaceAll("-", "");

        IHttpService httpService = baseRequestResponse.getHttpService();
        IHttpRequestResponse checkUUID = this.callbacks.makeHttpRequest(httpService,
                insertionPoint.buildRequest(this.helpers.stringToBytes(uuid)));

        String respHeaders = String.join("\n", this.helpers.analyzeResponse(checkUUID.getResponse()).getHeaders());


        if (respHeaders.contains(uuid)) {
            for (String payload: CRLFSplitters) {
                String finalPayload = new StringBuffer().append(uuid.substring(0,5))
                        .append(payload)
                        .append(CRLFHeader)
                        .append(uuid.substring(6))
                        .toString();

                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(httpService,
                        insertionPoint.buildRequest(this.helpers.stringToBytes(finalPayload)));

                String respAttackHeaders = String.join("\n",this.helpers.analyzeResponse(attack.getResponse()).getHeaders());

                Matcher m = CRLFPattern.matcher(respAttackHeaders);

                if (m.find() ){
                    String body = this.helpers.bytesToString(attack.getResponse());

                    List requestMarkers = new ArrayList(1);
                    requestMarkers.add(insertionPoint.getPayloadOffsets(this.helpers.stringToBytes(finalPayload)));
                    List responseMarkers = new ArrayList(1);
                    //println(Integer.toString(body.indexOf(CRLFHeader)));
                    //println(Integer.toString(body.indexOf(CRLFHeader)+CRLFHeader.length()));
                    responseMarkers.add(new int[]{body.indexOf(CRLFHeader), body.indexOf(CRLFHeader)+CRLFHeader.length() });


                    String attackDetails = "Vulnerability detected at <b>" + insertionPoint.getInsertionPointName() + "</b>, " +
                            "payload was set to <b>" + this.helpers.urlEncode(finalPayload) + "</b><br/>" +
                            "Found response: " + m.group();
                    return new checkResult(true,
                            finalPayload,
                            this.callbacks.applyMarkers(attack,requestMarkers,responseMarkers),
                            "High",
                            attackDetails);
                }
            }
        }
        return null;
    }

    public Boolean detectCustom404(IHttpRequestResponse baseRequestResponse, String domain) {
        String req = String.format("GET /No-way-it-can-be-here-such-file HTTP/1.1\nHOST: %s\n\n", domain);
        IHttpRequestResponse attack = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), this.helpers.stringToBytes(req));
        short code = this.helpers.analyzeResponse(attack.getResponse()).getStatusCode();
        return (code != 404);
    }

    public checkResult doDirbuster(IHttpRequestResponse baseRequestResponse)  {
        String scanDomain = baseRequestResponse.getHttpService().getHost();
        URL domainUrl = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String fullURL = domainUrl.getProtocol() + "://" + domainUrl.getHost() + ":" +
                ((domainUrl.getPort() == -1) ? Integer.toString(domainUrl.getDefaultPort()):Integer.toString(domainUrl.getPort())) +
                domainUrl.getPath();
        if (!scannedURLS.contains(fullURL)) {
            scannedURLS.add(fullURL);
            String path = domainUrl.getPath();

            for (String extension : DirbExtensions) {
                byte[] req = this.helpers.stringToBytes(String.format(this.dirbRequest, path + extension, scanDomain));
                IHttpRequestResponse attack = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req);
                IResponseInfo resp = this.helpers.analyzeResponse(attack.getResponse());
                if (resp.getStatusCode() != 404){
                    List<String> headers = resp.getHeaders();
                    for (String oneHeader: headers){
                        if (oneHeader.startsWith("Content-Length:")){
                            Integer contLength = Integer.parseInt(oneHeader.split(":")[1].trim());
                            if (contLength > 1000)
                            {
                                String attackDetails = "Detected temporary file <b>" + path + extension + "</b>";
                                return new checkResult(true,
                                    "",
                                    attack,
                                    "High",
                                    attackDetails);
                            }
                        }
                    }
                }
            }
        }
    return null;
    }

    public void doAAA(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < 4096; i++){
            sb.append("A");
        }

        String payload = sb.toString();
        byte[] req = insertionPoint.buildRequest(this.helpers.stringToBytes(payload));
        IHttpRequestResponse attack = this.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req);
        byte[] resp = attack.getResponse();

    }

    public void doLog(String scanHost){
        if (!ScannedHosts.contains(scanHost)){
            ScannedHosts.add(scanHost);
            println("Scanning website " + scanHost);
            IHttpChecker.checkRequest(scanHost, uuid, "domain");
        }
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        ArrayList<ScannerMatch> matches = new ArrayList<ScannerMatch>();
        URL url = this.helpers.analyzeRequest(messageInfo).getUrl();
        String urlAddress = url.getProtocol() + "://" + url.getHost() + ":" +
                ((url.getPort() == -1) ? Integer.toString(url.getDefaultPort()):Integer.toString(url.getPort())) +
                url.getPath();
        if (FoundTracebacks.contains(urlAddress))
        {
            return;
        }

        if (this.callbacks.isInScope(url)){
            if (!messageIsRequest) {
                //URL url = this.helpers.analyzeRequest(messageInfo).getUrl();
                if (this.callbacks.isInScope(url)) {
                    IResponseInfo response = this.helpers.analyzeResponse(messageInfo.getResponse());
                    if (response.getStatusCode() == 404 || response.getStatusCode() == 302 || response.getStatusCode() == 301) {
                        return;
                    }
                    String raw_response = BurpExtender.this.helpers.bytesToString(messageInfo.getResponse());

                    for (MatchRule rule : rules) {
                        Matcher matcher = rule.getPattern().matcher(raw_response);
                        while (matcher.find()) {
                            println(new StringBuilder().append("FOUND ").append(rule.getType()).append("!").toString());
                            String group;
                            if (rule.getMatchGroup() != null)
                                group = matcher.group(rule.getMatchGroup().intValue());
                            else {
                                group = matcher.group();
                            }

                            println(new StringBuilder().append("start: ").append(matcher.start()).append(" end: ").append(matcher.end()).append(" group: ").append(group).toString());

                            matches.add(new ScannerMatch(matcher.start(), matcher.end(), group, rule.getType()));
                        }

                    }

                    if (!matches.isEmpty()) {
                        //Collections.sort(matches);

                        ScannerMatch firstMatch = (ScannerMatch)matches.get(0);
                        StringBuilder description = new StringBuilder(matches.size() * 256);
                        description.append("The application displays detailed error messages when unhandled <b>").append(firstMatch.getType()).append("</b> exceptions occur.<br>");
                        description.append("Stacktrace is - <b>").append(firstMatch.getMatch()).append("</b>");
                        StringBuilder background = new StringBuilder();
                        background.append("Stack traces are not vulnerabilities by themselves, but they often reveal information that is interesting to an attacker. Attackers attempt to generate these stack traces by tampering with the input to the web application with malformed HTTP requests and other input data.<br/>");
                        background.append("If the application responds with stack traces that are not managed it could reveal information useful to attackers. This information could then be used in further attacks. Providing debugging information as a result of operations that generate errors is considered a bad practice due to multiple reasons. For example, it may contain information on internal workings of the application such as relative paths of the point where the application is installed or how objects are referenced internally. ");

                        List startStop = new ArrayList(1);
                        for (ScannerMatch match : matches) {
                            println(new StringBuilder().append("Processing match: ").append(match).toString());
                            println(new StringBuilder().append("    start: ").append(match.getStart()).append(" end: ").append(match.getEnd()).append(" match: ").append(match.getMatch()).append(" match: ").append(match.getMatch()).toString());

                            startStop.add(new int[] { match.getStart(), match.getEnd() });
                        }

                        println(new StringBuilder().append("    Description: ").append(description.toString()).toString());

                        callbacks.addScanIssue(new CustomScanIssue(messageInfo.getHttpService(),
                                this.helpers.analyzeRequest(messageInfo).getUrl(),
                                new IHttpRequestResponse[]{this.callbacks.applyMarkers(messageInfo, null, startStop)},
                                "Detailed Error Messages Revealed",
                                description.toString(),
                                background.toString(),
                                "Medium", "Firm"));
                        FoundTracebacks.add(urlAddress);
                        return ;
                    }
                }

            }
        }

    }

    public void initDirBuster()
    {
        DirbExtensions.add("-");
        DirbExtensions.add(".1");
        DirbExtensions.add(".2");
        DirbExtensions.add(".3");
        DirbExtensions.add(".bac");
        DirbExtensions.add(".backup");
        DirbExtensions.add(".orig");
        DirbExtensions.add(".vb");
        DirbExtensions.add(".part");
        DirbExtensions.add(".rej");
        DirbExtensions.add(".sav");
        DirbExtensions.add(".save");
        DirbExtensions.add(".save.1");
        DirbExtensions.add(".bak");
        DirbExtensions.add(".cache");
        DirbExtensions.add(".cs");
        DirbExtensions.add(".csproj");
        DirbExtensions.add(".dif");
        DirbExtensions.add(".err");
        DirbExtensions.add(".gz");
        DirbExtensions.add(".inc");
        DirbExtensions.add(".ini");
        DirbExtensions.add(".java");
        DirbExtensions.add(".log");
        DirbExtensions.add(".old");
        DirbExtensions.add(".sublime-workspace");
        DirbExtensions.add(".swp");
        DirbExtensions.add(".tar");
        DirbExtensions.add(".tar.gz");
        DirbExtensions.add(".temp");
        DirbExtensions.add(".tmp");
        DirbExtensions.add(".txt");
        DirbExtensions.add(".un~");
        DirbExtensions.add(".vi");
        DirbExtensions.add(".zip");
        DirbExtensions.add("0");
        DirbExtensions.add("1");
        DirbExtensions.add("2");
        DirbExtensions.add("dist");
        DirbExtensions.add("~");
    }

    public void initCRLFSplitters()
    {
        byte[] CDRIVES = new byte[] {(byte)0xE5, (byte)0x98, (byte)0x8A, (byte)0xE5, (byte)0x98, (byte)0x8D, };
        CRLFSplitters.add(this.helpers.bytesToString(CDRIVES));
        CRLFSplitters.add("\r\n");
        CRLFSplitters.add("\r ");
        CRLFSplitters.add("\r\t");
        CRLFSplitters.add("\r\n ");
        CRLFSplitters.add("\r\n\t");
    }


    private void applyRules()
    {
        rules.add(new MatchRule(PHP_ON_LINE, Integer.valueOf(0), "PHP"));
        rules.add(new MatchRule(PHP_FATAL_ERROR, Integer.valueOf(0), "PHP"));
        rules.add(new MatchRule(PHP_LINE_NUMBER, Integer.valueOf(0), "PHP"));
        rules.add(new MatchRule(MSSQL_ERROR, Integer.valueOf(0), "Microsoft SQL Server"));
        rules.add(new MatchRule(MYSQL_SYNTAX_ERROR, Integer.valueOf(0), "MySQL"));
        rules.add(new MatchRule(JAVA_LINE_NUMBER, Integer.valueOf(0), "Java"));
        rules.add(new MatchRule(JAVA_COMPILED_CODE, Integer.valueOf(0), "Java"));
        rules.add(new MatchRule(ASP_STACK_TRACE, Integer.valueOf(0), "ASP.Net"));
        rules.add(new MatchRule(PERL_STACK_TRACE, Integer.valueOf(0), "Perl"));
        rules.add(new MatchRule(PYTHON_STACK_TRACE, Integer.valueOf(0), "Python"));
        rules.add(new MatchRule(ASP_NET, Integer.valueOf(0), "ASPNET"));
        rules.add(new MatchRule(RUBY, Integer.valueOf(0), "RUBY"));
        rules.add(new MatchRule(NODEJS, Integer.valueOf(0), "NODEJS"));
        rules.add(new MatchRule(ORA, Integer.valueOf(0), "Oracle DB"));
    }


    private void println(String toPrint) {
        try {
            this.output.write(toPrint.getBytes());
            this.output.write("\n".getBytes());
            this.output.flush();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }
}
