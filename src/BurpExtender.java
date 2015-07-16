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


public class BurpExtender implements IBurpExtender, IScannerCheck {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private OutputStream output;
    private Set<String> ScannedHosts = new HashSet<String>();
    private String uuid;


    //CRLF variables
    private static final String CRLFHeader = "Burp-Verification-Header: ";
    private static final Pattern CRLFPattern = Pattern.compile("\\n\\s*" + CRLFHeader);
    private static final List<String> CRLFSplitters = new ArrayList<String>();
    private static List<String> DirbExtensions = new ArrayList<String>();
    private static String dirbRequest = "GET %s HTTP/1.1\nHOST: %s\n\n";
    private Set<String> scannedURLS = new HashSet<String>();
    private HashMap<String, Boolean> custom404 = new HashMap<String, Boolean>();


    private static String CRLFDescription = "";


    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)  {
        this.callbacks = callbacks;

        this.helpers = callbacks.getHelpers();
        this.output = callbacks.getStdout();


        callbacks.setExtensionName("Burp enforcer");
        callbacks.registerScannerCheck(BurpExtender.this);
        println("Burp enforcer 0.2");

        initCRLFSplitters();
        initDirBuster();


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
