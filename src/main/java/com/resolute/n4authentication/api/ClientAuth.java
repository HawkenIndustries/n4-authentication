package com.resolute.n4authentication.api;

import com.google.common.collect.ImmutableMap;
import com.resolute.n4authentication.impl.Endpoint;
import com.resolute.n4authentication.impl.N4Parameters;

import javax.naming.AuthenticationException;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// http[s]://<username>:<password>@<host>[:<port>] [client_type]
public class ClientAuth {
    private boolean debug = false;
    private URL fqHost, loginUrl, logoutUrl, servletUrl;
    private String user;
    private String pass;
    private String session;
    private String csrf;

    private ImmutableMap<String, String> endpointProps, paramProps;

    private static final String USER_AGENT = "resolute-bi-scramsha";
    private static final String CMD_CLIENT_FIRST_MESSAGE = "sendClientFirstMessage";
    private static final String CMD_CLIENT_FINAL_MESSAGE = "sendClientFinalMessage";
    private static final Pattern CSRF_TOKEN_PATTERN = Pattern.compile("<input [^<>]*id=['\"]csrfToken['\"][^<>]*>");
    private static final Pattern VALUE_PATTERN = Pattern.compile("value=['\"]([^\"']*)['\"]");

    private ClientAuth(){}
    
    private void clientInit() {
        try {
            endpointProps = Endpoint.make().getConfigProps();
            paramProps = N4Parameters.make().getConfigProps();
            
            String url = endpointProps.get("scheme") +
                         "://"                       +
                         endpointProps.get("user")   +
                         ":"                         +
                         endpointProps.get("pass")   +
                         "@"                         +
                         endpointProps.get("host")   +
                         ":"                         +
                         endpointProps.get("port");

            fqHost = new URL(url);

            URL loginUrl = new URL(fqHost.getProtocol(), fqHost.getHost(),
                    fqHost.getPort() == -1 ? fqHost.getDefaultPort() : fqHost.getPort(),
                    "/" + paramProps.get("loginServlet") + "/");

            URL logoutUrl = new URL(fqHost.getProtocol(),
                    fqHost.getHost(),
                    fqHost.getPort() == -1 ? fqHost.getDefaultPort() : fqHost.getPort(),
                    "/" + paramProps.get("logoutServlet"));

            URL servletUrl = new URL(fqHost.getProtocol(), fqHost.getHost(),
                    fqHost.getPort() == -1 ? fqHost.getDefaultPort() : fqHost.getPort(),
                    "/" + endpointProps.get("servletUrl") + "/");

            String[] userInfo = fqHost.getUserInfo().split(":");
            if (userInfo.length != 2)
            {
                log("FATAL: invalid <username>:<password> combination provided!\n");
            }

            String user = URLDecoder.decode(userInfo[0], "UTF-8");
            String pass = URLDecoder.decode(userInfo[1], "UTF-8");

            log("username : " + user);
            log("password : " + pass);
            log("loginUrl : " + loginUrl);
            log("logoutUrl : " + logoutUrl);
            log("servletUrl: " +  servletUrl);

            this.user = user;
            this.pass = pass;
            this.loginUrl = loginUrl;
            this.logoutUrl = logoutUrl;
            this.servletUrl = servletUrl;

        } catch (MalformedURLException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public String login() throws Exception {

        clientInit();

        try{
            ScramSha256Client scramClient = new ScramSha256Client(user, pass);

            // client-first-message
            String clientFirstMessage = scramClient.createClientFirstMessage();

            // server-first-message
            String message = "clientFirstMessage="+clientFirstMessage;
            String serverFirstMessage = sendScramMessage(CMD_CLIENT_FIRST_MESSAGE, message);

            // client-final-message
            String clientFinalMessage = scramClient.createClientFinalMessage(serverFirstMessage);

            // server-final-message
            message = "clientFinalMessage="+clientFinalMessage;
            String serverFinalMessage = sendScramMessage(CMD_CLIENT_FINAL_MESSAGE, message);

            // validate
            scramClient.processServerFinalMessage(serverFinalMessage);

            sendGetRequest(loginUrl);

            sendPostRequest(servletUrl, session);

        }catch(Exception e){
            if(debug) e.printStackTrace();
            throw new AuthenticationException();
        }
        return session;
    }

    public void logout() throws Exception
    {
        String url = logoutUrl.toString();
        if (csrf != null)
        {
            url = url + "?csrfToken=" + csrf;
        }
        sendGetRequest(new URL(url));
    }

    private void sendGetRequest(URL url) throws Exception
    {
        HttpURLConnection connection = null;

        try
        {
            connection = (HttpURLConnection) url.openConnection();

            if (connection instanceof HttpsURLConnection) TrustModifier.relaxHostChecking((HttpsURLConnection) connection);

            connection.setDoInput(true);

            connection.addRequestProperty("Cookie", paramProps.get("userCookie") + "=" + user);
            if (session != null)
                connection.addRequestProperty("Cookie", paramProps.get("sessionCookie") + "=" + session);
            connection.connect();
            InputStream in = connection.getInputStream();

            StringBuilder builder = new StringBuilder();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null)
            {
                builder.append(line + "\n");
            }

            String response = builder.toString();
            Matcher match = CSRF_TOKEN_PATTERN.matcher(response);
            if (match.find())
            {
                String csrfTokenElement = match.group(0);
                match = VALUE_PATTERN.matcher(csrfTokenElement);
                if (match.find() && match.groupCount() >= 1)
                {
                    csrf = match.group(1);
                }
            }
        }
        finally
        {
            if (connection != null)
                connection.disconnect();
        }
    }

    private void sendPostRequest(URL url, String sess) throws Exception {
        log("url=" + url.toString());
        HttpURLConnection connection = null;

        try{
            connection = (HttpURLConnection) url.openConnection();
            if(connection instanceof HttpsURLConnection) TrustModifier.relaxHostChecking(connection);

            String postContent = "[" +
                    "{\"name\":\"/BoolPoint\", \"value\":\"true\", \"dataType\":\"b\", \"action\":\"disable\"}," +
                    "{\"name\":\"/NumPoint\", \"value\":\"11.443\", \"dataType\":\"n\", \"action\":\"disable\"}" +
                    "]";

            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.addRequestProperty("Cookie", paramProps.get("userCookie") + "=" + user);
            connection.addRequestProperty("Content-Type", "application/json");
            connection.addRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Length", Integer.toString(postContent.length()));

            if (session != null) {
                log( "session: " + paramProps.get("sessionCookie") + "=" + session );
                log( "session: " + paramProps.get("sessionCookie") + "=" + sess );
                log("user: " + paramProps.get("userCookie") + "=" + user);

                connection.addRequestProperty("Cookie", paramProps.get("sessionCookie") + "=" + sess);
                connection.addRequestProperty("Cookie", paramProps.get("userCookie") + "=" + user);
//                 session = "f5329197aa428a4845ced02a925f8854d3db3549fcf8007a17";
//                connection.addRequestProperty("Cookie", "niagara_userid=resolute");
            }

            connection.connect();

            OutputStream out = connection.getOutputStream();
            out.write(postContent.getBytes());
            out.flush();

            log("connection status: " + connection.getResponseCode());
            log("connection message: " +  connection.getResponseMessage());
            InputStream in = connection.getInputStream();
            if( in != null){
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                StringBuilder sb = new StringBuilder();
                String input;
                while((input = reader.readLine()) != null){
                    sb.append(input);
                }
                log(sb.toString());
            }else{
                log("null servlet response...");
            }

        }catch(Exception e){
            log("Failed Post in client authenticator...!");
            e.printStackTrace();
        }
    }

    private String sendScramMessage(String command, String message)
            throws Exception
    {
        HttpURLConnection connection = null;

        try
        {
            String serverMessage = null;

            connection = (HttpURLConnection) loginUrl.openConnection();

            if (connection instanceof HttpsURLConnection) TrustModifier.relaxHostChecking((HttpsURLConnection) connection);

            String request = "action=" + command + "&" + message;

            connection.setDoOutput(true);
            connection.setRequestMethod("POST");

            connection.setRequestProperty("User-Agent", USER_AGENT);

            // these header fields are REQUIRED
            connection.setRequestProperty("Content-Type", "application/x-niagara-login-support");
            connection.setRequestProperty("Content-Length", Integer.toString(request.length()));
            connection.addRequestProperty("Cookie", paramProps.get("userCookie") + "=" + user);

            // make sure you save the session for subsequent requests for the same session
            if (session != null)
                connection.addRequestProperty("Cookie", paramProps.get("sessionCookie") + "=" + session);

            // Make the POST request
            OutputStream out = connection.getOutputStream();
            //#ifdef DEBUG
            log("sending request to server: " + request);
            //#endif
            out.write(request.getBytes());
            out.flush();

            // Set the session Cookie we got from the server
            // make sure you save the session for subsequent requests for the same session
            String cookie = connection.getHeaderField("Set-Cookie");
            if (cookie != null && cookie.startsWith(paramProps.get("sessionCookie")))
            {
                session = (cookie.split(";"))[0].trim();
                session = session.split("=")[1];
                System.out.println("*** sessionId: " + session);
            }

            int status = connection.getResponseCode();

            log("status code from the remote server = " + status);

            if (status != HttpURLConnection.HTTP_OK)
                throw new AuthenticationException();

            InputStream in = connection.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in));
            serverMessage = reader.readLine();

            return serverMessage;
        }
        finally
        {
            if (connection != null)
                connection.disconnect();
        }
    }

    public void setDebug(boolean d){
        debug = d;
    }

    private void log(String msg){
        if(debug){
            System.out.println(msg);
        }
    }

    public static ClientAuth make(){ return new ClientAuth(); }
}
