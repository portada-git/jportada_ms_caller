package org.elsquatrecaps.portada.jportadamscaller;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.elsquatrecaps.portada.jportadamscaller.exceptions.PortadaMicroserviceCallException;
import org.json.JSONObject;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 *
 * @author josep
 */
public class PortadaMicroservicesCaller {
    public String securityPath = "security";
    public static String[] msContext = {"java", "python", "r", "docker"};
    protected Map<String, ConnectionMs> conDataList;

    
    
    protected static String signChallenge(String challenge, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(challenge.getBytes());
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    public PortadaMicroservicesCaller() {
    }
    
    public <S extends PortadaMicroservicesCaller> S  init(String securityPath) {
        this.securityPath = securityPath;
        return (S) this;
    }
    
    public <S extends PortadaMicroservicesCaller> S  init(Map<String, ConnectionMs> conDataList) {
        this.conDataList = conDataList;
        return (S) this;
    }
    
    public <S extends PortadaMicroservicesCaller> S init(Properties props){
        conDataList = new HashMap<>();
        for(String cntx: msContext){
            String port;
            String protocol;
            String host;
            String pref;
            if(props.containsKey(cntx.concat(".").concat("protocol"))){
                protocol = props.getProperty(cntx.concat(".").concat("protocol"));
            }else{
                protocol = props.getProperty("protocol");
            }
            if(props.containsKey(cntx.concat(".").concat("host"))){
                host = props.getProperty(cntx.concat(".").concat("host"));
            }else{
                host = props.getProperty("host");
            }
            if(props.containsKey(cntx.concat(".").concat("port"))){
                port = props.getProperty(cntx.concat(".").concat("port"));
            }else{
                port = props.getProperty("port");
            }
            if(props.containsKey(cntx.concat(".").concat("pref"))){
                pref = props.getProperty(cntx.concat(".").concat("pref"));
            }else{
                pref = props.getProperty("pref");
            }
            conDataList.put(cntx, new ConnectionMs(protocol, port, host, pref));
        }
        if (props.containsKey("security_path")){
            this.securityPath = props.getProperty("security_path");
        }
        return (S) this;
    }


    protected static PrivateKey loadPrivateKey(String filename) throws Exception {
        String key = new String(Files.readAllBytes(new File(filename).toPath()));
        
        // Eliminar les línies d'encapçalament i peu
        key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                 .replace("-----END PRIVATE KEY-----", "")
                 .replaceAll("\\s", ""); // Elimina espais i salts de línia

        byte[] keyBytes = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    public <T> T sendPostAsFormatParams(String command, String context, JSONObject params, Class<T> type) throws PortadaMicroserviceCallException {
        return sendPostAsFormatParams(command, context, params, null, type, true);
    }

    public <T> T sendPostAsFormatParams(String command, String context, MultiValueMap<String, Object> params, Class<T> type) throws PortadaMicroserviceCallException {
        return sendPostAsFormatParams(command, context, params, null, type, true);
    }

    public <T> T sendPostAsFormatParams(String command, String context, MultiValueMap<String, Object> params, SignedData signatureData, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException {
        return sendPostAsFormatParams(command, context, params, null, null, signatureData, type, secureRepeat);
    }

    public <T> T sendPostAsFormatParams(String command, String context, MultiValueMap<String, Object> params, String challenge, String signedChallenge, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException {
        return sendPostAsFormatParams(command, context, params, challenge, signedChallenge, null, type, secureRepeat);
    }

    private <T> T sendPostAsFormatParams(String command, String context, MultiValueMap<String, Object> params, String challenge, String signedChallenge, SignedData signatureData, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException {
        T ret = null;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }
        });
        restTemplate.setMessageConverters(Arrays.asList(new HttpMessageConverter[]{new FormHttpMessageConverter(), new StringHttpMessageConverter()}));
        String strUrl = String.format("%s://%s:%s%s%s", getProtocol(context), getHost(context), getPort(context), getPref(context), command);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (signatureData != null) {
            headers.set("X-Signature", signatureData.getSignedData());
            headers.set("Cookie", signatureData.getSessionCookie());
        }else if (challenge !=null && signedChallenge!=null){
            headers.set("X-Challenge", challenge);
            headers.set("X-Signature", signedChallenge);
        }
        HttpEntity<MultiValueMap<String, Object>> requestEntity = new HttpEntity<>(params, headers);
        ResponseEntity<T> response = restTemplate.exchange(strUrl, HttpMethod.POST, requestEntity, type);
        int responseCode = response.getStatusCode().value();
        if ((responseCode >= 200) && (responseCode < 400)) {
            ret = response.getBody();
        } else if (responseCode == 401 && secureRepeat && params.getFirst("team") != null) {
            try {
                SignedData signedData = signChallengeOfConnection(response, params.getFirst("team").toString());
                if (signedData == null) {
                    throw new PortadaMicroserviceCallException(-401, "You need generate a security key access");
                } else {
                    ret = sendPostAsFormatParams(command, context, params, signedData, type, false);
                }
            } catch (Exception exc) {
                throw new PortadaMicroserviceCallException(-100, String.format("Unexpected error: %s.\nPlease check with the person in charge.", exc.getMessage()), exc);
            }
        } else {
            String message = response.getHeaders().getFirst("X-message_error");
            if (message != null) {
                throw new PortadaMicroserviceCallException(-responseCode, String.format("Unexpected http error in server process: %s.\nPlease check with the person in charge.", message));
            } else {
                throw new PortadaMicroserviceCallException(-responseCode, "Unexpected http error.\nPlease check with the person in charge.");
            }
        }
        return ret;
    }

    public <T> T sendPostAsFormatParams(String command, String context, JSONObject params, SignedData signatureData, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException {
        return sendPostAsFormatParams(command, context, params, null, null, signatureData, type, secureRepeat);
    }
    
    public <T> T sendPostAsFormatParams(String command, String context, JSONObject params, String challenge, String signedChallenge, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException {
        return sendPostAsFormatParams(command, context, params, challenge, signedChallenge, null, type, secureRepeat);
    }
        
    private <T> T sendPostAsFormatParams(String command, String context, JSONObject params, String challenge, String signedChallenge, SignedData signatureData, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException {
        T ret;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }
        });
        System.out.println("CTX: ".concat(context));
        String strUrl = String.format("%s://%s:%s%s%s", getProtocol(context), getHost(context), getPort(context), getPref(context), command);
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/json");
        if (signatureData != null) {
            headers.set("X-Signature", signatureData.getSignedData());
            headers.set("Cookie", signatureData.getSessionCookie());
        }else if (challenge !=null && signedChallenge!=null){
            headers.set("X-Challenge", challenge);
            headers.set("X-Signature", signedChallenge);
        }
        HttpEntity<String> requestEntity = new HttpEntity<>(params.toString(), headers);
        ResponseEntity<T> response = restTemplate.exchange(strUrl, HttpMethod.POST, requestEntity, type);
        int responseCode = response.getStatusCode().value();
        if ((responseCode >= 200) && (responseCode < 400)) {
            ret = response.getBody();
        } else if (responseCode == 401 && secureRepeat && params.has("team")) {
            try {
                SignedData signedData = signChallengeOfConnection(response, params.getString("team"));
                if (signedData == null) {
                    throw new PortadaMicroserviceCallException(-401, "You need generate a security key access");
                } else {
                    ret = sendPostAsFormatParams(command, context, params, signedData, type, false);
                }
            } catch (Exception exc) {
                throw new PortadaMicroserviceCallException(-100, String.format("Unexpected error: %s.\nPlease check with the person in charge.", exc.getMessage()), exc);
            }
        } else {
            String message = response.getHeaders().getFirst("X-message_error");
            if (message != null) {
                throw new PortadaMicroserviceCallException(-responseCode, String.format("Unexpected http error in server process: %s.\nPlease check with the person in charge.", message));
            } else {
                throw new PortadaMicroserviceCallException(-responseCode, "Unexpected http error.\nPlease check with the person in charge.");
            }
        }
        return ret;                
    }
    
//    private <T> T sendPostErrorHandler(ClientHttpResponse response, String command, String context, JSONObject jparams, MultiValueMap<String, Object> mparams, Class<T> type, boolean secureRepeat) throws PortadaMicroserviceCallException{
//        T ret = null;
//        int responseCode;
//        try {
//            responseCode = response.getStatusCode().value();
//            if (responseCode == 401 && secureRepeat) {
//                try {
//                    if(jparams!=null){
//                        SignedData signedData = signChallengeOfConnection(jparams.optString("team", null), response.getBody(), response.getHeaders().getFirst("Set-Cookie"));
//                        if (signedData == null) {
//                            throw new PortadaMicroserviceCallException(-401, "You need generate a security key access");
//                        } else {
//                            ret = sendPostAsFormatParams(command, context, jparams, signedData, type, false);
//                        }
//                    }else if(mparams!=null){
//                        SignedData signedData = signChallengeOfConnection(mparams.getFirst("team").toString(), response.getBody(), response.getHeaders().getFirst("Set-Cookie"));
//                        if (signedData == null) {
//                            throw new PortadaMicroserviceCallException(-401, "You need generate a security key access");
//                        } else {
//                            ret = sendPostAsFormatParams(command, context, mparams, signedData, type, false);
//                        }
//                    }
//                } catch (Exception ex) {
//                    throw new PortadaMicroserviceCallException(-100, String.format("Unexpected error: %s.\nPlease check with the person in charge.", ex.getMessage()), ex);
//                }
//            } else {
//                String message = response.getHeaders().getFirst("X-message_error");
//                if (message != null) {
//                    throw new PortadaMicroserviceCallException(-responseCode, String.format("Unexpected http error in server process: %s.\nPlease check with the person in charge.", message));
//                } else {
//                    throw new PortadaMicroserviceCallException(-responseCode, "Unexpected http error.\nPlease check with the person in charge.");
//                }
//            }
//        } catch (IOException ex) {
//            throw new PortadaMicroserviceCallException(-101, ex.getMessage());
//        }      
//        return ret;
//    }

    public String sendData(String command, HashMap<String, String> paramData, String context) throws Exception {
        return sendData(command, paramData, null, context);
    }

    public String sendData(String command, HashMap<String, String> paramData, SignedData signatureData, String context) throws Exception {
        String ret;
        String strUrl = String.format("%s://%s:%s%s%s", getProtocol(context), getHost(context), getPort(context), getPref(context), command);
        HttpPost post = new HttpPost(strUrl);
        if (signatureData != null) {
            post.addHeader("X-Signature", signatureData.getSignedData());
            post.addHeader("Cookie", signatureData.getSessionCookie());
        }
        List<NameValuePair> params = new ArrayList<>();
        for (String key : paramData.keySet()) {
            params.add(new BasicNameValuePair(key, paramData.get(key)));
        }
        post.setEntity(new UrlEncodedFormEntity(params));
        try (CloseableHttpClient client = HttpClients.createDefault();CloseableHttpResponse response = (CloseableHttpResponse) client.execute(post)) {
            int responseCode = response.getStatusLine().getStatusCode();
            if ((responseCode >= 200) && (responseCode < 400)) {
                ret = EntityUtils.toString(response.getEntity());
            } else if (responseCode == 401) {
                PortadaMicroservicesCaller.SignedData signedData = signChallengeOfConnection(response, paramData.getOrDefault("team", null));
                if (signedData == null) {
                    ret = "{\"error\":true, \"message\":\"You need generate a security key access\"}";
                } else {
                    ret = sendData(command, paramData, signedData, context);
                }
            } else {
                ret = "{\"error\":true, \"message\":\"Access to resource forbidden\", \"response\":".concat(EntityUtils.toString(response.getEntity())).concat("}");
            }
        }
        return ret;
    }
    
    protected HttpURLConnection flushMultipartRequest(String command, String fileFieldName, String inputFile, HashMap<String, String> paramData, String context) throws MalformedURLException, IOException{
        return flushMultipartRequest(command, fileFieldName, inputFile, paramData, null, context);
    }
    
    protected HttpURLConnection flushMultipartRequest(String command, String fileFieldName, String inputFile, HashMap<String, String> paramData, SignedData signatureData, String context) throws MalformedURLException, IOException{
        HttpURLConnection con;
        String strUrl = String.format("%s://%s:%s%s%s", getProtocol(context), getHost(context), getPort(context),getPref(context), command);
        File inFile = new File(inputFile);
        StringBuilder hwriter = new StringBuilder();
        if(paramData!=null){
            paramData.forEach((key, val) -> {
                hwriter.append("--*****\r\n");
                hwriter.append("Content-Disposition: form-data; name=\"").append(key).append("\"\r\n");
                hwriter.append("Content-Type: ").append("text/plain").append("\r\n");
                hwriter.append("\r\n"); 
                hwriter.append(val).append("\r\n");
            });
        }
        hwriter.append("--*****\r\n");
        hwriter.append("Content-Disposition: form-data; name=\"").append(fileFieldName).append("\"; filename=\"").append(inFile.getName()).append("\"\r\n");
        hwriter.append("Content-Type: ").append(HttpURLConnection.guessContentTypeFromName(inFile.getName())).append("\r\n");
        hwriter.append("Content-Length: ").append(String.valueOf(inFile.length())).append("\r\n");
        hwriter.append("\r\n"); 
        StringBuilder fwriter = new StringBuilder();
        fwriter.append("\r\n");
        fwriter.append("--*****--\r\n");

        URL url = new URL(strUrl);
        con = (HttpURLConnection)url.openConnection();
        con.setDoInput(true);
        con.setDoOutput(true);
        con.setUseCaches(false);
        con.setRequestMethod("POST");
        if(signatureData!=null){
            con.setRequestProperty("X-Signature", signatureData.getSignedData());
            con.setRequestProperty("Cookie", signatureData.getSessionCookie());
        }
        con.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + "*****");
        con.connect();
        try (OutputStream outputStream = con.getOutputStream();
                PrintWriter writer = new PrintWriter(new OutputStreamWriter(outputStream, "UTF-8"), true)) { 
            writer.append(hwriter.toString());   
            writer.flush();
            try(FileInputStream in = new FileInputStream(inFile)){
                copyStreams(in, outputStream);
                outputStream.flush();
            }
            writer.append(fwriter.toString());
            writer.flush();
        }        
        return con;
    }    
    
    protected String copyStreamToString(InputStream in) throws IOException{
        StringBuilder sb = new StringBuilder();
        try(BufferedReader br = new BufferedReader(new InputStreamReader(in))){
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append("\n");
            }            
        }
        return sb.toString();
    }
    
    protected long copyStreams(InputStream in, OutputStream out) throws IOException{
        BufferedOutputStream bos = new BufferedOutputStream(out);
        BufferedInputStream bis = new BufferedInputStream(in);
        byte[] buffer = new byte[12288]; // 12K
        long count = 0L;
        int n = 0;
        while (-1 != (n = bis.read(buffer))) {
            bos.write(buffer, 0, n);
            count += n;
        }
        bos.flush();
        return count;
    }       

    protected SignedData signChallengeOfConnection(ResponseEntity response, String team) throws Exception {
        String strContent;
        Object content = response.getBody();
        if (content == null) {
            strContent = String.format("{\"challenge\":\"%s\"}", response.getHeaders().getFirst("X-challenge"));
        } else {
            strContent = content.toString();
        }
        return signChallengeOfConnection(team, strContent, response.getHeaders().getFirst("Set-Cookie"));
    }

    protected SignedData signChallengeOfConnection(CloseableHttpResponse response, String team) throws Exception {
        return signChallengeOfConnection(team, response.getEntity().getContent(), response.getFirstHeader("Set-Cookie").getValue());
    }

    protected SignedData signChallengeOfConnection(HttpURLConnection con, String team) throws Exception {
        return signChallengeOfConnection(team, con.getErrorStream(), con.getHeaderField("Set-Cookie"));
    }

    protected SignedData signChallengeOfConnection(String team, InputStream stream, String sessionCookie) throws Exception {
        SignedData ret = null;
        File privateKeyFile = new File(new File(securityPath, team), "private.pem").getCanonicalFile().getAbsoluteFile();
        if (privateKeyFile.exists()) {
            PrivateKey privateKey = loadPrivateKey(privateKeyFile.getAbsolutePath());
            InputStreamReader reader = new InputStreamReader(stream);
            JsonObject jsonResponse = JsonParser.parseReader(reader).getAsJsonObject();
            String signed = signChallenge(jsonResponse.get("challenge").getAsString(), privateKey);
            ret = new SignedData(signed, sessionCookie);
        }
        return ret;
    }

    protected SignedData signChallengeOfConnection(String team, String content, String sessionCookie) throws Exception {
        SignedData ret = null;
        File privateKeyFile = new File(new File(securityPath, team), "private.pem").getCanonicalFile().getAbsoluteFile();
        if (privateKeyFile.exists()) {
            PrivateKey privateKey = loadPrivateKey(privateKeyFile.getAbsolutePath());
            JSONObject jsonResponse = new JSONObject(content);
            String signed = signChallenge(jsonResponse.optString("challenge"), privateKey);
            ret = new SignedData(signed, sessionCookie);
        }
        return ret;
    }
    
    /**
     * @param key
     * @return the host
     */
    public String getHost(String key) {
        return conDataList.get(key).getHost();
    }

    /**
     * @param key
     * @return the protocol
     */
    public String getProtocol(String key) {
        return conDataList.get(key).getProtocol();
    }

    /**
     * @return the port
     */
    public String getPort(String key) {
        return conDataList.get(key).getPort();
    }

    /**
     * @return the pref
     */
    public String getPref(String key) {
        return conDataList.get(key).getPref();
    }    
    
    
    public static final class SignedData{
        private final String signedData;
        private final String sessionCookie;

        public SignedData(String signedData, String sessionCookie) {
            this.signedData = signedData;
            this.sessionCookie = sessionCookie;
        }

        /**
         * @return the signedData
         */
        public String getSignedData() {
            return signedData;
        }

        /**
         * @return the sessionCookie
         */
        public String getSessionCookie() {
            return sessionCookie;
        }
    }         
}
