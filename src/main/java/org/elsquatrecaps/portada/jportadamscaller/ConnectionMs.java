package org.elsquatrecaps.portada.jportadamscaller;

/**
 *
 * @author josep
 */
public class ConnectionMs {

    private String port;
    private String host;
    private String protocol;
    private String pref;

    public ConnectionMs(String protocol, String ports, String hosts, String prefs) {
        this.port = ports;
        this.host = hosts;
        this.setPref(prefs);
        this.protocol = protocol;
    }

    public ConnectionMs() {
    }

    
    /**
     * @return the port
     */
    public String getPort() {
        return port;
    }

    /**
     * @param port the port to set
     */
    public void setPort(String port) {
        this.port = port;
    }

    /**
     * @return the host
     */
    public String getHost() {
        return host;
    }

    /**
     * @param host the host to set
     */
    public void setHost(String host) {
        this.host = host;
    }

    /**
     * @return the pref
     */
    public String getPref() {
        return pref;
    }

    /**
     * @param pref the pref to set
     */
    public void setPref(String pref) {
        if(pref==null || pref.isEmpty() || pref.trim().isEmpty()){
            pref="/";
        }else{
            if(!pref.startsWith("/")){
                pref="/".concat(pref);
            }
            if(!pref.endsWith("/")){
                pref=pref.concat("/");
            }
        }
        this.pref = pref;
    }
  
    /**
     * @return the protocol
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * @param protocol the protocol to set
     */
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
}
