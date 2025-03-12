package org.elsquatrecaps.portada.jportadamscaller.exceptions;

/**
 *
 * @author josep
 */
public class PortadaMicroserviceCallException  extends Exception{
    private int errorcode;

    public PortadaMicroserviceCallException(int errorcode) {
        this.errorcode = errorcode;
    }

    public PortadaMicroserviceCallException(int errorcode, String message) {
        super(message);
        this.errorcode = errorcode;
    }

    public PortadaMicroserviceCallException(int errorcode, Throwable cause) {
        super(cause);
        this.errorcode = errorcode;
    }

    public PortadaMicroserviceCallException(int errorcode, String message, Throwable cause) {
        super(message, cause);
        this.errorcode = errorcode;
    }

    /**
     * @return the errorcode
     */
    public int getErrorcode() {
        return errorcode;
    }
    
    public String getJsonFormat(){
        return String.format("{\"error\":true, \"status_code\":%d, \"message\":\"%s\"}", errorcode, getMessage());
    }
}
