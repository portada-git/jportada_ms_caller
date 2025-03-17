package org.elsquatrecaps.portada.jportadamscaller.exceptions;

import java.io.IOException;

/**
 *
 * @author josep
 */
public class PortadaMicroserviceCallException  extends IOException{
    private int errorcode;

    public PortadaMicroserviceCallException(int errorcode) {
        super();
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
