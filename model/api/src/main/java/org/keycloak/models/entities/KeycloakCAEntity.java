package org.keycloak.models.entities;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class KeycloakCAEntity {

    private String id;

    private String rootCAPublicKey;

    private String rootCAPrivateKey;

    private String rootCACertificate;

    private String rootCACRLHolder;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRootCAPublicKey() {
        return rootCAPublicKey;
    }

    public void setRootCAPublicKey(String rootCAPublicKey) {
        this.rootCAPublicKey = rootCAPublicKey;
    }

    public String getRootCAPrivateKey() {
        return rootCAPrivateKey;
    }

    public void setRootCAPrivateKey(String rootCAPrivateKey) {
        this.rootCAPrivateKey = rootCAPrivateKey;
    }

    public String getRootCACertificate() {
        return rootCACertificate;
    }

    public void setRootCACertificate(String rootCACertificate) {
        this.rootCACertificate = rootCACertificate;
    }

    public String getRootCACRLHolder() {
        return rootCACRLHolder;
    }

    public void setRootCACRLHolder(String rootCACRLHolder) {
        this.rootCACRLHolder = rootCACRLHolder;
    }
}
