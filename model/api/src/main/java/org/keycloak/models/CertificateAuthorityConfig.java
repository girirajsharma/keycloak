package org.keycloak.models;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class CertificateAuthorityConfig {
    
    private String keyAlgorithm;

    private String signatureAlgorithm;

    private long certificateValidity;

    private int keyLength;
    
    private String baseDN;
    
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public void setKeyAlgorithm(String keyAlgorithm) {
        this.keyAlgorithm = keyAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public long getCertificateValidity() {
        return certificateValidity;
    }

    public void setCertificateValidity(long certificateValidity) {
        this.certificateValidity = certificateValidity;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public String getBaseDN() {
        return baseDN;
    }

    public void setBaseDN(String baseDN) {
        this.baseDN = baseDN;
    }

}
