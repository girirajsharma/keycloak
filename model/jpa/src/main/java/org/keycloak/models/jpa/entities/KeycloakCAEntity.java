package org.keycloak.models.jpa.entities;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
@NamedQueries({
    // There will be only a single row in KEYCLOAK_CERTIFICATE_AUTHORITY_ENTITY at any time.
    @NamedQuery(name = "getDefaultKeycloakCA", query = "select c from KeycloakCAEntity c"),
    @NamedQuery(name = "removeDefaultKeycloakCA", query = "delete from KeycloakCAEntity")
})
@Entity
@Table(name = "KEYCLOAK_CA_ENTITY")
public class KeycloakCAEntity {

    @Id
    @Column(name = "ID", length = 36)
    private String id;

    @Column(name = "ROOT_CA_PUBLIC_KEY")
    private String rootCAPublicKey;

    @Column(name = "ROOT_CA_PRIVATE_KEY")
    private String rootCAPrivateKey;

    @Column(name = "ROOT_CA_CERTIFICATE")
    private String rootCACertificate;

    @Column(name = "ROOT_CA_CRL_HOLDER")
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
