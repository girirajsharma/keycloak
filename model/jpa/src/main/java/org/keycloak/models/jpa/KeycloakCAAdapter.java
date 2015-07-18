package org.keycloak.models.jpa;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.persistence.EntityManager;

import net.iharder.Base64;

import org.keycloak.models.KeycloakCAModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.KeycloakCAEntity;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class KeycloakCAAdapter implements KeycloakCAModel {

    protected KeycloakSession session;
    protected EntityManager em;
    protected KeycloakCAEntity entity;

    public KeycloakCAAdapter(EntityManager em, KeycloakSession session,
        KeycloakCAEntity entity) {
        this.session = session;
        this.em = em;
        this.entity = entity;
    }

    @Override
    public String getId() {
        return entity.getId();
    }

    @Override
    public void setId(String id) {
        entity.setId(id);
    }

    @Override
    public PublicKey getRootCAPublicKey() {
        return KeycloakModelUtils.getPublicKeyFromPem(entity.getRootCAPublicKey());
    }

    @Override
    public void setRootCAPublicKey(PublicKey publicKey) {
        entity.setRootCAPublicKey(KeycloakModelUtils.getPemFromKey(publicKey));
    }

    @Override
    public PrivateKey getRootCAPrivateKey() {
        return KeycloakModelUtils.getPrivateKeyFromPem(entity.getRootCAPrivateKey());
    }

    @Override
    public void setRootCAPrivateKey(PrivateKey privateKey) {
        entity.setRootCAPrivateKey(KeycloakModelUtils.getPemFromKey(privateKey));
    }

    @Override
    public X509Certificate getRootCACertificate() {
        return KeycloakModelUtils.getCertificateFromPem(entity.getRootCACertificate());
    }

    @Override
    public void setRootCACertificate(X509Certificate certificate) {
        entity.setRootCAPrivateKey(KeycloakModelUtils.getPemFromCertificate(certificate));
    }

    @Override
    public byte[] getRootCACRLHolder() {
        try {
            return Base64.decode(entity.getRootCACRLHolder());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setRootCACRLHolder(byte[] crlHolderBytes) {
        entity.setRootCACRLHolder(Base64.encodeBytes(crlHolderBytes));
    }

}
