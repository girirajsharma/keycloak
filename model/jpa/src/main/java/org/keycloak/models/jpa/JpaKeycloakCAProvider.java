package org.keycloak.models.jpa;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;

import net.iharder.Base64;

import org.keycloak.models.KeycloakCAModel;
import org.keycloak.models.KeycloakCAProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.KeycloakCAEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.PKIProvider;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class JpaKeycloakCAProvider implements KeycloakCAProvider {

    private final KeycloakSession session;
    protected EntityManager em;

    public JpaKeycloakCAProvider(KeycloakSession session, EntityManager em) {
        this.session = session;
        this.em = em;
    }

    @Override
    public void close() {
    }

    @Override
    public KeycloakCAModel getKecloakDefaultCA() {
        TypedQuery<KeycloakCAEntity> query = em.createNamedQuery("getDefaultKeycloakCA", KeycloakCAEntity.class);
        List<KeycloakCAEntity> entities = query.getResultList();
        if (entities.size() == 0)
            return null;
        return new KeycloakCAAdapter(em, session, entities.get(0));
    }

    @Override
    public KeycloakCAAdapter addKeycloakDefaultCA() {
        KeycloakCAEntity certificateAuthority = new KeycloakCAEntity();

        certificateAuthority.setId(KeycloakModelUtils.generateId());

        PKIProvider pkiProvider = session.getProvider(PKIProvider.class);
        KeyPair keyPair = pkiProvider.generate();
        X509Certificate caCertificate = pkiProvider.issue(keyPair, "KeycloakCA");

        certificateAuthority.setId(KeycloakModelUtils.generateId());
        certificateAuthority.setRootCAPublicKey(KeycloakModelUtils.getPemFromKey(keyPair.getPublic()));
        certificateAuthority.setRootCAPrivateKey(KeycloakModelUtils.getPemFromKey(keyPair.getPrivate()));
        certificateAuthority.setRootCACertificate(KeycloakModelUtils.getPemFromCertificate(caCertificate));
        certificateAuthority.setRootCACRLHolder(Base64.encodeBytes(pkiProvider.createCRLHolderBytes(new KeyPair(keyPair.getPublic(), keyPair.getPrivate()), caCertificate)));

        em.persist(certificateAuthority);
        em.flush();

        return new KeycloakCAAdapter(em, session, certificateAuthority);

    }

    @Override
    public KeycloakCAModel configureKecloakCA(PublicKey publicKey, PrivateKey privateKey, X509Certificate caCertificate) {
        em.createNamedQuery("removeDefaultKeycloakCA", KeycloakCAEntity.class).executeUpdate();

        KeycloakCAEntity certificateAuthority = new KeycloakCAEntity();
        PKIProvider pkiProvider = session.getProvider(PKIProvider.class);

        certificateAuthority.setId(KeycloakModelUtils.generateId());
        certificateAuthority.setRootCAPublicKey(KeycloakModelUtils.getPemFromKey(publicKey));
        certificateAuthority.setRootCAPrivateKey(KeycloakModelUtils.getPemFromKey(privateKey));
        certificateAuthority.setRootCACertificate(KeycloakModelUtils.getPemFromCertificate(caCertificate));
        certificateAuthority.setRootCACRLHolder(Base64.encodeBytes(pkiProvider.createCRLHolderBytes(new KeyPair(publicKey, privateKey), caCertificate)));

        em.persist(certificateAuthority);
        em.flush();

        return new KeycloakCAAdapter(em, session, certificateAuthority);

    }

}
