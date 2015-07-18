package org.keycloak.models.mongo.keycloak.adapters;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import net.iharder.Base64;

import org.keycloak.connections.mongo.api.MongoStore;
import org.keycloak.connections.mongo.api.context.MongoStoreInvocationContext;
import org.keycloak.models.KeycloakCAModel;
import org.keycloak.models.KeycloakCAProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.mongo.keycloak.entities.MongoKeycloakCAEntity;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.PKIProvider;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class MongoKeycloakCAProvider implements KeycloakCAProvider {

    private final MongoStoreInvocationContext invocationContext;
    private final KeycloakSession session;

    public MongoKeycloakCAProvider(KeycloakSession session, MongoStoreInvocationContext invocationContext) {
        this.session = session;
        this.invocationContext = invocationContext;
    }

    @Override
    public void close() {
    }

    @Override
    public KeycloakCAModel getKecloakDefaultCA() {
        MongoKeycloakCAEntity defaultCA = getMongoStore().loadEntity(MongoKeycloakCAEntity.class, null, invocationContext);

        if (defaultCA == null) {
            return null;
        } else {
            return new KeycloakCAAdapter(session, defaultCA, invocationContext);
        }
    }

    @Override
    public KeycloakCAAdapter addKeycloakDefaultCA() {
        MongoKeycloakCAEntity certificateAuthority = new MongoKeycloakCAEntity();
        certificateAuthority.setId(KeycloakModelUtils.generateId());

        PKIProvider pkiProvider = session.getProvider(PKIProvider.class);
        KeyPair keyPair = pkiProvider.generate();
        X509Certificate caCertificate = pkiProvider.issue(keyPair, "KeycloakCA");

        certificateAuthority.setId(KeycloakModelUtils.generateId());
        certificateAuthority.setRootCAPublicKey(KeycloakModelUtils.getPemFromKey(keyPair.getPublic()));
        certificateAuthority.setRootCAPrivateKey(KeycloakModelUtils.getPemFromKey(keyPair.getPrivate()));
        certificateAuthority.setRootCACertificate(KeycloakModelUtils.getPemFromCertificate(caCertificate));
        certificateAuthority.setRootCACRLHolder(Base64.encodeBytes(pkiProvider.createCRLHolderBytes(new KeyPair(keyPair.getPublic(), keyPair.getPrivate()), caCertificate)));

        getMongoStore().insertEntity(certificateAuthority, invocationContext);
        return new KeycloakCAAdapter(session, certificateAuthority, invocationContext);
    }

    @Override
    public KeycloakCAModel configureKecloakCA(PublicKey publicKey,
        PrivateKey privateKey, X509Certificate caCertificate) {
        MongoKeycloakCAEntity defaultCA = getMongoStore().loadEntity(MongoKeycloakCAEntity.class, null, invocationContext);
        getMongoStore().removeEntity(MongoKeycloakCAEntity.class, defaultCA.getId(), invocationContext);

        MongoKeycloakCAEntity certificateAuthority = new MongoKeycloakCAEntity();
        PKIProvider pkiProvider = session.getProvider(PKIProvider.class);

        certificateAuthority.setId(KeycloakModelUtils.generateId());
        certificateAuthority.setRootCAPublicKey(KeycloakModelUtils.getPemFromKey(publicKey));
        certificateAuthority.setRootCAPrivateKey(KeycloakModelUtils.getPemFromKey(privateKey));
        certificateAuthority.setRootCACertificate(KeycloakModelUtils.getPemFromCertificate(caCertificate));
        certificateAuthority.setRootCACRLHolder(Base64.encodeBytes(pkiProvider.createCRLHolderBytes(new KeyPair(publicKey, privateKey), caCertificate)));

        getMongoStore().insertEntity(certificateAuthority, invocationContext);
        return new KeycloakCAAdapter(session, certificateAuthority, invocationContext);
    }

    protected MongoStore getMongoStore() {
        return invocationContext.getMongoStore();
    }

}
