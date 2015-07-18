package org.keycloak.models;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.PKIProvider;
import org.keycloak.models.PKIProviderFactory;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class CertificatePKIProviderFactory implements PKIProviderFactory {

    public static final String ID = "certificate";

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public PKIProvider create(KeycloakSession session) {
        return new CertificatePKIProvider(session);
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
