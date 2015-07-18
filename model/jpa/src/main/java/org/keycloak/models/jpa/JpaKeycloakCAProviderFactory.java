package org.keycloak.models.jpa;

import javax.persistence.EntityManager;

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakCAProvider;
import org.keycloak.models.KeycloakCAProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class JpaKeycloakCAProviderFactory implements KeycloakCAProviderFactory {

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return "jpa";
    }

    @Override
    public KeycloakCAProvider create(KeycloakSession session) {
        EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        return new JpaKeycloakCAProvider(session, em);
    }

    @Override
    public void close() {
    }
}
