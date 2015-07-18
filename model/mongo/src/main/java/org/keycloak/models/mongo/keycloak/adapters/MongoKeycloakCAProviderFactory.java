package org.keycloak.models.mongo.keycloak.adapters;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.connections.mongo.MongoConnectionProvider;
import org.keycloak.models.KeycloakCAProvider;
import org.keycloak.models.KeycloakCAProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MongoKeycloakCAProviderFactory implements KeycloakCAProviderFactory {
    protected static final Logger logger = Logger.getLogger(MongoUserProviderFactory.class);

    @Override
    public String getId() {
        return "mongo";
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public KeycloakCAProvider create(KeycloakSession session) {
        MongoConnectionProvider connection = session.getProvider(MongoConnectionProvider.class);
        return new MongoKeycloakCAProvider(session, connection.getInvocationContext());
    }

    @Override
    public void close() {
    }

}
