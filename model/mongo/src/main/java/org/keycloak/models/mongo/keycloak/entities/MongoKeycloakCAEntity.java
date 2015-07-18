package org.keycloak.models.mongo.keycloak.entities;

import org.keycloak.connections.mongo.api.MongoCollection;
import org.keycloak.connections.mongo.api.MongoIdentifiableEntity;
import org.keycloak.connections.mongo.api.context.MongoStoreInvocationContext;
import org.keycloak.models.entities.KeycloakCAEntity;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
@MongoCollection(collectionName = "keycloakCertificateAuthority")
public class MongoKeycloakCAEntity extends KeycloakCAEntity implements MongoIdentifiableEntity {

    @Override
    public void afterRemove(MongoStoreInvocationContext invocationContext) {
    }
}
