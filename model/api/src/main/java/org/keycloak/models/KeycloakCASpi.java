package org.keycloak.models;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class KeycloakCASpi implements Spi {
	
    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "keycloakCA";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return KeycloakCAProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return KeycloakCAProviderFactory.class;
    }

}
