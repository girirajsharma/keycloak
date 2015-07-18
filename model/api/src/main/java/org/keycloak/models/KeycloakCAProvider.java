package org.keycloak.models;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.keycloak.provider.Provider;

/**
 * KeycloakCAProvider to allow persistence of Keycloak root Certificate Authority
 *
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public interface KeycloakCAProvider extends Provider {
	
	/**
	 * Gets the default model of Keycloak root Certificate Authority.
	 *
	 * @return the keycloak default CA model
	 */
	KeycloakCAModel getKecloakDefaultCA();
	
	/**
	 * Adds the Keycloak root Certificate Authority model.
	 *
	 * @return the keycloak default CA model
	 */
	KeycloakCAModel addKeycloakDefaultCA();
	
	/**
	 * Configure Keycloak root Certificate Authority with uploaded keys and certificates.
	 *
	 * @param publicKey the public key of CA
	 * @param privateKey the private key of CA
	 * @param caCertificate the CA certificate
	 * @return the keycloak CA model
	 */
	KeycloakCAModel configureKecloakCA(PublicKey publicKey, PrivateKey privateKey, X509Certificate caCertificate);
}
