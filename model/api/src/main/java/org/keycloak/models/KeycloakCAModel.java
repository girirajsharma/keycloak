package org.keycloak.models;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Base KeycloakCAModel to provide configuration of Keycloak root Certificate Authority.
 *
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public interface KeycloakCAModel {
	
	/**
	 * Gets the id of the Keycloak root Certificate Authority.
	 *
	 * @return the id
	 */
	String getId();
	
	/**
	 * Sets the id of the Keycloak root Certificate Authority.
	 *
	 * @param id the new id
	 */
	void setId(String id);
	
	/**
	 * Gets the Keycloak root Certificate Authority public key.
	 *
	 * @return the root CA public key
	 */
	PublicKey getRootCAPublicKey();
	
	/**
	 * Sets the Keycloak root Certificate Authority public key.
	 *
	 * @param publicKey the root CA public key
	 */
	void setRootCAPublicKey(PublicKey publicKey);
	
	/**
	 * Gets the Keycloak root Certificate Authority private key.
	 *
	 * @return the root CA private key
	 */
	PrivateKey getRootCAPrivateKey();
	
	/**
	 * Sets the root CA private key.
	 *
	 * @param privateKey the new root CA private key
	 */
	void setRootCAPrivateKey(PrivateKey privateKey);
	
	/**
	 * Gets the Keycloak root Certificate Authority certificate.
	 *
	 * @return the root CA certificate
	 */
	X509Certificate getRootCACertificate();
	
	/**
	 * Sets the Keycloak root Certificate Authority certificate.
	 *
	 * @param certificate the new root CA certificate
	 */
	void setRootCACertificate(X509Certificate certificate);
	
	/**
	 * Gets the Keycloak root Certificate Authority Certificate Revocation List holder.
	 *
	 * @return the root CA CRL holder
	 */
	byte[] getRootCACRLHolder();
	
	/**
	 * Sets the Keycloak root Certificate Authority Certificate Revocation List holder.
	 *
	 * @param holder the new root CA CRL holder
	 */
	void setRootCACRLHolder(byte[] holder);

}
