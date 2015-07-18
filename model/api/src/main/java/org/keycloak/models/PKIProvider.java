package org.keycloak.models;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CRLHolder;
import org.keycloak.provider.Provider;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public interface PKIProvider extends Provider {
    
    /**
     * Gets the key algorithm to be used for key generation.
     *
     * @return the key algorithm
     */
    String getKeyAlgorithm();

    /**
     * Gets the signature algorithm to be used for {@link java.security.cert.X509Certificate} generation.
     *
     * @return the signature algorithm
     */
    String getSignatureAlgorithm();

    /**
     * Gets the {@link java.security.cert.X509Certificate} validity.
     *
     * @return the certificate validity
     */
    Integer getCertificateValidity();

    /**
     * Gets the key length.
     *
     * @return the key length
     */
    Integer getKeyLength();

    /**
     * Gets the Base distinguished name.
     *
     * @return the Base DN
     */
    String getBaseDN();
    
    /**
     * <p>
     * Generates a {@link java.security.KeyPair} based on default configuration.
     * </p>
     *
     * @return A key pair representing the public and private keys.
     */
    KeyPair generate();
    
    /**
     * <p>
     * Generates a {@link java.security.KeyPair} based upon configuration {@link java.security.cert.X509Certificate} of the CA.
     * </p>
     *
     * @return A key pair representing the public and private keys.
     */
    KeyPair generate(X509Certificate certificate);
    
    /**
     * <p>
     * Generates a {@link java.security.KeyPair} based upon configuration of the CA.
     * </p>
     *
     * @return A key pair representing the public and private keys.
     */
    KeyPair generate(CertificateAuthorityConfig config);
    
    /**
     * <p>
     * Returns the default {@link CertificateAuthorityConfig}.
     * </p>
     * 
     * @return CertificateAuthorityConfig CA configuration
     */
    CertificateAuthorityConfig getConfiguration();
    
    /**
     * <p>
     * Returns the {@link CertificateAuthorityConfig} or the configuration of caCertificate.
     * </p>
     * 
     * @param caCertificate The certificate of Certificate Authority
     * 
     * @return CertificateAuthorityConfig CA configuration
     */
    CertificateAuthorityConfig getConfiguration(X509Certificate caCertificate);
    
    /**
     * <p>
     * Issues a valid digital {@link java.security.cert.X509Certificate} to self, realm or any other entity.
     * </p>
     *
     * @param caKeyPair The keypair of Certificate Authority
     * @param subjectName The name of issuer entity
     *
     * @return A valid digital certificate for self.
     */
    X509Certificate issue(KeyPair caKeyPair, String subjectName);
    
    /**
     * <p>
     * Issues a valid digital {@link java.security.cert.X509Certificate} to self, realm or any other entity using specified configuration.
     * </p>
     *
     * @param caKeyPair The keypair of Certificate Authority
     * @param subjectName The name issuer entity
     * @param certificateConfig The configuration of certificate to be issued
     *
     * @return A valid digital certificate for self.
     */
    X509Certificate issue(KeyPair caKeyPair, String subjectName, CertificateAuthorityConfig certificateConfig);
    
    /**
     * <p>
     * Issues a valid digital {@link java.security.cert.X509Certificate} given a username.
     * </p>
     *
     * @param caCertificate The certificate of Certificate Authority
     * @param caKeyPair The keypair of Certificate Authority
     * @param username The username of user to issue a new certificate.
     * @param userKeyPair The keypair of user
     *
     * @return A valid digital certificate, signed by this CA.
     */
    X509Certificate issue(X509Certificate caCertificate, KeyPair caKeyPair, String username, KeyPair userKeyPair);
    
    /**
     * <p>
     * Issues a valid digital {@link org.bouncycastle.cert.X509CRLHolder} as a byte array to the CA.
     * </p>
     *
     * @param caKeyPair The keypair of Certificate Authority
     * @param caCertificate The certificate of Certificate Authority
     *
     * @return A valid digital CRLHolder, signed by this CA.
     */
    byte[] createCRLHolderBytes(KeyPair caKeyPair, X509Certificate caCertificate);
    
    /**
     * <p>
     * Issues a valid digital {@link org.bouncycastle.cert.X509CRLHolder} to the CA.
     * </p>
     *
     * @param caKeyPair The keypair of Certificate Authority
     * @param caCertificate The certificate of Certificate Authority
     *
     * @return A valid digital CRLHolder, signed by this CA.
     */
    X509CRLHolder createCRLHolder(KeyPair caKeyPair, X509Certificate caCertificate);
    
    /**
     * <p>
     * Validates a {@link java.security.cert.X509Certificate}.
     * </p>
     * 
     * @param crlHolder The certificate Revocation List Holder
     * @param certificate The digital certificate to validate.
     * @param caKeyPair The keypair of Certificate Authority 
     *
     * @return True if the digital certificate is valid. Otherwise, false.
     */
    boolean validate(X509CRLHolder crlHolder, X509Certificate certificate, KeyPair caKeyPair);

    /**
     * <p>
     * Revokes the given {@link java.security.cert.X509Certificate}.
     * </p>
     *
     * <p>
     * In order to revoke a digital {@link java.security.cert.X509Certificate}, it must be valid and issued by this CA.
     * </p>
     * 
     * @param crlHolder The certificate Revocation List Holder
     * @param caKeyPair The keypair of Certificate Authority
     * @param caCertificate The certificate of Certificate Authority
     * @param userCertificate The digital certificate to revoke.
     * 
     * @return X509CRLHolder The updated certificate Revocation List Holder
     */
    X509CRLHolder revoke(X509CRLHolder crlHolder, KeyPair caKeyPair, X509Certificate caCertificate, X509Certificate userCertificate);

    /**
     * <p>
     * Checks if the given {@link java.security.cert.X509Certificate} is revoked.
     * </p>
     *
     * @param crlHolder The certificate Revocation List Holder
     * @param certificate The certificate to be checked for validity
     * 
     * @returns True if the certificate is revoked. Otherwise, false.
     */
    boolean isRevoked(X509CRLHolder crlHolder, X509Certificate certificate);
    
    /**
     * Encrypts the raw text using {@link java.security.PublicKey}, defined transformation and encoding.
     *
     * @param rawText the raw text
     * @param publicKey the public key
     * @param transformation the transformation
     * @param encoding the encoding
     *
     * @return the encrypted string
     */
    String encrypt(String rawText, PublicKey publicKey, String transformation, String encoding);
    
    /**
     * Decrypts the cipher text using {@link java.security.PrivateKey}, defined transformation and encoding.
     *
     * @param cipherText the cipher text
     * @param privateKey the private key
     * @param transformation the transformation
     * @param encoding the encoding
     *
     * @return the decrypted string
     */
    String decrypt(String cipherText, PrivateKey privateKey, String transformation, String encoding);

}
