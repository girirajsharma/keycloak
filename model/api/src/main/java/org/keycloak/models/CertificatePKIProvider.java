package org.keycloak.models;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509CRLEntryHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.CertificateAuthorityConfig;
import org.keycloak.models.PKIProvider;
import org.keycloak.models.utils.X509Util;

/**
 * @author <a href="mailto:giriraj.sharma27@gmail.com">Giriraj Sharma</a>
 */
public class CertificatePKIProvider implements PKIProvider {

    private final KeycloakSession session;

    public static final String DEFAULT_BASE_DISTINGUISHED_NAME = "O=Keycloak,OU=JBoss";

    // keySignatureAlgorithm: DiffieHellman (1024), DSA (1024), RSA (1024, 2048), EC
    private static String DEFAULT_KEY_SIGNATURE_ALGORITHM = "RSA";

    // CertificateSignatureAlgorithm: DSA (SHA1withDSA), Elliptic Curve (ECDSA) (SHA1withECDSA, SHA256withECDSA)
    // Reference :
    // http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation#X.509PublicKeyCertificateandCertificationRequestGeneration-DSA
    private static String DEFAULT_CERTIFICATE_SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";

    // Providers: Sun, SunJSSE, SunJCE, SunRsaSign
    // private static String DEFAULT_SIGNATURE_ALGORITHM_PROVIDER = "SUN";

    // Providers: Sun, SunJSSE, SunJCE, SunRsaSign
    // private static String DEFAULT_SECURE_RANDOM_ALGORITHM_PROVIDER = "SUN";

    private static Integer DEFAULT_VALIDITY = Integer.valueOf(1000);
    private static Integer DEFAULT_BIT_LENGTH = Integer.valueOf(2048);

    private final String keyAlgorithm;
    private final String signatureAlgorithm;
    private final Integer validity;
    private final Integer bitLength;
    private final String baseDN;

    public CertificatePKIProvider(KeycloakSession session) {
        this.session = session;

        this.keyAlgorithm = DEFAULT_KEY_SIGNATURE_ALGORITHM;
        this.signatureAlgorithm = DEFAULT_CERTIFICATE_SIGNATURE_ALGORITHM;
        this.validity = DEFAULT_VALIDITY;
        this.bitLength = DEFAULT_BIT_LENGTH;
        this.baseDN = DEFAULT_BASE_DISTINGUISHED_NAME;
    }

    @Override
    public String getKeyAlgorithm() {
        return this.keyAlgorithm;
    }

    @Override
    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    @Override
    public Integer getCertificateValidity() {
        return this.validity;
    }

    @Override
    public Integer getKeyLength() {
        return this.bitLength;
    }

    @Override
    public String getBaseDN() {
        return this.baseDN;
    }

    @Override
    public KeyPair generate() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(getKeyAlgorithm());
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyPairGenerator.initialize(getKeyLength(), random);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Could not generateKeyPair keys.", e);
        }
        return keyPair;
    }

    @Override
    public KeyPair generate(X509Certificate certificate) {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(certificate.getPublicKey().getAlgorithm());
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyPairGenerator.initialize(getKeyLength(), random);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Could not generateKeyPair keys.", e);
        }
        return keyPair;
    }

    @Override
    public KeyPair generate(CertificateAuthorityConfig config) {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(config.getKeyAlgorithm());
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            keyPairGenerator.initialize(config.getKeyLength(), random);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Could not generateKeyPair keys.", e);
        }
        return keyPair;
    }

    @Override
    public CertificateAuthorityConfig getConfiguration() {
        CertificateAuthorityConfig config = new CertificateAuthorityConfig();
        config.setKeyAlgorithm(getKeyAlgorithm());
        config.setSignatureAlgorithm(getSignatureAlgorithm());
        config.setCertificateValidity(getCertificateValidity());
        config.setKeyLength(getKeyLength());
        config.setBaseDN(getBaseDN());
        return config;
    }

    @Override
    public CertificateAuthorityConfig getConfiguration(X509Certificate caCertificate) {
        CertificateAuthorityConfig config = getConfiguration();
        config.setKeyAlgorithm(caCertificate.getPublicKey().getAlgorithm());
        config.setSignatureAlgorithm(caCertificate.getSigAlgName());
        return config;
    }

    @Override
    public X509Certificate issue(KeyPair caKeyPair, String realmName) {
        X500Name subjectDN = new X500Name("CN=" + realmName + "," + getBaseDN());
        return X509Util.generateV1Certificate(subjectDN, caKeyPair, getConfiguration());
    }

    @Override
    public X509Certificate issue(KeyPair caKeyPair, String realmName, CertificateAuthorityConfig certificateConfig) {
        X500Name subjectDN = new X500Name("CN=" + realmName + "," + certificateConfig.getBaseDN());
        return X509Util.generateV1Certificate(subjectDN, caKeyPair, certificateConfig);
    }

    @Override
    public X509Certificate issue(X509Certificate caCertificate, KeyPair caKeyPair, String username, KeyPair userKeyPair) {
        X509Certificate certificate = null;
        try {
            X500Name subjectDN = new X500Name("CN=" + username + "," + getBaseDN());
            certificate = X509Util.generateV3Certificate(caCertificate, caKeyPair, subjectDN, userKeyPair);
        } catch (Exception e) {
            throw new RuntimeException("Could not issue certificate.", e);
        }
        return certificate;
    }

    @Override
    public byte[] createCRLHolderBytes(KeyPair caKeyPair, X509Certificate caCertificate) {
        try {
            return X509Util.createRevocationList(caKeyPair, caCertificate, getConfiguration(caCertificate)).getEncoded();
        } catch (IOException e) {
            throw new RuntimeException("Could not encode CRL Holder.", e);
        }
    }

    @Override
    public X509CRLHolder createCRLHolder(KeyPair caKeyPair, X509Certificate caCertificate) {
        return X509Util.createRevocationList(caKeyPair, caCertificate, getConfiguration(caCertificate));
    }

    @Override
    public boolean validate(X509CRLHolder crlHolder, X509Certificate certificate, KeyPair caKeyPair) {
        try {
            certificate.checkValidity();
            certificate.verify(caKeyPair.getPublic());

            return !isRevoked(crlHolder, certificate);
        } catch (Exception e) {
        }
        return false;
    }

    @Override
    public X509CRLHolder revoke(X509CRLHolder crlHolder, KeyPair caKeyPair, X509Certificate caCertificate,
        X509Certificate userCertificate) {
        try {
            Date date = new Date();
            X509v2CRLBuilder builder = new X509v2CRLBuilder(crlHolder.getIssuer(), date); // Create
            Date nextUpdate = new Date(date.getTime() + 30 * 24 * 60 * 60 * 1000);

            // add the existing one into it
            builder.addCRL(crlHolder);
            // Add the serial to be revoked
            builder.addCRLEntry(userCertificate.getSerialNumber(), date, CRLReason.privilegeWithdrawn);
            builder.setNextUpdate(nextUpdate);

            ContentSigner contentSigner = X509Util.createSigner(caKeyPair.getPrivate(), getConfiguration(caCertificate));
            X509CRLHolder updatedCRL = builder.build(contentSigner);
            // certificateRevocationList.setEncoded(Base64.encodeBytes(updatedCRL.getEncoded()));
            return updatedCRL;
        } catch (Exception e) {
            throw new RuntimeException("Could not update revocation list.", e);
        }
    }

    @Override
    public boolean isRevoked(X509CRLHolder crlHolder, X509Certificate certificate) {
        X509CRLEntryHolder revocationEntry = crlHolder.getRevokedCertificate(certificate.getSerialNumber());
        if (revocationEntry != null) {
            return true;
        }
        return false;
    }

    @Override
    public String encrypt(String rawText, PublicKey publicKey, String transformation, String encoding) {
        String encryptedText = null;
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            encryptedText = new String(Base64.encodeBase64(cipher
                .doFinal(rawText.getBytes(encoding))));
        } catch (Exception e) {
            throw new RuntimeException("Could not encrypt rawText.", e);
        }
        return encryptedText;
    }

    @Override
    public String decrypt(String cipherText, PrivateKey privateKey, String transformation, String encoding) {
        String decryptedText = null;
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedText = new String(cipher.doFinal(Base64
                .decodeBase64(cipherText.getBytes())), encoding);
        } catch (Exception e) {
            throw new RuntimeException("Could not decrypt cipherText.", e);
        }
        return decryptedText;
    }

    @Override
    public void close() {

    }

}
