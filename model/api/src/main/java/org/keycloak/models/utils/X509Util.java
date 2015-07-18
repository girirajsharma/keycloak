package org.keycloak.models.utils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.models.CertificateAuthorityConfig;

/**
 * The Class X509Util for generation of X509 v1 and v3 certificates.
 *
 * @author Giriraj Sharma
 */
public class X509Util {

    /**
     * Generates version 1 {@link java.security.cert.X509Certificate}.
     *
     * @param subjectDN the subject dn
     * @param caKeyPair the CA key pair
     * @param certificateConfig the certificate config
     *
     * @return the x509 certificate
     */
    public static X509Certificate generateV1Certificate(X500Name subjectDN, KeyPair caKeyPair,
            CertificateAuthorityConfig certificateConfig) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date validityStartDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
            Date validityEndDate = new Date(System.currentTimeMillis() + certificateConfig.getCertificateValidity() * 24 * 60
                    * 60 * 1000);
            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded());

            X509v1CertificateBuilder builder = new X509v1CertificateBuilder(subjectDN, serialNumber, validityStartDate,
                    validityEndDate, subjectDN, subPubKeyInfo);
            X509CertificateHolder holder = builder.build(createSigner(caKeyPair.getPrivate(), certificateConfig));

            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (Exception e) {
            throw new RuntimeException("Error creating X509v1Certificate.", e);
        }
    }

    /**
     * Generate version 3 {@link java.security.cert.X509Certificate}.
     *
     * @param rootCertificate the root certificate
     * @param issuerKeyPair the issuer key pair
     * @param subjectDN the subject dn
     * @param subjectKeyPair the subject key pair
     * @param certificateConfig the certificate config
     *
     * @return the x509 certificate
     */
    public static X509Certificate generateV3Certificate(X509Certificate rootCertificate, KeyPair issuerKeyPair,
            X500Name subjectDN, KeyPair subjectKeyPair) {
        try {
            // Serial Number
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()));

            // Validity
            Date notBefore = new Date(System.currentTimeMillis());
            Date notAfter = new Date(System.currentTimeMillis() + (((1000L * 60 * 60 * 24 * 30)) * 12) * 3);

            // SubjectPublicKeyInfo
            SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(subjectKeyPair.getPublic()
                    .getEncoded()));

            X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(new X500Name(rootCertificate.getSubjectDN()
                    .getName()), serialNumber, notBefore, notAfter, subjectDN, subjPubKeyInfo);

            DigestCalculator digCalc = new BcDigestCalculatorProvider()
                    .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
            X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);

            // Subject Key Identifier
            certGen.addExtension(Extension.subjectKeyIdentifier, false,
                    x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));

            // Authority Key Identifier
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));

            // Key Usage
            certGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign
                    | KeyUsage.cRLSign));

            // Extended Key Usage
            KeyPurposeId[] EKU = new KeyPurposeId[2];
            EKU[0] = KeyPurposeId.id_kp_emailProtection;
            EKU[1] = KeyPurposeId.id_kp_serverAuth;

            certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(EKU));

            // Basic Constraints
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

            // TODO :Certificate Policies, Authority Information Access, CRL Distribution Points are redundant and can be removed.
            
            // Certificate Policies.
            /* PolicyInformation[] certPolicies = new PolicyInformation[2];
            certPolicies[0] = new PolicyInformation(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.5"));
            certPolicies[1] = new PolicyInformation(new ASN1ObjectIdentifier("2.16.840.1.101.2.1.11.18"));

            certGen.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(certPolicies));

            // Authority Information Access
            AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(
                    GeneralName.uniformResourceIdentifier, new DERIA5String("http://www.somewebsite.com/ca.cer")));
            AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(
                    GeneralName.uniformResourceIdentifier, new DERIA5String("http://ocsp.somewebsite.com")));

            ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
            aia_ASN.add(caIssuers);
            aia_ASN.add(ocsp);

            certGen.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));

            // CRL Distribution Points
            DistributionPointName distPointOne = new DistributionPointName(new GeneralNames(new GeneralName(
                    GeneralName.uniformResourceIdentifier, "http://crl.somewebsite.com/master.crl")));
            DistributionPointName distPointTwo = new DistributionPointName(
                    new GeneralNames(
                            new GeneralName(GeneralName.uniformResourceIdentifier,
                                    "ldap://crl.somewebsite.com/cn%3dSecureCA%2cou%3dPKI%2co%3dCyberdyne%2cc%3dUS?certificaterevocationlist;binary")));

            DistributionPoint[] distPoints = new DistributionPoint[2];
            distPoints[0] = new DistributionPoint(distPointOne, null, null);
            distPoints[1] = new DistributionPoint(distPointTwo, null, null);

            certGen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));*/

            // Content Signer
            ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(
                    issuerKeyPair.getPrivate());

            // Certificate
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
        } catch (Exception e) {
            throw new RuntimeException("Error creating X509v3Certificate.", e);
        }
    }

    /**
     * Creates the content signer for generation of Version 1 {@link java.security.cert.X509Certificate}.
     *
     * @param privateKey the private key
     * @param certificateConfig the certificate config
     *
     * @return the content signer
     */
    public static ContentSigner createSigner(PrivateKey privateKey, CertificateAuthorityConfig certificateConfig) {
        try {
            AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(certificateConfig
                    .getSignatureAlgorithm());
            AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

            return new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                    .build(PrivateKeyFactory.createKey(privateKey.getEncoded()));
        } catch (Exception e) {
            throw new RuntimeException("Could not create content signer.", e);
        }
    }
    
    public static X509CRLHolder createRevocationList(KeyPair caKeyPair, X509Certificate caCertificate,
            CertificateAuthorityConfig config) {
        Date date = new Date();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(caCertificate.getSubjectDN().getName()), date);
        Date nextUpdate = new Date(date.getTime() + 30 * 24 * 60 * 60 * 1000); // Every 30 days

        builder.setNextUpdate(nextUpdate);

        ContentSigner contentSigner = createSigner(caKeyPair.getPrivate(), config);

        return builder.build(contentSigner);
    }
}
