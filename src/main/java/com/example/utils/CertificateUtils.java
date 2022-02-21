package com.example.utils;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.*;
import java.net.ConnectException;
import java.net.Proxy;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;
import java.util.Hashtable;

@Slf4j
public class CertificateUtils {

    public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    public static final String END_CERT = "-----END CERTIFICATE-----";
    public static final String BEGIN = "-----BEGIN ";
    public static final String END = "-----END ";

    public static X509Certificate getX509Certificate(String cer) throws Exception {
        return getX509Certificate(cleanCertificate(cer).getBytes());
    }

    public static X509Certificate getX509Certificate(byte[] cer)
            throws CertificateException, NoSuchProviderException {
        ByteArrayInputStream byis = new ByteArrayInputStream(cer);
        return getX509Certificate(byis);
    }

    public static X509Certificate getX509Certificate(InputStream byis)
            throws CertificateException, NoSuchProviderException {
        CertificateFactory factory =
                CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
        return (X509Certificate) factory.generateCertificate(byis);
    }

    private static String cleanCertificate(String cer) {
        cer = cer.replaceAll("[\\t\\n\\r]+", "");
        cer = cer.replaceAll("[\uFEFF-\uFFFF]", "");

        String certData = cer.substring(BEGIN_CERT.length(), cer.length() - END_CERT.length()).trim();
        cer = BEGIN_CERT + "\n" + certData + "\n" + END_CERT;
        return cer;
    }

    public static boolean matchKeyPair(RSAPrivateKeySpec privateKey, RSAPublicKeySpec publicKey) {
        return privateKey.getModulus().equals(publicKey.getModulus())
                && privateKey.getModulus().equals(publicKey.getModulus());
    }

    public static RSAPublicKeySpec getRSAPublicKeySpec(final PublicKey publicKey) throws Exception {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
    }

    public static PublicKey getPublicKey(final InputStream inputStream) throws Exception {
        final byte[] pemContent = getPemBytesBouncyCastle(new InputStreamReader(inputStream));
        final X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(encodedKeySpec);
    }

    public static PublicKey getPublicKey(final String pem) throws Exception {
        StringReader stringReader = new StringReader(pem);
        final byte[] pemContent = getPemBytesBouncyCastle(stringReader);
        final X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(encodedKeySpec);
    }

    public static RSAPrivateKeySpec getRSAPrivateKeySpec(final PrivateKey privateKey)
            throws Exception {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
    }

    public static PrivateKey getPrivateKey(final InputStream inputStream) throws Exception {
        final byte[] pemContent = getPemBytesBouncyCastle(new InputStreamReader(inputStream));
        final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(encodedKeySpec);
    }

    public static PrivateKey getPrivateKey(final String pem) throws Exception {
        StringReader stringReader = new StringReader(pem);
        final byte[] pemContent = getPemBytesBouncyCastle(stringReader);
        final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(encodedKeySpec);
    }

    private static byte[] getPemBytesBouncyCastle(Reader reader) throws Exception {
        PemReader pemReader = new PemReader(reader);
        final PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }

    @SneakyThrows
    public static PrivateKey getPrivateFromKeyStore(
            InputStream inputStream, String type, String storePassword, String keyPassword) {
        KeyStore keystore = KeyStore.getInstance(type);
        keystore.load(inputStream, storePassword.toCharArray());

        Enumeration<String> enumeration = keystore.aliases();
        if (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            return (PrivateKey) keystore.getKey(alias, keyPassword.toCharArray());
        }
        return null;
    }

    @SneakyThrows
    public static X509Certificate getX509CertificateFromKeyStore(
            InputStream inputStream, String type, String storePassword) {
        KeyStore keystore = KeyStore.getInstance(type);
        keystore.load(inputStream, storePassword.toCharArray());

        Enumeration<String> enumeration = keystore.aliases();
        if (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            return (X509Certificate) keystore.getCertificate(alias);
        }
        return null;
    }

    public static X509CRL getCRL(X509Certificate cert, Proxy proxy) {

        try {
            byte[] crldpExt = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());

            if (crldpExt == null) {
                return null;
            }

            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crldpExt));
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crldpExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crldpExtOctets));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                // Look for URIs in fullName
                if (dpn != null) {
                    if (dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                        // Look for an URI
                        for (GeneralName genName : genNames) {
                            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String crlURL = DERIA5String.getInstance(genName.getName()).getString();

                                InputStream is = null;
                                if (crlURL.startsWith("ldap://")) {

                                    Hashtable<String, String> env = new Hashtable<>();
                                    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                                    env.put(Context.PROVIDER_URL, crlURL);
                                    DirContext ctx = new InitialDirContext(env);
                                    Attributes avals = ctx.getAttributes("");
                                    Attribute aval = avals.get("certificateRevocationList;binary");
                                    byte[] val = (byte[]) aval.get();
                                    if ((val != null) && (val.length != 0)) {
                                        is = new ByteArrayInputStream(val);
                                    }
                                } else {
                                    if (proxy == null) {
                                        is = new URL(crlURL).openStream();
                                    } else {
                                        is = new URL(crlURL).openConnection(proxy).getInputStream();
                                    }
                                }

                                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                                return (X509CRL) cf.generateCRL(is);
                            }
                        }
                    }
                }
            }
        } catch (ConnectException e) {
            log.error(e.getMessage());
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public static String getKeyPem(Key key) throws IOException {
        final StringWriter stringWriter = new StringWriter();
        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(stringWriter);
        jcaPEMWriter.writeObject(key);
        jcaPEMWriter.close();
        final String pem = stringWriter.toString();
        stringWriter.close();
        return pem;
    }

    public static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }
}

