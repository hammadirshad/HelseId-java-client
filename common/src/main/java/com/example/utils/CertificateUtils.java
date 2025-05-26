package com.example.utils;

import com.example.config.OAuth2ClientDetailProperties.Registration;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.*;
import java.util.Enumeration;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

@Slf4j
public class CertificateUtils {

    public static X509Certificate getX509Certificate(String pem)
            throws CertificateException, NoSuchProviderException, IOException {
        final byte[] pemContent = getPemBytesBouncyCastle(new StringReader(pem));
        return getX509Certificate(pemContent);
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

    public static X509Certificate getX509Certificate(
        final InputStream keystoreInputStream, String type, String storePassword)
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore keystore = getKeyStore(type, keystoreInputStream, storePassword);

        Enumeration<String> enumeration = keystore.aliases();
        if (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            return (X509Certificate) keystore.getCertificate(alias);
        }
        return null;
    }

    public static RSAPublicKeySpec getRSAPublicKeySpec(final PublicKey publicKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
    }

    public static PublicKey getPublicKey(final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] pemContent = getPemBytesBouncyCastle(new InputStreamReader(inputStream));
        final X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(encodedKeySpec);
    }

    public static PublicKey getPublicKey(final String pem)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        StringReader stringReader = new StringReader(pem);
        final byte[] pemContent = getPemBytesBouncyCastle(stringReader);
        final X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(encodedKeySpec);
    }

    public static PublicKey getPublicKey(final PrivateKey privateKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(),
            rsaPrivateCrtKey.getPublicExponent());
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(publicKeySpec);
    }

    public static RSAPrivateKeySpec getRSAPrivateKeySpec(final PrivateKey privateKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
    }

    public static PrivateKey getPrivateKey(final InputStream inputStream)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] pemContent = getPemBytesBouncyCastle(new InputStreamReader(inputStream));
        final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(encodedKeySpec);
    }

    public static PrivateKey getPrivateKey(final String pem)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        StringReader stringReader = new StringReader(pem);
        final byte[] pemContent = getPemBytesBouncyCastle(stringReader);
        final PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(pemContent);
        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(encodedKeySpec);
    }

    public static PrivateKey getPrivateKey(
        final InputStream keystoreInputStream, String type, String storePassword, String keyPassword)
        throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keystore = getKeyStore(type, keystoreInputStream, storePassword);

        Enumeration<String> enumeration = keystore.aliases();
        if (enumeration.hasMoreElements()) {
            String alias = enumeration.nextElement();
            return (PrivateKey) keystore.getKey(alias, keyPassword.toCharArray());
        }
        return null;
    }

    private static byte[] getPemBytesBouncyCastle(Reader reader) throws IOException {
        PemReader pemReader = new PemReader(reader);
        final PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }


    public static KeyStore getKeyStore(String type, InputStream inputStream, String storePassword)
        throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance(type);
        keystore.load(inputStream, storePassword.toCharArray());
        return keystore;
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

    public static boolean matchKeyPair(RSAPrivateKeySpec privateKey, RSAPublicKeySpec publicKey) {
        return privateKey.getModulus().equals(publicKey.getModulus())
            && privateKey.getModulus().equals(publicKey.getModulus());
    }

    public static RSAKey getRsaKey(RSAPrivateKey privateKey, String keyId)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKey publicKey = (RSAPublicKey) CertificateUtils.getPublicKey(privateKey);
        return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(keyId != null ? keyId : UUID.randomUUID().toString())
            .build();
    }

    public static RSAPrivateKey getRsaPrivateKey(String privateKeyValue)
        throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPrivateKey privateKey;
        if (privateKeyValue.endsWith(".pem")) {
            final String pem =
                Files.readString(Path.of(PathResolver.getURI(privateKeyValue)));
            privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
        } else if (privateKeyValue.endsWith(".xml")) {
            final String pem =
                XMLSec2PEM.getPem(PathResolver.getInputStream(privateKeyValue));
            privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
        } else if (privateKeyValue.endsWith(".json")) {
            final String pem = JWK2PEM.getPem(PathResolver.getInputStream(privateKeyValue));
            privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
        } else {
            privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(privateKeyValue);
        }
        return privateKey;
    }

    public static JwsAlgorithm resolveAlgorithm(JWK jwk) {
        JwsAlgorithm jwsAlgorithm = null;

        if (jwk.getAlgorithm() != null) {
            jwsAlgorithm = SignatureAlgorithm.from(jwk.getAlgorithm().getName());
            if (jwsAlgorithm == null) {
                jwsAlgorithm = MacAlgorithm.from(jwk.getAlgorithm().getName());
            }
        }

        if (jwsAlgorithm == null) {
            if (KeyType.RSA.equals(jwk.getKeyType())) {
                jwsAlgorithm = SignatureAlgorithm.RS256;
            } else if (KeyType.EC.equals(jwk.getKeyType())) {
                jwsAlgorithm = SignatureAlgorithm.ES256;
            } else if (KeyType.OCT.equals(jwk.getKeyType())) {
                jwsAlgorithm = MacAlgorithm.HS256;
            }
        }

        return jwsAlgorithm;
    }
}

