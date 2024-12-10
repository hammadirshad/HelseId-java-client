package com.example.utils;

import com.nimbusds.jose.util.Base64URL;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;


@Slf4j
public class JWK2PEM {

    private static final int PRIVATE_KEY = 1;
    private static final int PUBLIC_KEY = 2;
    private static final String[] PRIVATE_KEY_XML_NODES = {"kty", "p", "q", "d", "e", "qi", "dp", "dq", "n"};
    private static final String[] PUBLIC_KEY_XML_NODES = {"kty", "e", "use", "x5t", "kid", "x5c", "alg", "n"};

    public static String getPem(String jwk) {
        try {
            JSONObject jsonObject = new JSONObject(jwk);
            return getPem(jsonObject);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public static String getPem(InputStream inputStream) {
        try {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            for (int length; (length = inputStream.read(buffer)) != -1; ) {
                result.write(buffer, 0, length);
            }
            JSONObject jsonObject = new JSONObject(result.toString(StandardCharsets.UTF_8));
            return getPem(jsonObject);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private static String getPem(JSONObject jwk) {
        try {
            int keyType = getKeyType(jwk);
            if ((keyType == PRIVATE_KEY || keyType == PUBLIC_KEY) && checkXMLRSAKey(keyType, jwk)) {

                StringBuilder pemStringBuilder = new StringBuilder();
                if (keyType == PRIVATE_KEY) {
                    pemStringBuilder.append("-----BEGIN RSA PRIVATE KEY-----");
                    pemStringBuilder.append("\n");
                    pemStringBuilder.append(convertJwkRSAPrivateKeyToPEM(jwk));
                    pemStringBuilder.append("\n");
                    pemStringBuilder.append("-----END RSA PRIVATE KEY-----");
                } else {
                    pemStringBuilder.append("-----BEGIN PUBLIC KEY-----");
                    pemStringBuilder.append("\n");
                    pemStringBuilder.append(convertJwkRSAPublicKeyToPEM(jwk));
                    pemStringBuilder.append("\n");
                    pemStringBuilder.append("-----END PUBLIC KEY-----");
                }
                return pemStringBuilder.toString();
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private static int getKeyType(JSONObject jwk) {
        if (jwk.keySet().size() == PUBLIC_KEY_XML_NODES.length) {
            return PUBLIC_KEY;
        }
        return PRIVATE_KEY;

    }

    private static boolean checkXMLRSAKey(int keyType, JSONObject jwk) {
        String[] wantedNodes;
        if (keyType == PRIVATE_KEY) {
            wantedNodes = PRIVATE_KEY_XML_NODES;
        } else {
            wantedNodes = PUBLIC_KEY_XML_NODES;
        }
        for (String wantedNode : wantedNodes) {
            boolean found = false;
            for (String node : jwk.keySet()) {
                if (node.equals(wantedNode)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;

    }


    private static String convertJwkRSAPrivateKeyToPEM(JSONObject jwk) {

        BigInteger modulus = new BigInteger(1, b64URLdecode(jwk.getString("n")));
        BigInteger exponent = new BigInteger(1, b64URLdecode(jwk.getString("e")));
        BigInteger primeP = new BigInteger(1, b64URLdecode(jwk.getString("p")));
        BigInteger primeQ = new BigInteger(1, b64URLdecode(jwk.getString("q")));
        BigInteger primeExponentP = new BigInteger(1, b64URLdecode(jwk.getString("dp")));
        BigInteger primeExponentQ = new BigInteger(1, b64URLdecode(jwk.getString("dq")));
        BigInteger crtCoefficient = new BigInteger(1, b64URLdecode(jwk.getString("qi")));
        BigInteger privateExponent = new BigInteger(1, b64URLdecode(jwk.getString("d")));

        try {

            RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                    modulus, exponent, privateExponent, primeP, primeQ,
                    primeExponentP, primeExponentQ, crtCoefficient);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey key = keyFactory.generatePrivate(keySpec);
            return b64encode(key.getEncoded());

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;

    }

    private static String convertJwkRSAPublicKeyToPEM(JSONObject jwk) {

        BigInteger modulus = new BigInteger(1, b64URLdecode(jwk.getString("n")));
        BigInteger exponent = new BigInteger(1, b64URLdecode(jwk.getString("e")));
        try {

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey key = keyFactory.generatePublic(keySpec);
            return b64encode(key.getEncoded());

        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;

    }


    private static String b64encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data).trim();
    }

    private static byte[] b64decode(String data) {
        return Base64.getDecoder().decode(data.trim());
    }

    private static byte[] b64URLdecode(String data) {
        return new Base64URL(data.trim()).decode();
    }
}
