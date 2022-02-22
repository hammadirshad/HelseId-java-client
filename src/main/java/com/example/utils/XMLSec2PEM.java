package com.example.utils;

import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;


@Slf4j
public class XMLSec2PEM {

    private static final int PRIVATE_KEY = 1;
    private static final int PUBLIC_KEY = 2;
    private static final String[] PRIVATE_KEY_XML_NODES = {"Modulus", "Exponent", "P", "Q", "DP", "DQ", "InverseQ", "D"};
    private static final String[] PUBLIC_KEY_XML_NODES = {"Modulus", "Exponent"};

    public static String getPem(String xml) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            return getPem(builder.parse(new File(xml)));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    public static String getPem(InputStream inputStream) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            return getPem(builder.parse(inputStream));
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            return null;
        }
    }

    private static String getPem(Document XMLSecKeyDoc) {
        try {
            int keyType = getKeyType(XMLSecKeyDoc);
            if ((keyType == PRIVATE_KEY || keyType == PUBLIC_KEY) && checkXMLRSAKey(keyType, XMLSecKeyDoc)) {

                StringBuilder pemStringBuilder = new StringBuilder();
                if (keyType == PRIVATE_KEY) {
                    pemStringBuilder.append("-----BEGIN RSA PRIVATE KEY-----");
                    pemStringBuilder.append(convertXMLRSAPrivateKeyToPEM(XMLSecKeyDoc));
                    pemStringBuilder.append("-----END RSA PRIVATE KEY-----");
                } else {
                    pemStringBuilder.append("-----BEGIN PUBLIC KEY-----");
                    pemStringBuilder.append(convertXMLRSAPrivateKeyToPEM(XMLSecKeyDoc));
                    pemStringBuilder.append("-----END PUBLIC KEY-----");
                }
                return pemStringBuilder.toString();
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }

    private static int getKeyType(Document xmldoc) {

        Node root = xmldoc.getFirstChild();
        if (!root.getNodeName().equals("RSAKeyValue")) {
            return 0;
        }
        NodeList children = root.getChildNodes();
        if (children.getLength() == PUBLIC_KEY_XML_NODES.length) {
            return PUBLIC_KEY;
        }
        return PRIVATE_KEY;

    }

    private static boolean checkXMLRSAKey(int keyType, Document xmldoc) {

        Node root = xmldoc.getFirstChild();
        NodeList children = root.getChildNodes();
        String[] wantedNodes = {};
        if (keyType == PRIVATE_KEY) {
            wantedNodes = PRIVATE_KEY_XML_NODES;
        } else {
            wantedNodes = PUBLIC_KEY_XML_NODES;
        }
        for (String wantedNode : wantedNodes) {
            boolean found = false;
            for (int i = 0; i < children.getLength(); i++) {
                if (children.item(i).getNodeName().equals(wantedNode)) {
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


    private static String convertXMLRSAPrivateKeyToPEM(Document xmldoc) {

        Node root = xmldoc.getFirstChild();
        NodeList children = root.getChildNodes();

        BigInteger modulus = null, exponent = null, primeP = null, primeQ = null,
                primeExponentP = null, primeExponentQ = null,
                crtCoefficient = null, privateExponent = null;

        for (int i = 0; i < children.getLength(); i++) {

            Node node = children.item(i);
            String textValue = node.getTextContent();
            switch (node.getNodeName()) {
                case "Modulus" -> modulus = new BigInteger(b64decode(textValue));
                case "Exponent" -> exponent = new BigInteger(b64decode(textValue));
                case "P" -> primeP = new BigInteger(b64decode(textValue));
                case "Q" -> primeQ = new BigInteger(b64decode(textValue));
                case "DP" -> primeExponentP = new BigInteger(b64decode(textValue));
                case "DQ" -> primeExponentQ = new BigInteger(b64decode(textValue));
                case "InverseQ" -> crtCoefficient = new BigInteger(b64decode(textValue));
                case "D" -> privateExponent = new BigInteger(b64decode(textValue));
            }

        }

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

    private static String convertXMLRSAPublicKeyToPEM(Document xmldoc) {

        Node root = xmldoc.getFirstChild();
        NodeList children = root.getChildNodes();

        BigInteger modulus = null, exponent = null;

        for (int i = 0; i < children.getLength(); i++) {

            Node node = children.item(i);
            String textValue = node.getTextContent();
            if (node.getNodeName().equals("Modulus")) {
                modulus = new BigInteger(b64decode(textValue));
            } else if (node.getNodeName().equals("Exponent")) {
                exponent = new BigInteger(b64decode(textValue));
            }

        }

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


}
