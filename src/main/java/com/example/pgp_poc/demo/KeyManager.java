package com.example.pgp_poc.demo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;


import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;

public class KeyManager {

    public static PGPPublicKey loadPublicKey(String resourcePath) throws Exception {
        InputStream in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
                new ClassPathResource(resourcePath).getInputStream()
        );
        PGPPublicKeyRingCollection keyRings = new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        for (PGPPublicKeyRing keyRing : keyRings) {
            for (PGPPublicKey key : keyRing) {
                if (key.isEncryptionKey()) return key;
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    public static PGPPrivateKey loadPrivateKey(String resourcePath, String passphrase) throws Exception {
        InputStream in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(
                new ClassPathResource(resourcePath).getInputStream()
        );
        PGPSecretKeyRingCollection keyRings = new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        for (PGPSecretKeyRing keyRing : keyRings) {
            for (PGPSecretKey key : keyRing) {
                if (key.isSigningKey()) {
                    return key.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider( new BouncyCastleProvider()).build(passphrase.toCharArray()));
                }
            }
        }
        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }
}
