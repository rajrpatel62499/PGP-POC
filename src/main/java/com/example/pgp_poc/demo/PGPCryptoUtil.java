package com.example.pgp_poc.demo;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.Security;
import java.security.SecureRandom;
import java.util.Date;

public class PGPCryptoUtil {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] encrypt(String message, PGPPublicKey publicKey) throws Exception {
        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(encOut);

        ByteArrayOutputStream literalOut = new ByteArrayOutputStream();
        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        try (OutputStream pOut = lGen.open(literalOut, PGPLiteralData.BINARY, "message", message.getBytes().length, new Date())) {
            pOut.write(message.getBytes());
        }

        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        try (OutputStream encOutStream = encGen.open(armoredOut, literalOut.toByteArray().length)) {
            encOutStream.write(literalOut.toByteArray());
        }

        armoredOut.close();
        return encOut.toByteArray();
    }

    public static String decrypt(byte[] encryptedData, PGPPrivateKey privateKey) throws Exception {
        InputStream in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptedData));
        PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
        Object o = pgpF.nextObject();
        PGPEncryptedDataList enc;

        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) enc.get(0);

        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
        PGPLiteralData ld = (PGPLiteralData) plainFact.nextObject();

        InputStream unc = ld.getInputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;
        while ((ch = unc.read()) >= 0) {
            out.write(ch);
        }
        return out.toString();
    }
}
