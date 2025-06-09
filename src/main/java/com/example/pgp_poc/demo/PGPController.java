package com.example.pgp_poc.demo;


import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/pgp")
public class PGPController {


    private final PGPPublicKey publicKey;
    private final PGPPrivateKey privateKey;

    public PGPController() throws Exception {
        this.publicKey = KeyManager.loadPublicKey("keys/public.asc");
        this.privateKey = KeyManager.loadPrivateKey("keys/private.asc", "rajrpatel");
    }

    @PostMapping("/encrypt")
    public String encrypt(@RequestBody String message) throws Exception {
        byte[] encrypted = PGPCryptoUtil.encrypt(message, publicKey);
        return new String(encrypted);
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody String encryptedText) throws Exception {
        return PGPCryptoUtil.decrypt(encryptedText.getBytes(), privateKey);
    }

    // # Post Message - encrypt with their key and
}

