package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.example.entity.*;
import org.example.sign.GroupSignatureEngine;
import org.example.utils.PairingUtils;
import org.junit.Test;

public class GroupSignatureTest {
    @Test
    public void testGroupSignature(){
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        GroupSignatureEngine engine=new GroupSignatureEngine();
        System.out.println("Setup: ");
        KeyPair keyPair =engine.setup(pairingParameters);
        System.out.println("KeyGen: ");
        GroupSignPublicKey publicKey = (GroupSignPublicKey) keyPair.getPublickey();
        GroupSignMasterKey masterKey = (GroupSignMasterKey)keyPair.getMasterKey();
        GroupSignSecretKey secretKey =engine.keyGen(pairingParameters, publicKey, masterKey);
        Element message = pairing.getGT().newRandomElement().getImmutable();
        System.out.println(message);
        System.out.println("signature: ");
        GroupSignature signature=engine.sign(pairingParameters, publicKey,secretKey,message);
            System.out.println("verify: ");
            boolean result=engine.verify(pairingParameters,message,publicKey,signature);
            System.out.println(result);

        }
}
