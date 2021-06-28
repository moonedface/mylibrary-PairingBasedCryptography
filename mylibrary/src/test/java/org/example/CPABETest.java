package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.example.crypto.CPABE;
import org.example.entity.*;
import org.example.utils.PairingUtils;
import org.junit.Test;

public class CPABETest {
    public static final String access_policy_example_1 = "0 and 1 and (2 or 3)";
    public static final int[][]  accessPolicy1={
            {3, 2, 1, 2, 3},
            {3, 2, -1, -2, -3},
            {3, 2, -4, -5, -6},
            {3, 2, -7, -8, 4},
            {4, 3, -9, -10, -11, -12},
    };
    public static final String[] example_1_rho = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10","11",
    };
    public static final String[] access_policy_threshold_example_1_satisfied01 = new String[] {
            "0", "1", "3", "4",
    };
    public static final String[] access_policy_threshold_example_1_unsatisfied01 = new String[] {
            "0", "3", "6", "8", "9",
    };
    @Test
    public  void testCPABE(){
        PairingParameters pairingParameters =PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        CPABE cpabe=new CPABE();
        System.out.println("Setup: ");
        KeyPair keyPair =cpabe.setup(pairingParameters);
        System.out.println("KeyGen: ");
        CPABEPublicKey CPABEPublicKey = (CPABEPublicKey) keyPair.getPublickey();
        MasterKey07 masterKey07 = (MasterKey07)keyPair.getMasterKey();
        SecretKey07 secretKey07 =cpabe.keyGen(pairingParameters, CPABEPublicKey, masterKey07,access_policy_threshold_example_1_satisfied01);
        //public Ciphertext encryption(PairingParameters pairingParameters,PublicKey publicKey,int[][] accessPolicyIntArrays, String[] rhos, Element
        //message){

        Element message = pairing.getGT().newRandomElement().getImmutable();
        System.out.println(message);
        System.out.println("encryption: ");
        Ciphertext ciphertext=cpabe.encryption(pairingParameters, CPABEPublicKey,accessPolicy1,example_1_rho,message);
        try {
            System.out.println("decryption: ");
            Element plaintext=cpabe.decryption(pairingParameters,  secretKey07,accessPolicy1,example_1_rho,ciphertext);
            System.out.println(plaintext);
        } catch (InvalidCipherTextException e) {
            System.out.println("Access policy satisfied test failed ");
        }catch (Exception e) {
        System.out.println("Access policy satisfied test failed ");
        e.printStackTrace();
        System.exit(1);
        }
    }

}
