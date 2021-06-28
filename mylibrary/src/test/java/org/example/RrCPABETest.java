package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.example.crypto.RrCPABE;
import org.example.entity.*;
import org.example.utils.PairingUtils;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class RrCPABETest {
    //public static final String access_policy_example_1 = "0 and 1 and (2 or 3)";
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
    public  void testRrCPABE(){
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Map<Element,Element> RL=new HashMap<>();
        Element u1=pairing.getZr().newElement(23).getImmutable();
        Element u2=pairing.getZr().newElement(24).getImmutable();
        Element u3=pairing.getZr().newElement(25).getImmutable();
        Element u4=pairing.getZr().newElement(26).getImmutable();
        Element u100=pairing.getZr().newElement(100).getImmutable();
        //System.out.println("uk"+u100);

        RrCPABE cpabe=new RrCPABE();
        System.out.println("Setup: ");
        KeyPair keyPair =cpabe.setup(pairingParameters);
        System.out.println("KeyGen: ");
        CPABEPublicKey CPABEPublicKey = (CPABEPublicKey) keyPair.getPublickey();

        RrMasterKey masterKey = (RrMasterKey)keyPair.getMasterKey();
        RrSecretKey secretKey =cpabe.keyGen(pairingParameters, CPABEPublicKey, masterKey,access_policy_threshold_example_1_satisfied01,u100);
        //public Ciphertext encryption(PairingParameters pairingParameters,PublicKey publicKey,int[][] accessPolicyIntArrays, String[] rhos, Element
        //message){
        RL.put(u1,masterKey.getLagrangePolynomial().evaluate(u1).getImmutable());
//   //     System.out.println("setupu1:"+RL.get(u1));
        RL.put(u2,masterKey.getLagrangePolynomial().evaluate(u2).getImmutable());
     //   System.out.println("setupu2:"+RL.get(u2));
        RL.put(u3,masterKey.getLagrangePolynomial().evaluate(u3).getImmutable());
//     //   System.out.println("setupu3:"+RL.get(u3));
        RL.put(u4,masterKey.getLagrangePolynomial().evaluate(u4).getImmutable());
//       // System.out.println("setupu4:"+RL.get(u4));
//        //System.out.println("uukk:"+masterKey.getLagrangePolynomial().evaluate(u100));
        Element p_uk=masterKey.getLagrangePolynomial().evaluate(u100).getImmutable();
        Element message = pairing.getGT().newRandomElement().getImmutable();
        System.out.println(message);
        System.out.println("encryption: ");
        Ciphertext ciphertext=cpabe.encryption(pairingParameters, CPABEPublicKey,accessPolicy1,example_1_rho,message);
        try {
            System.out.println("decryption: ");
            Element plaintext=cpabe.decryption(pairingParameters,  secretKey,accessPolicy1,example_1_rho,ciphertext,RL);
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
