package org.example.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.example.UnsatisfiedAccessControlException;
import org.example.entity.*;
import org.example.utils.PairingUtils;

import java.util.HashMap;
import java.util.Map;

public class CPABE {
    //初始化
    public KeyPair setup(PairingParameters pairingParameters){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element gAlpha = g.powZn(alpha).getImmutable();
        Element h = g.powZn(beta).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        return new KeyPair(
                new CPABEPublicKey(g,h,eggAlpha),
                new MasterKey07(gAlpha, beta));
    }
    //密钥生成
    public SecretKey07 keyGen(PairingParameters pairingParameters, CPABEPublicKey CPABEPublicKey, MasterKey07 masterKey07, String[] attributes){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Map<String, Element> D1s = new HashMap<String, Element>();
        Map<String, Element> D2s = new HashMap<String, Element>();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element D = masterKey07.getGAlpha().mul(CPABEPublicKey.getG().powZn(r)).powZn(masterKey07.getBeta().invert()).getImmutable();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            D1s.put(attribute, CPABEPublicKey.getG().powZn(r).mul(elementAttribute.powZn(ri)).getImmutable());
            D2s.put(attribute, CPABEPublicKey.getG().powZn(ri).getImmutable());
        }
        return new SecretKey07(D, D1s, D2s);
    }
    //加密
    public Ciphertext encryption(PairingParameters pairingParameters, CPABEPublicKey CPABEPublicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message){
        //生成访问控制树
        AccessTreeNode rootTreeNode=AccessTreeNode.GenerateAccessTree(accessPolicyIntArrays,rhos);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element s = pairing.getZr().newRandomElement().getImmutable();
        //eggs
        Element sessionKey = CPABEPublicKey.getEggAlpha().powZn(s).getImmutable();
        //c=h^s
        Element C= CPABEPublicKey.getH().powZn(s).getImmutable();
        //构建加密的访问控制树
        AccessTree accessTree=new AccessTree(rootTreeNode,accessPolicyIntArrays,rhos);
        //lambdas表示CP-ABE中的叶子节点集合
        Map<String, Element> lambdas = accessTree.secretSharing(pairing, s,rootTreeNode);
        Map<String, Element> C1s = new HashMap<String, Element>();
        Map<String, Element> C2s = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            C1s.put(rho, CPABEPublicKey.getG().powZn(lambdas.get(rho)).getImmutable());
            C2s.put(rho, PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1).powZn(lambdas.get(rho)).getImmutable());
        }
        Element CPrime = sessionKey.mul(message).getImmutable();
        return new Ciphertext( CPrime, C, C1s, C2s);
    }
    //解密
    public Element decryption(PairingParameters pairingParameters,  SecretKey07 secretKey07,
                              int[][] accessPolicyIntArrays, String[] rhos, Ciphertext ciphertext)throws InvalidCipherTextException {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        //构建访问树的根节点
        AccessTreeNode rootTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicyIntArrays, rhos);
        //构建访问树
        AccessTree accessTree=new AccessTree(rootTreeNode,accessPolicyIntArrays,rhos);
        Map<String, Element> omegaElementsMap = null;
        try {
            //属性和属性对应的拉格朗日系数
            omegaElementsMap = accessTree.reconstructOmegas(pairing, secretKey07.getAttributes(), rootTreeNode);
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element D1 = secretKey07.getDjAt(attribute);
                Element D2 = secretKey07.getDjsAt(attribute);
                Element C1 = ciphertext.getC1sAt(attribute);
                Element C2 = ciphertext.getC2sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(D1, C1).div(pairing.pairing(D2, C2)).powZn(lambda)).getImmutable();
            }
            Element sessionKey = pairing.pairing(ciphertext.getC(), secretKey07.getD()).div(A).getImmutable();
            return ciphertext.getCPrime().div(sessionKey).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

}
