package org.example.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.example.UnsatisfiedAccessControlException;
import org.example.entity.*;
import org.example.utils.LagrangePolynomial;
import org.example.utils.PairingUtils;

import java.util.HashMap;
import java.util.Map;

public class RrCPABE {
    //初始化
    public KeyPair setup(PairingParameters pairingParameters){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element gAlpha = g.powZn(alpha).getImmutable();
        Element h = g.powZn(beta).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        //创建一个阶为t的多项式（t表示阈值）p，p（0）=secret
        final int RL_max=4;
        Element P_0=pairing.getZr().newRandomElement().getImmutable();
        LagrangePolynomial P = new LagrangePolynomial(pairing, RL_max, P_0);
        return new KeyPair(
                new CPABEPublicKey(g,h,eggAlpha),
                new RrMasterKey(gAlpha, beta,P));
    }
    //密钥生成
    public RrSecretKey keyGen(PairingParameters pairingParameters, CPABEPublicKey CPABEPublicKey,
                            RrMasterKey RrmasterKey, String[] attributes,Element uk)
    {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        Map<String, Element> Dj = new HashMap<String, Element>();
        Map<String, Element> Djs = new HashMap<String, Element>();
        Map<String, Element> Djss = new HashMap<String, Element>();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element zero=pairing.getZr().newZeroElement().getImmutable();
        Element D = RrmasterKey.getGAlpha().mul(CPABEPublicKey.getG().powZn(r)).powZn(RrmasterKey.getBeta().invert()).getImmutable();
        Element P_uk=RrmasterKey.getLagrangePolynomial().evaluate(uk).getImmutable();

       Element P_0=RrmasterKey.getLagrangePolynomial().evaluate(zero).getImmutable();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Element riP_0=ri.mul(P_0).getImmutable();
            Dj.put(attribute, CPABEPublicKey.getG().powZn(r).mul(elementAttribute.powZn(riP_0)).getImmutable());
            Djs.put(attribute, CPABEPublicKey.getG().powZn(ri).getImmutable());
            Djss.put(attribute, Djs.get(attribute).powZn(P_uk).getImmutable());
        }
        return new RrSecretKey(D,Dj,Djs,Djss,uk);
    }
    //加密
    public Ciphertext encryption(PairingParameters pairingParameters, CPABEPublicKey CPABEPublicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message){
        //生成访问控制树
        AccessTreeNode rootTreeNode=AccessTreeNode.GenerateAccessTree(accessPolicyIntArrays,rhos);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element s = pairing.getZr().newRandomElement().getImmutable();
        //eggas
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
    public Element decryption(PairingParameters pairingParameters,  RrSecretKey RrsecretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, Ciphertext ciphertext, Map<Element,Element> RL)throws InvalidCipherTextException {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        AccessTreeNode rootTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicyIntArrays, rhos);
        AccessTree accessTree=new AccessTree(rootTreeNode,accessPolicyIntArrays,rhos);
        Map<String, Element> omegaElementsMap = null;
        try {
            omegaElementsMap = accessTree.reconstructOmegas(pairing, RrsecretKey.getAttributes(), rootTreeNode);
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element Dj = RrsecretKey.getDjAt(attribute).getImmutable();
                Element Djs = RrsecretKey.getDjsAt(attribute).getImmutable();
                Element Djss=RrsecretKey.getDjssAt(attribute).getImmutable();
                Element C1 = ciphertext.getC1sAt(attribute).getImmutable();
                Element C2 = ciphertext.getC2sAt(attribute).getImmutable();
                Element uk=RrsecretKey.getUk().getImmutable();
               Element result=pairing.getZr().newZeroElement().getImmutable();
                for(Element u_i:RL.keySet()){
                    //            Element member = pairing.getZr().newZeroElement()
                    //                    .sub(elementSet[i]).getImmutable();

                    Element denominator = uk.sub(u_i).getImmutable();
                    //                    .getImmutable();
                    Element u_kk=uk.mul(denominator.invert()).getImmutable();
                    Element lambda_i=u_kk.mul(LagrangePolynomial.lamda_i(pairing,RL.keySet(),u_i)).getImmutable();
                    Element l_p=lambda_i.mul(RL.get(u_i)).getImmutable();
                    result=result.add(l_p);

                }
                Element lambda_k=LagrangePolynomial.lamda_i(pairing,RL.keySet(),uk).getImmutable();
   //             Element l_pk=lambda_k.mul(masterKey.getLagrangePolynomial().evaluate(uk)).getImmutable();
   //             Element p_0=l_pk.add(result).getImmutable();
                //System.out.println("验证p_0:"+p_0);
                //System.out.println("验证p_0:"+p_0);
                //attribute对应的叶子节点
                Element lambda = omegaElementsMap.get(attribute).getImmutable();
                Element C3=C2.powZn(result).getImmutable();
                Element denominator1=pairing.pairing(Djss, C2).powZn(lambda_k).getImmutable();
                Element denominator2=pairing.pairing(Djs, C3).getImmutable();

                A= A.mul(pairing.pairing(Dj,C1).div(denominator1.mul(denominator2)).powZn(lambda)).getImmutable();
            }
            Element sessionKey = pairing.pairing(ciphertext.getC(), RrsecretKey.getD()).div(A).getImmutable();
            return ciphertext.getCPrime().div(sessionKey).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }
}
