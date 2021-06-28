package org.example.sign;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.example.entity.*;
import org.example.utils.PairingUtils;

import java.util.ArrayList;
import java.util.List;

//群签名算法实现
public class GroupSignatureEngine {
    //初始化
    public KeyPair setup(PairingParameters pairingParameters){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element kesi = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();
        Element u=pairing.getG1().newRandomElement().getImmutable();
        Element v=u.powZn(kesi).getImmutable();
        Element omega=g2.powZn(gamma).getImmutable();
        return new KeyPair(
                new GroupSignPublicKey(g1,g2,u,v,omega),
                new GroupSignMasterKey(kesi, gamma));
    }
    //生成密钥
    public GroupSignSecretKey keyGen(PairingParameters pairingParameters,GroupSignPublicKey publicKey,GroupSignMasterKey masterKey){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element xi=pairing.getZr().newRandomElement().getImmutable();
        Element g1=publicKey.getG1().getImmutable();
        Element gamma=masterKey.getGamma().getImmutable();
        Element Ai=g1.powZn(xi.add(gamma).invert()).getImmutable();
        return new GroupSignSecretKey(Ai,xi);
    }
    //签名
    public org.example.entity.GroupSignature sign(PairingParameters pairingParameters, GroupSignPublicKey publicKey, GroupSignSecretKey secretKey, Element message){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element eta=pairing.getZr().newRandomElement().getImmutable();
        Element T_1=publicKey.getU().powZn(eta).getImmutable();
        Element T_2=secretKey.getAi().mul(publicKey.getV().powZn(eta)).getImmutable();
        Element delta=secretKey.getXi().mul(eta).getImmutable();
        Element r_eta=pairing.getZr().newRandomElement().getImmutable();
        Element r_xi=pairing.getZr().newRandomElement().getImmutable();
        Element r_delta=pairing.getZr().newRandomElement().getImmutable();
        Element R_1=publicKey.getU().powZn(r_eta).getImmutable();
        Element R_2stemp1=pairing.pairing(T_2,publicKey.getG2()).powZn(r_eta).getImmutable();
        Element zero=pairing.getZr().newZeroElement().getImmutable();
        Element R_2stemp2=pairing.pairing(publicKey.getV(),publicKey.getOmega()).powZn(zero.sub(r_eta)).getImmutable();
        Element R_2stemp3=pairing.pairing(publicKey.getV(),publicKey.getG2()).powZn(zero.sub(r_eta)).getImmutable();
        Element R_2=R_2stemp1.mul(R_2stemp2).mul(R_2stemp3).getImmutable();
        Element R_3=T_1.powZn(r_xi).mul(publicKey.getU().powZn(zero.sub(r_delta))).getImmutable();
        List<Element> list=new ArrayList<>();
        list.add(0,message.duplicate().getImmutable());
        list.add(1,T_1.duplicate().getImmutable());
        list.add(2,T_2.duplicate().getImmutable());
        list.add(3,R_1.duplicate().getImmutable());
        list.add(4,R_2.duplicate().getImmutable());
        list.add(5,R_3.duplicate().getImmutable());
        Element c=computeC(pairing,list);
        Element s_eta=r_eta.add(c.mul(eta)).getImmutable();
        Element s_xi=r_xi.add(c.mul(secretKey.getXi())).getImmutable();
        Element s_delta=r_delta.add(c.mul(delta)).getImmutable();
        return new org.example.entity.GroupSignature(T_1,T_2,c,s_eta,s_xi,s_delta);
    }
    public Element computeC(Pairing pairing,List<Element> list){
        int c_length=0;
        for(int i=0;i<list.size();i++){
            c_length=c_length+list.get(i).getLengthInBytes();
        }
        byte[] c_byte=new byte[c_length];
        int start=0;
        for(int i=0;i<list.size();i++){
            int length=list.get(i).getLengthInBytes();
            System.arraycopy(list.get(i).toBytes(),0,c_byte,start,length);
            start=start+length;
        }
        Element c=PairingUtils.MapByteArrayToGroup(pairing,c_byte, PairingUtils.PairingGroupType.Zr).getImmutable();
        return c;
    }
    //验证
    public boolean verify(PairingParameters pairingParameters, Element message, GroupSignPublicKey publicKey,GroupSignature signature){
        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        Element c=signature.getC().getImmutable();
        Element T_1=signature.getT_1().getImmutable();
        Element T_2=signature.getT_2().getImmutable();
        Element s_xi=signature.getS_xi().getImmutable();
        Element s_eta=signature.getS_eta().getImmutable();
        Element s_delta=signature.getS_delta().getImmutable();

        Element g1=publicKey.getG1().getImmutable();
        Element g2=publicKey.getG2().getImmutable();
        Element v=publicKey.getV().getImmutable();
        Element u=publicKey.getU().getImmutable();
        Element omega=publicKey.getOmega().getImmutable();
        Element zero=pairing.getZr().newZeroElement().getImmutable();

        Element R_1_1=u.powZn(s_eta).getImmutable();
        Element R_1_2=T_1.powZn(c).getImmutable();
        Element R_1=R_1_1.mul(R_1_2.invert()).getImmutable();

        Element R_2_1=pairing.pairing(T_2,g2).powZn(s_xi).getImmutable();
        Element R_2_2=pairing.pairing(v,omega).powZn(zero.sub(s_eta)).getImmutable();
        Element R_2_3=pairing.pairing(v,g2).powZn(zero.sub(s_delta)).getImmutable();
        Element R_2_4=pairing.pairing(T_2,omega).getImmutable();
        Element R_2_5=pairing.pairing(g1,g2).invert().getImmutable();
        Element R_2_45=R_2_4.mul(R_2_5).powZn(c).getImmutable();
        Element R_2_123=R_2_1.mul(R_2_2).mul(R_2_3).getImmutable();
        Element R_2=R_2_123.mul(R_2_45).getImmutable();

        Element R_3_1=T_1.powZn(s_xi).getImmutable();
        Element R_3_2=u.powZn(s_delta).invert().getImmutable();
        Element R_3=R_3_1.mul(R_3_2).getImmutable();
        List<Element> list=new ArrayList<>();
        list.add(0,message.duplicate().getImmutable());
        list.add(1,T_1.duplicate().getImmutable());
        list.add(2,T_2.duplicate().getImmutable());
        list.add(3,R_1.duplicate().getImmutable());
        list.add(4,R_2.duplicate().getImmutable());
        list.add(5,R_3.duplicate().getImmutable());
        Element c_s=computeC(pairing,list);
        return c.isEqual(c_s);
    }


}
