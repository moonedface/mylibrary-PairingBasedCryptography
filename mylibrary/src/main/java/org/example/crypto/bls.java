package org.example.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

public class bls {

    public static void main(String[] args) {
        //方式一：通过文件读取产生，将JPBC库中的Type A曲线对应的参数文件a.properties直接存放在该project下
        //jpbc库中的椭圆曲线参数文件存放在params文件夹中
        //  Pairing pairing = PairingFactory.getPairing("a.properties");

        //方式二：直接通过代码产生
        int rBits = 160;
        int qBits = 512;
        //生成一个椭圆曲线生成器Apg
        TypeACurveGenerator Apg=new TypeACurveGenerator(rBits,qBits);
        //生成配对参数
        PairingParameters typeAParams=Apg.generate();
        //初始化一个Pairing实例
        Pairing pairing= PairingFactory.getPairing(typeAParams);


        Field G1=pairing.getG1();
        Field GT=pairing.getGT();
        Field Zr=pairing.getZr();
        Element g=G1.newRandomElement().getImmutable();
        Element s=Zr.newRandomElement().getImmutable();
        String message="welcome";
        byte[] m=message.getBytes();
        Element hm=pairing.getG1().newRandomElement().setFromHash(m,0,m.length).getImmutable();
        //pk=g^s
        Element pk=g.powZn(s).getImmutable();
        //签名为H(m)^s
        //验证：e(g,H(M)^s)==e(g^s,H(m))
        Element sigma=hm.powZn(s).getImmutable();
        Element egshm=pairing.pairing(g,sigma);
        Element esghm=pairing.pairing(pk,hm);
        System.out.println(egshm.isEqual(esghm));
        //g^1/beta
        //g^alpha
        //g^beta
        //egg
        Element egg=pairing.pairing(g,g);
        Element alpha=Zr.newRandomElement().getImmutable();
        Element beta=Zr.newRandomElement().getImmutable();
        Element g_alpha=g.powZn(alpha).getImmutable();
        Element g_beta=g.powZn(beta).getImmutable();
        Element invertbeta=beta.invert().getImmutable();
        Element g_1_beta=g.powZn(beta.invert()).getImmutable();
        Element eggbeta=pairing.pairing(g_beta,g_1_beta).getImmutable();
        System.out.println(egg.isEqual(eggbeta));
        //验证论文中的e(g^a+r/beta,gbeta)=e(g,g)^a*e(g^v1,g^v2)
        Element v1=Zr.newRandomElement().getImmutable();
        Element v2=Zr.newRandomElement().getImmutable();
        Element ver1=g.powZn(v1).getImmutable();
        Element ver2=g.powZn(v2).getImmutable();
        Element r=v1.mul(v2).getImmutable();
        //a+r/beta
        Element arb=(alpha.add(r)).mul(invertbeta).getImmutable();
        //g^a+r/beta
        Element D=g.powZn(arb).getImmutable();
        //e(g^a+r/beta,gbeta)
        Element eggarbb=pairing.pairing(D,g_beta).getImmutable();
        //eggalpha
        Element eggalpha=egg.powZn(alpha);
        //eggv1v2
        Element eggv1v2=pairing.pairing(ver1,ver2).getImmutable();
        System.out.println(eggarbb.isEqual(eggalpha.mul(eggv1v2).getImmutable()));

    }
}
