package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.example.utils.LagrangePolynomial;
import org.example.utils.PairingUtils;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class LagelangriTest {
    @Test
    public void testLagelangri(){
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        Element P_0=pairing.getZr().newElement(111).getImmutable();
        LagrangePolynomial P = new LagrangePolynomial(pairing, 4, P_0);
        Map<Element,Element> RL=new HashMap<>();
        Element u1=pairing.getZr().newElement(23).getImmutable();
        Element u2=pairing.getZr().newElement(24).getImmutable();
        Element u3=pairing.getZr().newElement(25).getImmutable();
        Element u4=pairing.getZr().newElement(26).getImmutable();
        Element u100=pairing.getZr().newElement(100).getImmutable();
        RL.put(u1,P.evaluate(u1));
        RL.put(u2,P.evaluate(u2));
        RL.put(u3,P.evaluate(u3));
        RL.put(u4,P.evaluate(u4));

        Element result=pairing.getZr().newZeroElement().getImmutable();
        for(Element u_i:RL.keySet()){
            //            Element member = pairing.getZr().newZeroElement()
            //                    .sub(elementSet[i]).getImmutable();
                      Element denominator = u100.sub(u_i).getImmutable();
            //                    .getImmutable();
            Element u_kk=u100.mul(denominator.invert()).getImmutable();
            Element lambda_i=u_kk.mul(LagrangePolynomial.lamda_i(pairing,RL.keySet(),u_i)).getImmutable();
            Element l_p=lambda_i.mul(RL.get(u_i)).getImmutable();
            result=result.add(l_p);

        }
        Element lambda_k=LagrangePolynomial.lamda_i(pairing,RL.keySet(),u100).getImmutable();
        Element l_pk=lambda_k.mul(P.evaluate(u100)).getImmutable();
        Element p_0=l_pk.add(result).getImmutable();
        System.out.println(p_0);
        System.out.println(P_0);


    }

}
