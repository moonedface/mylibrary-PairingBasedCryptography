package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.LagrangePolynomial;
import org.example.utils.PairingUtils;

import java.util.Arrays;

public class RrMasterKey extends MasterKey{
    private transient Element gAlpha;
    private final byte[] byteArrayGAlpha;

    private transient Element beta;
    private final byte[] byteArrayBeta;

    private final LagrangePolynomial lagrangePolynomial;
    //private final byte[] byteArrayLagrangePolynomial;

    public RrMasterKey( Element gAlpha, Element beta,LagrangePolynomial lagrangePolynomial) {
        this.gAlpha = gAlpha.getImmutable();
        this.byteArrayGAlpha = this.gAlpha.toBytes();

        this.beta = beta.getImmutable();
        this.byteArrayBeta = this.beta.toBytes();
        //需要序列化该对象
        this.lagrangePolynomial=lagrangePolynomial;
       // this.byteArrayLagrangePolynomial=this.lagrangePolynomial.
    }

    public Element getGAlpha() { return this.gAlpha.duplicate(); }

    public Element getBeta() { return this.beta.duplicate(); }
    public LagrangePolynomial getLagrangePolynomial(){ return this.lagrangePolynomial;}
    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RrMasterKey) {
            RrMasterKey that = (RrMasterKey)anObject;
            //compare gAlpha
            if (!(PairingUtils.isEqualElement(this.gAlpha, that.gAlpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGAlpha, that.byteArrayGAlpha)) {
                return false;
            }
            //compare beta
            if (!(PairingUtils.isEqualElement(this.beta, that.beta))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayBeta, that.byteArrayBeta)) {
                return false;
            }
            //Compare Pairing Parameters
            //return this.getParameters().toString().equals(that.getParameters().toString());
            //比较多项式
        }
        return false;
    }
}
