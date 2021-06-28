package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;

public class CPABEPublicKey extends PublicKey{
    public transient Element g;
    private final byte[] byteArrayG;

    private transient Element h;
    private final byte[] byteArrayH;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    public CPABEPublicKey(Element g, Element h, Element eggAlpha) {
        this.g = g;
        this.byteArrayG= this.g.toBytes();
        this.h = h;
        this.byteArrayH = this.h.toBytes();
        this.eggAlpha = eggAlpha;
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
    }
    public Element getG() { return this.g.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }
    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEPublicKey) {
            CPABEPublicKey that = (CPABEPublicKey)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.h)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
                return false;
            }
            return true;
            //Compare Pairing Parameters
            //return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

//    private void readObject(java.io.ObjectInputStream objectInputStream)
//            throws java.io.IOException, ClassNotFoundException {
//        objectInputStream.defaultReadObject();
//        Pairing pairing = PairingFactory.getPairing(this.getParameters());
//        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
//        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
//        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
//    }

}
