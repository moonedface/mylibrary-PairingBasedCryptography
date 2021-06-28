package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Ciphertext {
    //访问树
    private final String[] rhos;
    //c=me(g,g)s
    private transient Element CPrime;
    private final byte[] byteArrayCPrime;
    //c
    private transient Element C;
    private final byte[] byteArrayC;
    //cy
    private transient Map<String, Element> C1s;
    private final byte[][] byteArraysC1s;
    //cy'
    private transient Map<String, Element> C2s;
    private final byte[][] byteArraysC2s;
    public Ciphertext(Element CPrime,Element C, Map<String, Element> C1s, Map<String, Element> C2s) {

        this.rhos = C1s.keySet().toArray(new String[1]);

        this.CPrime = CPrime.getImmutable();
        this.byteArrayCPrime = this.CPrime.toBytes();

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();

        this.C1s = new HashMap<String, Element>();
        this.byteArraysC1s = new byte[this.rhos.length][];

        this.C2s = new HashMap<String, Element>();
        this.byteArraysC2s = new byte[this.rhos.length][];

        for (int i = 0; i < this.rhos.length; i++) {
            Element C1 = C1s.get(this.rhos[i]).duplicate().getImmutable();
            this.C1s.put(this.rhos[i], C1);
            this.byteArraysC1s[i] = C1.toBytes();

            Element C2 = C2s.get(this.rhos[i]).duplicate().getImmutable();
            this.C2s.put(this.rhos[i], C2);
            this.byteArraysC2s[i] = C2.toBytes();
        }
    }
    public Element getC() { return this.C.duplicate(); }

    public Element getC1sAt(String rho) { return this.C1s.get(rho).duplicate(); }

    public Element getC2sAt(String rho) { return this.C2s.get(rho).duplicate(); }
    public Element getCPrime() { return this.CPrime.duplicate(); }
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof Ciphertext) {
            Ciphertext that = (Ciphertext)anObject;
            //Compare C
            if (!PairingUtils.isEqualElement(this.C, that.C)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
                return false;
            }
            //Compare C1s
            if (!this.C1s.equals(that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare C2s
            if (!this.C2s.equals(that.C2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC2s, that.byteArraysC2s)) {
                return false;
            }
            //Compare CPrime
            return PairingUtils.isEqualElement(this.CPrime, that.CPrime)
                    && Arrays.equals(this.byteArrayCPrime, that.byteArrayCPrime);
        }
        return false;
    }
}
