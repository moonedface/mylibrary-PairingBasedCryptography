package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;

public class GroupSignPublicKey extends PublicKey {
    public transient Element g1;
    private final byte[] byteArrayG1;

    public transient Element g2;
    private final byte[] byteArrayG2;
    private transient Element u;
    private final byte[] byteArrayU;

    private transient Element v;
    private final byte[] byteArrayV;
    private transient Element omega;
    private final byte[] byteArrayOmega;

    public GroupSignPublicKey(Element g1, Element g2, Element u, Element v,Element omega) {
        this.g1 = g1;
        this.byteArrayG1= this.g1.toBytes();
        this.g2 = g2;
        this.byteArrayG2= this.g2.toBytes();
        this.u = u;
        this.byteArrayU= this.u.toBytes();
        this.v = v;
        this.byteArrayV= this.v.toBytes();
        this.omega = omega;
        this.byteArrayOmega= this.omega.toBytes();
    }

    public Element getG1() {
        return this.g1.duplicate();
    }

    public Element getG2() {
        return this.g2.duplicate();
    }

    public Element getU() {
        return this.u.duplicate();
    }

    public Element getV() {
        return this.v.duplicate();
    }

    public Element getOmega() {
        return this.omega.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof GroupSignPublicKey) {
            GroupSignPublicKey that = (GroupSignPublicKey)anObject;
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.g1)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1, that.byteArrayG1)) {
                return false;
            }
            //Compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.g2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2, that.byteArrayG2)) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.u)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.v)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
                return false;
            }
            //Compare omega
            if (!PairingUtils.isEqualElement(this.omega, that.omega)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayOmega, that.byteArrayOmega)) {
                return false;
            }
            return true;
            //Compare Pairing Parameters
            //return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
