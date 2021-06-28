package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;

public class GroupSignature {
    private transient Element T_1;
    private final byte[] byteArrayT_1;
    private transient Element T_2;
    private final byte[] byteArrayT_2;
    private transient Element c;
    private final byte[] byteArrayC;
    private transient Element s_eta;
    private final byte[] byteArrayS_eta;
    private transient Element s_xi;
    private final byte[] byteArrayS_xi;
    private transient Element s_delta;
    private final byte[] byteArrays_delta;
    public GroupSignature(Element T_1, Element T_2,Element c,Element s_eta,Element s_xi,Element s_delta) {
        this.T_1 = T_1.getImmutable();
        this.byteArrayT_1 = this.T_1.toBytes();
        this.T_2 = T_2.getImmutable();
        this.byteArrayT_2 = this.T_2.toBytes();
        this.c = c.getImmutable();
        this.byteArrayC = this.c.toBytes();
        this.s_eta = s_eta.getImmutable();
        this.byteArrayS_eta = this.s_eta.toBytes();
        this.s_xi = s_xi.getImmutable();
        this.byteArrayS_xi = this.s_xi.toBytes();
        this.s_delta = s_delta.getImmutable();
        this.byteArrays_delta = this.s_delta.toBytes();
    }

    public Element getT_1() {
        return this.T_1.getImmutable();
    }

    public Element getT_2() {
        return this.T_2.getImmutable();
    }

    public Element getC() {
        return this.c.getImmutable();
    }

    public Element getS_eta() {
        return this.s_eta.getImmutable();
    }

    public Element getS_xi() {
        return this.s_xi.getImmutable();
    }

    public Element getS_delta() {
        return this.s_delta.getImmutable();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof GroupSignature) {
            GroupSignature that = (GroupSignature)anObject;
            //compare t_1
            if (!(PairingUtils.isEqualElement(this.T_1, that.T_1))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayT_1, that.byteArrayT_1)) {
                return false;
            }
            //compare T_2
            if (!(PairingUtils.isEqualElement(this.T_2, that.T_2))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayT_2, that.byteArrayT_2)) {
                return false;
            }
            //compare c
            if (!(PairingUtils.isEqualElement(this.c, that.c))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
                return false;
            }
            //compare s_eta
            if (!(PairingUtils.isEqualElement(this.s_eta, that.s_eta))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayS_eta, that.byteArrayS_eta)) {
                return false;
            }
            //compare s_xi
            if (!(PairingUtils.isEqualElement(this.s_xi, that.s_xi))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayS_xi, that.byteArrayS_xi)) {
                return false;
            }
            //compare s_delta
            if (!(PairingUtils.isEqualElement(this.s_delta, that.s_delta))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrays_delta, that.byteArrays_delta)) {
                return false;
            }
            //Compare Pairing Parameters
            //return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
