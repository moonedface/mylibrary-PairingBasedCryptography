package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;

public class GroupSignSecretKey extends SecretKey{
    private transient Element Ai;
    private final byte[] byteArrayAi;

    private transient Element xi;
    private final byte[] byteArrayXi;

    public GroupSignSecretKey(Element Ai, Element xi) {
        this.Ai = Ai.getImmutable();
        this.byteArrayAi = this.Ai.toBytes();

        this.xi = xi.getImmutable();
        this.byteArrayXi = this.xi.toBytes();
    }

    public Element getAi() {
        return this.Ai.duplicate();
    }

    public Element getXi() {
        return this.xi.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof GroupSignSecretKey) {
            GroupSignSecretKey that = (GroupSignSecretKey)anObject;
            //compare Ai
            if (!(PairingUtils.isEqualElement(this.Ai, that.Ai))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayAi, that.byteArrayAi)) {
                return false;
            }
            //compare xi
            if (!(PairingUtils.isEqualElement(this.xi, that.xi))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayXi, that.byteArrayXi)) {
                return false;
            }
            //Compare Pairing Parameters
            //return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
