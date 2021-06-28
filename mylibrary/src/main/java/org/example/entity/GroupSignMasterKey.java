package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;

public class GroupSignMasterKey extends MasterKey {
    private transient Element kesi;
    private final byte[] byteArrayKesi;

    private transient Element gamma;
    private final byte[] byteArrayGamma;

    public GroupSignMasterKey(Element kesi, Element gamma) {
        this.kesi = kesi.getImmutable();
        this.byteArrayKesi = this.kesi.toBytes();

        this.gamma = gamma.getImmutable();
        this.byteArrayGamma = this.gamma.toBytes();
    }

    public Element getKesi() {
        return this.kesi.duplicate();
    }

    public Element getGamma() {
        return this.gamma.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof GroupSignMasterKey) {
            GroupSignMasterKey that = (GroupSignMasterKey)anObject;
            //compare kesi
            if (!(PairingUtils.isEqualElement(this.kesi, that.kesi))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayKesi, that.byteArrayKesi)) {
                return false;
            }
            //compare gamma
            if (!(PairingUtils.isEqualElement(this.gamma, that.gamma))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGamma, that.byteArrayGamma)) {
                return false;
            }
            //Compare Pairing Parameters
            //return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
