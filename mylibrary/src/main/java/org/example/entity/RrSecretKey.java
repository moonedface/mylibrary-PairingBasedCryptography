package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class RrSecretKey extends SecretKey{
    private transient Element D;
    private final byte[] byteArrayD;

    private transient Element uk;
    private final byte[] byteArrayuk;

    private transient Map<String, Element> Dj;
    private final Map<String, byte[]> byteArraysDj;

    private transient Map<String, Element> Djs;
    private final Map<String, byte[]> byteArraysDjs;

    private transient Map<String, Element> Djss;
    private final Map<String, byte[]> byteArraysDjss;

    public RrSecretKey(Element D, Map<String, Element> Dj, Map<String, Element> Djs,Map<String, Element> Djss,Element uk) {

        this.D = D.getImmutable();
        this.byteArrayD = this.D.toBytes();
        this.uk = uk.getImmutable();
        this.byteArrayuk = this.uk.toBytes();
        this.Dj = new HashMap<String, Element>();
        this.byteArraysDj = new HashMap<String, byte[]>();
        this.Djs = new HashMap<String, Element>();
        this.byteArraysDjs = new HashMap<String, byte[]>();
        this.Djss = new HashMap<String, Element>();
        this.byteArraysDjss = new HashMap<String, byte[]>();

        for (String attribute : Dj.keySet()) {
            this.Dj.put(attribute, Dj.get(attribute).duplicate().getImmutable());
            this.byteArraysDj.put(attribute, Dj.get(attribute).duplicate().getImmutable().toBytes());
            this.Djs.put(attribute, Djs.get(attribute).duplicate().getImmutable());
            this.byteArraysDjs.put(attribute, Djs.get(attribute).duplicate().getImmutable().toBytes());
            this.Djss.put(attribute, Djss.get(attribute).duplicate().getImmutable());
            this.byteArraysDjss.put(attribute, Djss.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public String[] getAttributes() { return this.Dj.keySet().toArray(new String[1]); }

    public Element getD() { return this.D.duplicate(); }

    public Element getUk() { return this.uk.duplicate(); }

    public Element getDjAt(String attribute) { return this.Dj.get(attribute).duplicate(); }

    public Element getDjsAt(String attribute) { return this.Djs.get(attribute).duplicate(); }
    public Element getDjssAt(String attribute) { return this.Djss.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RrSecretKey) {
            RrSecretKey that = (RrSecretKey)anObject;
            //Compare D
            if (!PairingUtils.isEqualElement(this.D, that.D)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
                return false;
            }
//            if (!PairingUtils.isEqualElement(this.uk, that.uk)) {
//                return false;
//            }
//            if (!Arrays.equals(this.byteArrayuk, that.byteArrayuk)) {
//                return false;
//            }
            //compare Dj
            if (!this.Dj.equals(that.Dj)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysDj, that.byteArraysDj)) {
                return false;
            }
            //compare Djs
            if (!this.Djs.equals(that.Djs)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysDjs, that.byteArraysDjs)) {
                return false;
            }
//            if (!this.Djss.equals(that.Djss)) {
//                return false;
//            }
//            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysDjss, that.byteArraysDjss)) {
//                return false;
//            }
            return true;
            //Compare Pairing Parameters
            // return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
