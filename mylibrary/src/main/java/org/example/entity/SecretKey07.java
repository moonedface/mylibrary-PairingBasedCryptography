package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import org.example.utils.PairingUtils;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SecretKey07 extends SecretKey{
    private transient Element D;
    private final byte[] byteArrayD;

    private transient Map<String, Element> Dj;
    private final Map<String, byte[]> byteArraysDj;

    private transient Map<String, Element> Djs;
    private final Map<String, byte[]> byteArraysDjs;

    public SecretKey07(Element D, Map<String, Element> Dj, Map<String, Element> Djs) {

        this.D = D.getImmutable();
        this.byteArrayD = this.D.toBytes();

        this.Dj = new HashMap<String, Element>();
        this.byteArraysDj = new HashMap<String, byte[]>();
        this.Djs = new HashMap<String, Element>();
        this.byteArraysDjs = new HashMap<String, byte[]>();

        for (String attribute : Dj.keySet()) {
            this.Dj.put(attribute, Dj.get(attribute).duplicate().getImmutable());
            this.byteArraysDj.put(attribute, Dj.get(attribute).duplicate().getImmutable().toBytes());
            this.Djs.put(attribute, Djs.get(attribute).duplicate().getImmutable());
            this.byteArraysDjs.put(attribute, Djs.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public String[] getAttributes() { return this.Dj.keySet().toArray(new String[1]); }

    public Element getD() { return this.D.duplicate(); }

    public Element getDjAt(String attribute) { return this.Dj.get(attribute).duplicate(); }

    public Element getDjsAt(String attribute) { return this.Djs.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof SecretKey07) {
            SecretKey07 that = (SecretKey07)anObject;
            //Compare D
            if (!PairingUtils.isEqualElement(this.D, that.D)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
                return false;
            }
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
            return true;
            //Compare Pairing Parameters
           // return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

//    private void readObject(java.io.ObjectInputStream objectInputStream)
//            throws java.io.IOException, ClassNotFoundException {
//        objectInputStream.defaultReadObject();
//        Pairing pairing = PairingFactory.getPairing(this.getParameters());
//        this.D = pairing.getG1().newElementFromBytes(this.byteArrayD);
//        this.Dj = new HashMap<String, Element>();
//        this.Djs = new HashMap<String, Element>();
//        for (String attribute : this.byteArraysDj.keySet()) {
//            this.Dj.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysDj.get(attribute)).getImmutable());
//            this.Djs.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysDjs.get(attribute)).getImmutable());
//        }
    }
