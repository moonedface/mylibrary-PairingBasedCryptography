package org.example.entity;

public class KeyPair {
    private PublicKey publickey;
    private MasterKey masterKey;
    public KeyPair(){

    }
    public KeyPair(PublicKey publickey, MasterKey masterKey) {
        this.publickey = publickey;
        this.masterKey = masterKey;
    }

    public PublicKey getPublickey() {
        return publickey;
    }

    public MasterKey getMasterKey() {
        return masterKey;
    }

    public void setPublickey(PublicKey publickey) {
        this.publickey = publickey;
    }

    public void setMasterKey(MasterKey masterKey) {
        this.masterKey = masterKey;
    }
}
