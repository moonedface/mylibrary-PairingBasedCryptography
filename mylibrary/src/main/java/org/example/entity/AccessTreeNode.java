package org.example.entity;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;


public class AccessTreeNode {
    private static int numberOfLeafNodes = 0;
    private final AccessTreeNode[] childNodes;
    private final int t;
    private final int label;
    private final String attribute;
    private final boolean isLeafNode;
    //叶子节点
    //i表示该节点的序号
    private AccessTreeNode(final int i, final String rho) {
        //叶子节点的孩子数为0
        this.childNodes = null;
        //节点阈值为0；
        this.t = 0;
        //节点序号
        this.label = i;
        this.isLeafNode = true;
        //节点对应的属性
        this.attribute = rho;
    }
    //非叶子节点
    private AccessTreeNode(final int[][] accessPolicy, final int i, final String[] rhos) {
        //取访问控制树的第i行
        int[] accessPolicyNode = accessPolicy[i];
        //当该节点的门限值大于节点的孩子节点数时，说明该访问策略无效
        if (accessPolicyNode[0] < accessPolicyNode[1]) {
            throw new InvalidParameterException("Invalid access policy, n < t in the threahold gate " + i);
        }
        //该节点的所有孩子节点
        this.childNodes = new AccessTreeNode[accessPolicyNode[0]];
        //该节点的门限值
        this.t = accessPolicyNode[1];
        //节点序号
        this.label = i;
        //节点对应的属性
        this.attribute = null;
        this.isLeafNode = false;
        int k = 0;
        //为该节点的所有叶子节点赋值
        for (int j = 2; j < accessPolicyNode.length; j++) {
            if (accessPolicyNode[j] > 0) {
                //节点序号大于0说明该节点是非叶子节点，
                this.childNodes[k] = new AccessTreeNode(accessPolicy, accessPolicyNode[j], rhos);
            } else if (accessPolicyNode[j] < 0) {
                //节点序号小于0说明是叶子节点
                numberOfLeafNodes++;
                this.childNodes[k] = new AccessTreeNode(accessPolicyNode[j], rhos[-accessPolicyNode[j] - 1]);
            } else {
                throw new InvalidParameterException("Invalid access policy, containing access node with index 0");
            }
            k++;
        }
    }
    //递归的创建访问控制树
    //返回根节点
    public static AccessTreeNode GenerateAccessTree(final int[][] accessPolicy, final String[] rhos) {
        //rhos表示访问树叶子节点对应的属性集
        numberOfLeafNodes = 0;
        AccessTreeNode rootAccessTreeNode = new AccessTreeNode(accessPolicy, 0, rhos);
        if (numberOfLeafNodes != rhos.length) {
            throw new InvalidParameterException("Invalid access policy, number of leaf nodes " + numberOfLeafNodes
                    + " does not match number of rhos " + rhos.length);
        }
        return rootAccessTreeNode;
    }
    //判断属性是否满足该该节点的访问策略
    boolean isAccessControlSatisfied(final String[] attributes) {
        //非叶子节点
        if (!this.isLeafNode) {
            int satisfiedChildNumber = 0;
            for (AccessTreeNode childNode : this.childNodes) {
                if (childNode.isAccessControlSatisfied(attributes)) {
                    satisfiedChildNumber++;
                }
            }
            return (satisfiedChildNumber >= t);
        } else {
            //叶子节点
            for (String eachAttribute : attributes) {
                if (this.attribute.equals(eachAttribute)) {
                    return true;
                }
            }
            return false;
        }
    }
    public int getT() {
        return this.t;
    }
//孩子节点的个数
    public int getN() {
        return this.childNodes.length;
    }

    public AccessTreeNode getChildNodeAt(int index) {
        return this.childNodes[index];
    }

    public boolean isLeafNode() {
        return this.isLeafNode;
    }

    public String getAttribute() {
        return this.attribute;
    }

    public int getLabel() {
        return this.label;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof AccessTreeNode) {
            AccessTreeNode that = (AccessTreeNode) anOjbect;
            //Compare t;
            if (this.t != that.getT()) {
                return false;
            }
            //Compare label
            if (this.label != that.getLabel()) {
                return false;
            }
            //Compare leafnode
            if (this.isLeafNode) {
                //Compare attribute
                if (!this.attribute.equals(that.attribute)) {
                    return false;
                }
                return this.isLeafNode == that.isLeafNode;
            } else {
                //Compare nonleaf nodes
                if (this.childNodes.length != that.childNodes.length) {
                    return false;
                }
                for (int i = 0; i < this.childNodes.length; i++) {
                    //Compare child nodes
                    if (!this.childNodes[i].equals(that.getChildNodeAt(i))) {
                        return false;
                    }
                }
                return true;
            }
        }
        return false;
    }

}
