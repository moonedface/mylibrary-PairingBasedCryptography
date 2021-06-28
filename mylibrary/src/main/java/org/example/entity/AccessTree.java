package org.example.entity;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.example.UnsatisfiedAccessControlException;
import org.example.utils.LagrangePolynomial;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AccessTree {
    //The Access Tree
    private final AccessTreeNode rootAccessTreeNode;
    //The access policy represented by int array
    protected final int[][] accessPolicy;
    //Rho map
    protected final String[] rhos;
    //构造函数
    public AccessTree(AccessTreeNode accessTreeNode, int[][] accessPolicy, String[] rhos) {
        this.rootAccessTreeNode = accessTreeNode;
        this.accessPolicy = accessPolicy;
        //Copy rhos数组的拷贝
        this.rhos = new String[rhos.length];
        System.arraycopy(rhos, 0, this.rhos, 0, rhos.length);
    }
    public String[] getRhos() {
        return this.rhos;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

//    public String[] minSatisfiedAttributeSet(String[] attributes) throws UnsatisfiedAccessControlException {
//        if (!this.rootAccessTreeNode.isAccessControlSatisfied(attributes)) {
//            throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
//        }
//        boolean[] isRedundantAttribute = new boolean[attributes.length];
//        int numOfMinAttributeSet = attributes.length;
//        for (int i = 0; i < isRedundantAttribute.length; i++) {
//            isRedundantAttribute[i] = true;
//            numOfMinAttributeSet--;
//            String[] minAttributeSet = new String[numOfMinAttributeSet];
//            for (int j = 0, k = 0; j < attributes.length; j++) {
//                if (!isRedundantAttribute[j]) {
//                    minAttributeSet[k] = attributes[j];
//                    k++;
//                }
//            }
//            if (!this.rootAccessTreeNode.isAccessControlSatisfied(minAttributeSet)) {
//                numOfMinAttributeSet++;
//                isRedundantAttribute[i] = false;
//            }
//        }
//        String[] minAttributeSet = new String[numOfMinAttributeSet];
//        for (int j = 0, k = 0; j < attributes.length; j++) {
//            if (!isRedundantAttribute[j]) {
//                minAttributeSet[k] = attributes[j];
//                k++;
//            }
//        }
//        return minAttributeSet;
//    }

    public AccessTreeNode getRootAccessTreeNode() {
        return this.rootAccessTreeNode;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof AccessTree) {
            AccessTree that = (AccessTree) anObject;
            //Compare rhos
            if (!Arrays.equals(this.rhos, that.getRhos())) {
                return false;
            }
            //Compare access policy
            if (this.accessPolicy.length != that.getAccessPolicy().length) {
                return false;
            }
            for (int i = 0; i < this.accessPolicy.length; i++) {
                if (!Arrays.equals(this.accessPolicy[i], that.getAccessPolicy()[i])) {
                    return false;
                }
            }
            //Compare AccessTreeNode
            return this.rootAccessTreeNode.equals(that.getRootAccessTreeNode());
        }
        return false;
    }
    //生成访问控制树
    public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessTreeNode rootAccessTreeNode) {
        Map<String, Element> sharedElementsMap = new HashMap<String, Element>();
        access_tree_node_secret_sharing(pairing, secret, rootAccessTreeNode, sharedElementsMap);
//        Object[] keySet = sharedElementsMap.keySet().toArray();
//        for (Object keys : keySet) {
//            System.out.println(keys + " : " + sharedElementsMap.get(keys));
//        }
        return sharedElementsMap;
    }
    private void access_tree_node_secret_sharing(Pairing pairing, Element rootSecret, AccessTreeNode accessTreeNode,
                                                 Map<String, Element> sharingResult) {
       //为叶节点选择
        if (accessTreeNode.isLeafNode()) {
            //leaf node, add root secret into the map
            //将访问树所有孩子节点的属性及对应的秘密值存入map中
            sharingResult.put(accessTreeNode.getAttribute(), rootSecret.duplicate().getImmutable());
        } else {
            //non-leaf nodes, share secrets to child nodes
            //创建一个阶为t-1的多项式（t表示阈值）p，p（0）=secret
            LagrangePolynomial lagrangePolynomial = new LagrangePolynomial(pairing, accessTreeNode.getT() - 1, rootSecret);
            for (int i = 0; i < accessTreeNode.getN(); i++) {
                //在p(x)上选择n个点（n表示the number of childNode），计算孩子节点的秘密值
                Element sharedSecret = lagrangePolynomial.evaluate(pairing.getZr().newElement(i + 1));
                access_tree_node_secret_sharing(pairing, sharedSecret, accessTreeNode.getChildNodeAt(i), sharingResult);
            }
        }
    }
    public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessTreeNode rootAccessTreeNode)
            throws UnsatisfiedAccessControlException {
        //判断属性集中是否有重复的属性
        Map<String, String> collisionMap = new HashMap<String, String>();
        for (String attribute : attributes) {
            if (collisionMap.containsKey(attribute)) {
                throw new UnsatisfiedAccessControlException("Invalid attribute set, containing identical attribute: " + attribute);
            } else {
                collisionMap.put(attribute, attribute);
            }
        }
        SatisfiedAccessTreeNode satisfiedAccessTreeNode = SatisfiedAccessTreeNode.GetSatisfiedAccessTreeNode(pairing, rootAccessTreeNode);
        return SatisfiedAccessTreeNode.CalCoefficient(satisfiedAccessTreeNode, attributes);
    }
    public static class SatisfiedAccessTreeNode {
        private final Pairing pairing;
        private final SatisfiedAccessTreeNode parentNode;
        private final SatisfiedAccessTreeNode[] childNodes;
        private final int index;

        private final int t;
        private final int n;
        private final boolean isLeafNode;
        private final String attribute;
        private int[] satisfiedIndex;
        private boolean isSatisfied;

        static SatisfiedAccessTreeNode GetSatisfiedAccessTreeNode(Pairing pairing, AccessTreeNode rootAccessTreeNode) {
            return new SatisfiedAccessTreeNode(pairing, null, 0, rootAccessTreeNode);
        }

        static Map<String, Element> CalCoefficient(SatisfiedAccessTreeNode rootSatisfiedAccessTreeNode, String[] attributes) throws UnsatisfiedAccessControlException {
            if (!rootSatisfiedAccessTreeNode.isAccessControlSatisfied(attributes)) {
                throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
            } else {
                Map<String, Element> coefficientElementsMap = new HashMap<String, Element>();
                rootSatisfiedAccessTreeNode.calcCoefficients(coefficientElementsMap);
//                Object[] keySet = coefficientElementsMap.keySet().toArray();
//                for (Object keys : keySet) {
//                    System.out.println(keys + " : " + coefficientElementsMap.get(keys));
//                }
                return coefficientElementsMap;
            }
        }

        private SatisfiedAccessTreeNode(Pairing pairing, final SatisfiedAccessTreeNode parentSatisfiedAccessTreeNode, int index, final AccessTreeNode accessTreeNode) {
            this.pairing = pairing;
            this.parentNode = parentSatisfiedAccessTreeNode;
            this.index = index;
            if (accessTreeNode.isLeafNode()) {
                this.childNodes = null;
                this.t = 1;
                this.n = 1;
                this.attribute = accessTreeNode.getAttribute();
                this.isLeafNode = true;
            } else {
                this.t = accessTreeNode.getT();
                this.n = accessTreeNode.getN();
                this.isLeafNode = false;
                this.attribute = null;
                this.childNodes = new SatisfiedAccessTreeNode[this.n];
                for (int i = 0; i < this.childNodes.length; i++) {
                    this.childNodes[i] = new SatisfiedAccessTreeNode(pairing, this, i + 1, accessTreeNode.getChildNodeAt(i));
//                    System.out.println("Node: " + this.childNodes[i].label + " with parentNode: " + this.label);
                }
            }
        }

        private boolean isAccessControlSatisfied(final String[] attributes) {
            this.isSatisfied = false;
            if (!this.isLeafNode) {
                int[] tempIndex = new int[this.childNodes.length];
                int satisfiedChildNumber = 0;
                for (int i = 0; i < this.childNodes.length; i++) {
                    if (childNodes[i].isAccessControlSatisfied(attributes)) {
                        tempIndex[i] = i + 1;
                        satisfiedChildNumber++;
                    }
                }
                this.satisfiedIndex = new int[satisfiedChildNumber];
                for (int i = 0, j = 0; i < this.childNodes.length; i++) {
                    if (tempIndex[i] > 0) {
                        this.satisfiedIndex[j] = tempIndex[i];
                        j++;
                    }
                }
//                System.out.println("Node " + this.label + " has satisfied child nodes " + satisfiedChildNumber);
                this.isSatisfied = (satisfiedChildNumber >= t);
            } else {
                for (String attribute1 : attributes) {
                    if (this.attribute.equals(attribute1)) {
                        this.isSatisfied = true;
                    }
                }
            }
            return this.isSatisfied;
        }

        private void calcCoefficients(Map<String, Element> coefficientElementsMap) {
            if (!this.isLeafNode && this.isSatisfied) {
                for (SatisfiedAccessTreeNode childNode : this.childNodes) {
                    if (childNode.isSatisfied) {
                        childNode.calcCoefficients(coefficientElementsMap);
                    }
                }
            } else {
                if (!this.isSatisfied) {
                    return;
                }
                SatisfiedAccessTreeNode currentNode = this;
                Element coefficientElement =  pairing.getZr().newOneElement().getImmutable();
                while (currentNode.parentNode != null) {
                    int currentNodeIndex = currentNode.index;
                    currentNode = currentNode.parentNode;
                    coefficientElement = coefficientElement.mulZn(LagrangePolynomial.calCoef(pairing, currentNode.satisfiedIndex, currentNodeIndex)).getImmutable();
                }
                coefficientElementsMap.put(this.attribute, coefficientElement);
            }
        }
    }
}
