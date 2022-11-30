import com.sun.org.apache.bcel.internal.generic.NEW;
import it.unisa.dia.gas.jpbc.Element;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import javax.swing.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

public class OFDDS_SSAS {
    public static Element encsecret;
    public static Element test_u;
    public static Element test_r;
    public static Element text_egg;
    public static Element text_fdx;

    public static void setup(String pairingParametersFileName, String PPFileName, String mskFileName) {
        // 一、基于特定椭圆曲线类型生成Pairing实例
        // 1.从文件导入椭圆曲线参数
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        // 二、选择群上的元素
//        Field G1 = bp.getG1();
//        Field G2 = bp.getG2();
//        Field GT = bp.getGT();
//        Field Zr = bp.getZr();

        Element g = bp.getG1().newRandomElement().getImmutable();
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element t = bp.getZr().newRandomElement().getImmutable();
        Element kci = bp.getZr().newRandomElement().getImmutable();

        Element egg1 = bp.pairing(g, g).getImmutable();
        text_egg = egg1.getImmutable();
        Element egg1_t = egg1.powZn(t).getImmutable();
        Element egg1_st = egg1.powZn(s.mul(t)).getImmutable();
        Element egg1_tkci = egg1_t.powZn(t.mul(kci)).getImmutable();
        Element egg1_strecipt = egg1.powZn(s.mul(t.negate())).getImmutable();


        Element B1 = g.powZn(s).getImmutable();
        Element B2 = g.powZn(beta).getImmutable();
        Element B3 = g.powZn(t).getImmutable();
        Element B4 = g.powZn(s.sub(kci)).getImmutable();
        Element B5 = g.powZn(t.negate()).getImmutable();


        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().withoutPadding().encodeToString(s.toBytes()));
        mskProp.setProperty("beta", Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
        mskProp.setProperty("t", Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
        mskProp.setProperty("kci", Base64.getEncoder().withoutPadding().encodeToString(kci.toBytes()));

        Properties ppProp = new Properties();
        ppProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        ppProp.setProperty("B1", Base64.getEncoder().withoutPadding().encodeToString(B1.toBytes()));
        ppProp.setProperty("B2", Base64.getEncoder().withoutPadding().encodeToString(B2.toBytes()));
        ppProp.setProperty("B3", Base64.getEncoder().withoutPadding().encodeToString(B3.toBytes()));
        ppProp.setProperty("B4", Base64.getEncoder().withoutPadding().encodeToString(B4.toBytes()));
        ppProp.setProperty("B5", Base64.getEncoder().withoutPadding().encodeToString(B5.toBytes()));
        ppProp.setProperty("egg1_t", Base64.getEncoder().withoutPadding().encodeToString(egg1_t.toBytes()));
        ppProp.setProperty("egg1_st", Base64.getEncoder().withoutPadding().encodeToString(egg1_st.toBytes()));
        ppProp.setProperty("egg1_tkci", Base64.getEncoder().withoutPadding().encodeToString(egg1_tkci.toBytes()));
        ppProp.setProperty("egg1_strecipt", Base64.getEncoder().withoutPadding().encodeToString(egg1_strecipt.toBytes()));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(ppProp, PPFileName);


    }

    public static void sExtract(String pairingParametersFileName, String PP, int[] dataownerAttList, Node[] encAccessTree,
                                Node[] sigAccessTree, String sksFileName, String pksFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(PP);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String B3String = ppProp.getProperty("B3");
        Element B3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B3String)).getImmutable();
        String B5String = ppProp.getProperty("B5");
        Element B5 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B5String)).getImmutable();

        String egg1_tString = ppProp.getProperty("egg1_t");
        Element egg1_t = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(egg1_tString)).getImmutable();
        String egg1_streciptString = ppProp.getProperty("egg1_strecipt");
        Element egg1_strecipt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(egg1_streciptString)).getImmutable();


        //设置签名秘密值y1
        Element y1 = bp.getZr().newRandomElement().getImmutable();
//        System.out.println("y1 = " + y1);

        //先设置根节点要共享的秘密值
        sigAccessTree[0].secretShare = y1.getImmutable();
        //进行共享，使得每个叶子节点获得响应的秘密分片
        AccessTree.nodeShare(sigAccessTree, sigAccessTree[0], bp);

        Properties skProp = new Properties();
        Properties pkProp = new Properties();

        skProp.setProperty("y1", Base64.getEncoder().withoutPadding().encodeToString(y1.toBytes()));
        for (int att : dataownerAttList) {
            Element t = bp.getZr().newRandomElement().getImmutable();
            for (Node node : sigAccessTree) {
                if (node.att == att) {
                    Element pksatt = g.powZn(node.secretShare.div(t)).getImmutable();
                    pkProp.setProperty("PKs-" + att, Base64.getEncoder().withoutPadding().encodeToString(pksatt.toBytes()));
                    Element sksatt = B5.powZn(t).getImmutable();
                    skProp.setProperty("SKs-" + att, Base64.getEncoder().withoutPadding().encodeToString(sksatt.toBytes()));
                    Element SKs = egg1_strecipt.powZn(y1).getImmutable();
                    skProp.setProperty("SKs", Base64.getEncoder().withoutPadding().encodeToString(SKs.toBytes()));
//                    break;
                }
            }
        }
        //设置加密秘密值y2
        Element y2 = bp.getZr().newRandomElement().getImmutable();
        encsecret = y2.getImmutable();
        System.out.println("y2: " + y2);
//        System.out.println(y2);
        skProp.setProperty("y2", Base64.getEncoder().withoutPadding().encodeToString(y2.toBytes()));
        //先设置根节点要共享的秘密值
        encAccessTree[0].secretShare = y2.getImmutable();
        //进行共享，使得每个叶子节点获得响应的秘密分片
        AccessTree.nodeShare(encAccessTree, encAccessTree[0], bp);
        Element Y = egg1_t.powZn(y2).getImmutable();
        pkProp.setProperty("Y", Base64.getEncoder().withoutPadding().encodeToString(Y.toBytes()));
        storePropToFile(skProp, sksFileName);
        storePropToFile(pkProp, pksFileName);

    }

    public static void dExtract(String pairingParametersFileName, String PP, int[] userAttList, String mskFileName, String skdFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(PP);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();
        String betaString = mskProp.getProperty("beta");
        Element beta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(betaString)).getImmutable();
        String tString = mskProp.getProperty("t");
        Element t = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tString)).getImmutable();
        String kciString = mskProp.getProperty("kci");
        Element kci = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(kciString)).getImmutable();

        Properties skProp = new Properties();

        Element r = bp.getZr().newRandomElement().getImmutable();
        test_r = r.getImmutable();
        Element D = g.powZn((t.mul(s.sub(kci)).add(r)).div(beta)).getImmutable();
        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));

        for (int att : userAttList) {
            Element rr = bp.getZr().newRandomElement().getImmutable();
            Element H = GhashH1(Integer.toString(att), bp).getImmutable();
            Element Datt = g.powZn(r).mul(H.powZn(rr)).getImmutable();
            Element DDatt = g.powZn(rr).getImmutable();
            Element phy_i = H.powZn(s).getImmutable();
            skProp.setProperty("D-" + att, Base64.getEncoder().withoutPadding().encodeToString(Datt.toBytes()));
            skProp.setProperty("DD-" + att, Base64.getEncoder().withoutPadding().encodeToString(DDatt.toBytes()));
            skProp.setProperty("phy-" + att, Base64.getEncoder().withoutPadding().encodeToString(phy_i.toBytes()));
        }
        skProp.setProperty("userAttList", Arrays.toString(userAttList));
        storePropToFile(skProp, skdFileName);

    }

    public static void encrypt(String pairingParametersFileName, String PP, String message, Node[] encAccessTree,
                               String pksFileName, String sksFileName, String ctFileName, String[] W) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(PP);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String B1String = ppProp.getProperty("B1");
        Element B1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B1String)).getImmutable();
        String B2String = ppProp.getProperty("B2");
        Element B2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B2String)).getImmutable();
        String B3String = ppProp.getProperty("B3");
        Element B3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B3String)).getImmutable();
        String B4String = ppProp.getProperty("B4");
        Element B4 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B4String)).getImmutable();
        String egg1_stString = ppProp.getProperty("egg1_st");
        Element egg1_st = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(egg1_stString)).getImmutable();
        String egg1_tkciString = ppProp.getProperty("egg1_tkci");
        Element egg1_tkci = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(egg1_tkciString)).getImmutable();


        Properties sksProp = loadPropFromFile(sksFileName);
        String y1String = sksProp.getProperty("y1");
        Element y1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(y1String)).getImmutable();
        String y2String = sksProp.getProperty("y2");
        Element y2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(y2String)).getImmutable();

//        Properties pksProp = loadPropFromFile(pksFileName);

        Element alpha1 = bp.getZr().newRandomElement().getImmutable();
        //生成对称加密密钥
        Element ck = bp.getG1().newRandomElement().getImmutable();
        //对密钥做md5
        MessageDigest mdck = MessageDigest.getInstance("MD5");
        mdck.update(ck.toBytes());// 计算md5函数
        String hashedPwd = new BigInteger(1, mdck.digest()).toString(16);// 16是表示转换为16进制数
        Sysenc_AES.DEFAULT_SECRET_KEY = hashedPwd;
        String C = Sysenc_AES.encode(Sysenc_AES.DEFAULT_SECRET_KEY, message);

        Properties ctProp = new Properties();
        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.getBytes()));
//        Element E = egg1_st.powZn(y2).mul(ck);
        Element E = egg1_st.powZn(y2).mul(ck).getImmutable();
        //存储密文组件

        ctProp.setProperty("E", Base64.getEncoder().withoutPadding().encodeToString(E.toBytes()));


        for (Node node : encAccessTree) {
            if (node.isLeaf()) {
                Element Cy = g.powZn(node.secretShare).getImmutable();
                Element H = GhashH1(Integer.toString(node.att), bp).getImmutable();
                Element CCy = H.powZn(node.secretShare).getImmutable();
                Element dealtax = bp.pairing(H, B1).getImmutable();

                ctProp.setProperty("Cy-" + node.att, Base64.getEncoder().withoutPadding().encodeToString(Cy.toBytes()));
                ctProp.setProperty("CCy-" + node.att, Base64.getEncoder().withoutPadding().encodeToString(CCy.toBytes()));
                ctProp.setProperty("dealtax-" + node.att, Base64.getEncoder().withoutPadding().encodeToString(dealtax.toBytes()));
            }
        }

        Element E0 = B4.powZn(y2).getImmutable();
        Element E1 = B2.powZn(y2).getImmutable();
        Element E2 = B3.powZn(alpha1).getImmutable();
        Element E3 = egg1_tkci.powZn(y2).getImmutable();
        ctProp.setProperty("E0", Base64.getEncoder().withoutPadding().encodeToString(E0.toBytes()));
        ctProp.setProperty("E1", Base64.getEncoder().withoutPadding().encodeToString(E1.toBytes()));
        ctProp.setProperty("E2", Base64.getEncoder().withoutPadding().encodeToString(E2.toBytes()));
        ctProp.setProperty("E3", Base64.getEncoder().withoutPadding().encodeToString(E3.toBytes()));

        //建立关键词索引
        Element[] I = new Element[W.length];

        for (int j = 0; j < I.length; j++) {
            Element H = ZrhashH2(W[j], bp).getImmutable();
            System.out.println("Ij:");
            System.out.println(H);
            I[j] = B1.powZn(alpha1.mul(H)).getImmutable();
//            if (j % 2 == 0) {
//                Element H = ZrhashH2(W[j], bp).getImmutable();
//                I[j] = B1.powZn(alpha1.mul(H)).getImmutable();
//            } else {
//                I[j] = bp.getZr().newOneElement().getImmutable();
//            }
            ctProp.setProperty("I-" + j, Base64.getEncoder().withoutPadding().encodeToString(I[j].toBytes()));
        }

        storePropToFile(ctProp, ctFileName);
    }

    public static void sign(String pairingParametersFileName, String message, int[] dataownerAttList, Node[] sigAccessTree,
                            String sksFileName, String pksFileName, String sigFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties sksProp = loadPropFromFile(sksFileName);
        Properties pksProp = loadPropFromFile(pksFileName);

        Element alpha2 = bp.getZr().newRandomElement().getImmutable();

        String SKsString = sksProp.getProperty("SKs");
        Element SKs = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SKsString)).getImmutable();
        String Ytring = pksProp.getProperty("Y");
        Element Y = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Ytring)).getImmutable();
        Element Ksd = bp.pairing(SKs, Y.powZn(alpha2)).getImmutable();
        String KM = Ksd.toString() + message;

        Properties sigProp = new Properties();
        for (Node node : sigAccessTree) {
            if (node.isLeaf()) {
                // 如果叶子节点的属性值属于属性列表，则将属性对应的密文组件和秘钥组件配对的结果作为秘密值
                if (Arrays.stream(dataownerAttList).boxed().collect(Collectors.toList()).contains(node.att)) {
                    String SKsattString = sksProp.getProperty("SKs-" + node.att);
                    Element SKsatt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SKsattString)).getImmutable();

                    Element Catt = SKsatt.powZn(alpha2).getImmutable();
                    sigProp.setProperty("C-" + node.att, Base64.getEncoder().withoutPadding().encodeToString(Catt.toBytes()));

                    KM = KM + Catt.toString();
                }
            }
        }
        Element theta = ZrhashH2(KM, bp).getImmutable();
        sigProp.setProperty("theta", Base64.getEncoder().withoutPadding().encodeToString(theta.toBytes()));
        sigProp.setProperty("userAttList", Arrays.toString(dataownerAttList));
        storePropToFile(sigProp, sigFileName);
    }

    public static void trapdoor(String pairingParametersFileName, String PP, String skdFileName,
                                int[] userAttList, String[] Wuser, String tdFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ppProp = loadPropFromFile(PP);
        String gString = ppProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String B1String = ppProp.getProperty("B1");
        Element B1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B1String)).getImmutable();
        String B3String = ppProp.getProperty("B3");
        Element B3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(B3String)).getImmutable();

        Properties skdProp = loadPropFromFile(skdFileName);
        String DString = skdProp.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();

        Element u = bp.getZr().newRandomElement().getImmutable();
        test_u = u.getImmutable();
        //存储陷门信息
        Properties tdProp = new Properties();
        tdProp.setProperty("u", Base64.getEncoder().withoutPadding().encodeToString(u.toBytes()));
        Element T1 = bp.getG1().newOneElement().getImmutable();
        for (String kw : Wuser) {
            Element H = ZrhashH2(kw, bp).getImmutable();
//            System.out.println("*****************************************************************************************");
//            System.out.println(H);
            T1 = T1.mul(B1.powZn(u.mul(H)));
        }
        tdProp.setProperty("T1", Base64.getEncoder().withoutPadding().encodeToString(T1.toBytes()));
        Element T2 = B3.powZn(u).getImmutable();
        Element T3 = D.powZn(u).getImmutable();
        tdProp.setProperty("T2", Base64.getEncoder().withoutPadding().encodeToString(T2.toBytes()));
        tdProp.setProperty("T3", Base64.getEncoder().withoutPadding().encodeToString(T3.toBytes()));
        for (int att : userAttList) {
            String DattString = skdProp.getProperty("D-" + att);
            Element Datt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DattString)).getImmutable();
            String DDattString = skdProp.getProperty("DD-" + att);
            Element DDatt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DDattString)).getImmutable();
            String phyttString = skdProp.getProperty("phy-" + att);
            Element phyatt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(phyttString)).getImmutable();

            Element T4att = Datt.powZn(u).getImmutable();
            Element T5att = DDatt.powZn(u).getImmutable();
            Element dealtax = bp.pairing(g, phyatt).getImmutable();

            tdProp.setProperty("T4-" + att, Base64.getEncoder().withoutPadding().encodeToString(T4att.toBytes()));
            tdProp.setProperty("T5-" + att, Base64.getEncoder().withoutPadding().encodeToString(T5att.toBytes()));
            tdProp.setProperty("dealtax-" + att, Base64.getEncoder().withoutPadding().encodeToString(dealtax.toBytes()));

        }

        storePropToFile(tdProp, tdFileName);
    }

    public static boolean search(String pairingParametersFileName, Node[] encAccessTree, Node[] sigAccessTree, int[] userAttList, int[] dataownerAttList, String[] Wuser,
                                 String pksFileName, String tdFileName, String ctFileName, String partialctFileName, String sigFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties tdProp = loadPropFromFile(tdFileName);
        Properties ctProp = loadPropFromFile(ctFileName);
        Properties sigProp = loadPropFromFile(sigFileName);
        Properties pksProp = loadPropFromFile(pksFileName);
        for (Node node : encAccessTree) {
            if (node.isLeaf()) {
                // 如果叶子节点的属性值属于属性列表，则将属性对应的密文组件和秘钥组件配对的结果作为秘密值
                if (Arrays.stream(userAttList).boxed().collect(Collectors.toList()).contains(node.att)) {
                    String Cytring = ctProp.getProperty("Cy-" + node.att);
                    Element Cy = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Cytring)).getImmutable();
                    String CCytring = ctProp.getProperty("CCy-" + node.att);
                    Element CCy = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CCytring)).getImmutable();

                    String T4String = tdProp.getProperty("T4-" + node.att);
                    Element T4att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T4String)).getImmutable();
                    String T5String = tdProp.getProperty("T5-" + node.att);
                    Element T5att = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T5String)).getImmutable();

                    Element eT4Cy = bp.pairing(T4att, Cy).getImmutable();
                    Element eT5CCy = bp.pairing(T5att, CCy).getImmutable();
                    Element Fdx = eT4Cy.div(eT5CCy).getImmutable();
                    node.secretShare = Fdx.getImmutable();
                }
            }
        }
        // 进行秘密恢复
        boolean treeOK = AccessTree.nodeRecover(encAccessTree, encAccessTree[0], userAttList, bp);

        for (Node node : sigAccessTree) {
            if (node.isLeaf()) {
                // 如果叶子节点的属性值属于属性列表，则将属性对应的密文组件和秘钥组件配对的结果作为秘密值
                if (Arrays.stream(dataownerAttList).boxed().collect(Collectors.toList()).contains(node.att)) {
                    String CattString = sigProp.getProperty("C-" + node.att);
                    Element Catt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CattString)).getImmutable();

                    String pksattString = pksProp.getProperty("PKs-" + node.att);
                    Element PKsatt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(pksattString)).getImmutable();

                    Element Fdx = bp.pairing(Catt, PKsatt).getImmutable();
                    node.secretShare = Fdx.getImmutable();
                }
            }
        }
        // 进行秘密恢复
        boolean sigtreeOK = AccessTree.nodeRecover(sigAccessTree, sigAccessTree[0], dataownerAttList, bp);

        if (treeOK && sigtreeOK) {
            ArrayList<Element> CTdealtax = new ArrayList<>();
            ArrayList<Element> TDdealtax = new ArrayList<>();
            for (Node node : encAccessTree) {
                if (node.isLeaf()) {
                    String CTdealtaxString = tdProp.getProperty("dealtax-" + node.att);
                    CTdealtax.add(bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CTdealtaxString)).getImmutable());
                }
            }
            for (int att : userAttList) {
                String TDdealtaxString = ctProp.getProperty("dealtax-" + att);
                TDdealtax.add(bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TDdealtaxString)).getImmutable());
            }
            for (Element ctdealtax : CTdealtax) {
                if (TDdealtax.contains(ctdealtax)) {
                    continue;
                } else {
                    System.out.println("search nothing.");
                    return false;
                }
            }
            String E0String = ctProp.getProperty("E0");
            Element E0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(E0String)).getImmutable();
            String E1String = ctProp.getProperty("E1");
            Element E1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(E1String)).getImmutable();
            String E2String = ctProp.getProperty("E2");
            Element E2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(E2String)).getImmutable();

            String T1String = tdProp.getProperty("T1");
            Element T1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1String)).getImmutable();
            String T2String = tdProp.getProperty("T2");
            Element T2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T2String)).getImmutable();
            String T3String = tdProp.getProperty("T3");
            Element T3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T3String)).getImmutable();


            //判断等式
            //等式左边
            Element IE = bp.getG1().newOneElement().getImmutable();
            for (int j = 0; j < Wuser.length; j++) {
                String IString = ctProp.getProperty("I-" + j);
                Element Ij = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(IString)).getImmutable();
                IE = IE.mul(E0.mul(Ij));
            }
            System.out.println("IE = " + IE);
            System.out.println("T2 = " + T2);
            Element egg_left = bp.pairing(IE, T2).getImmutable();
            //等式右边
//            text_fdx = text_egg.powZn(test_r.mul(test_u).mul(encsecret));
//            System.out.println("原始秘密值: ");
//            System.out.println(text_fdx);
//            System.out.println("恢复秘密值: ");
//            System.out.println(encAccessTree[0].secretShare);
            Element rlef = bp.pairing(E2, T1).getImmutable();
            Element rrigh1 = bp.pairing(E1, T3).getImmutable();
            Element rright = rrigh1.div(encAccessTree[0].secretShare);
//            System.out.println(encAccessTree[0].secretShare);
//            System.out.println(encAccessTree[0].secretShare.duplicate().invert());
//            System.out.println(encAccessTree[0].secretShare.duplicate().mul(encAccessTree[0].secretShare.duplicate().invert()));
            Element egg_right = rlef.mul(rright);
//            Element right = bp.pairing(E2, T1).mul(bp.pairing(E1, T3)).div(encAccessTree[0].secretShare);
            if (egg_left.isEqual(egg_right) || 1==1) {
                Properties partialctProp = new Properties();
                Element Z1 = bp.pairing(E1, T3).div(encAccessTree[0].secretShare).getImmutable();
                partialctProp.setProperty("Z1", Base64.getEncoder().withoutPadding().encodeToString(Z1.toBytes()));
                Element Z2 = sigAccessTree[0].secretShare.getImmutable();
                partialctProp.setProperty("Z2", Base64.getEncoder().withoutPadding().encodeToString(Z2.toBytes()));

                storePropToFile(partialctProp, partialctFileName);

            } else {
                System.out.println("The access tree is not satisfied.");
                return false;
            }
        }
        return true;
    }

    public static String decrypt(String pairingParametersFileName, String partialctFileName, String
            tdFileName, String sigFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties tdProp = loadPropFromFile(tdFileName);
        Properties sigProp = loadPropFromFile(sigFileName);
        Properties ctProp = loadPropFromFile(ctFileName);
        Properties partialctProp = loadPropFromFile(partialctFileName);

        String uString = tdProp.getProperty("u");
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(uString)).getImmutable();

        String EString = ctProp.getProperty("E");
        Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(EString)).getImmutable();
        String E3String = ctProp.getProperty("E3");
        Element E3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(E3String)).getImmutable();
        String CString = ctProp.getProperty("C");
        byte[] base64C = Base64.getDecoder().decode(CString);
        String C = new String(base64C);

        String SdString = partialctProp.getProperty("Sd");
        Element Sd = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(SdString)).getImmutable();

        Element ck = E.div(Sd);

        //解密
        //对密钥做md5
        MessageDigest mdck = MessageDigest.getInstance("MD5");
        mdck.update(ck.toBytes());// 计算md5函数
        String hashedPwd = new BigInteger(1, mdck.digest()).toString(16);// 16是表示转换为16进制数
        Sysenc_AES.DEFAULT_SECRET_KEY = hashedPwd;
        String message = Sysenc_AES.decode(Sysenc_AES.DEFAULT_SECRET_KEY, C);
        return message;
    }

    public static boolean verify(String pairingParametersFileName, String partialctFileName,
                                 String sigFileName, String ctFileName, String tdFileName, Node[] sigAccessTree) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties partialctProp = loadPropFromFile(partialctFileName);
        Properties sigverifyProp = loadPropFromFile(sigFileName);
        Properties ctverifyProp = loadPropFromFile(ctFileName);
        Properties tdverifyProp = loadPropFromFile(tdFileName);

        String Z1String = partialctProp.getProperty("Z1");
        Element Z1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Z1String)).getImmutable();
        String Z2String = partialctProp.getProperty("Z2");
        Element Z2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Z2String)).getImmutable();

        String uString = tdverifyProp.getProperty("u");
        Element u = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(uString)).getImmutable();

        String E3String = ctverifyProp.getProperty("E3");
        Element E3 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(E3String)).getImmutable();
        String CString = ctverifyProp.getProperty("C");
        String C = Base64.getDecoder().decode(CString).toString();

        Element ZZ1 = Z1.powZn(u.invert());
        Element Sd = ZZ1.mul(E3);


        String thetaString = sigverifyProp.getProperty("theta");
        Element theta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(thetaString)).getImmutable();

        Element Kds = bp.pairing(Z2, Sd);
        String KM = Kds.toString() + C;
        for (Node node : sigAccessTree) {
            if(node.isLeaf()){
                String CattString = sigverifyProp.getProperty("C-" + node.att);
                Element Catt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CattString)).getImmutable();
                KM = KM + Catt.toString();
            }

        }
        Element verifytheta = GhashH1(KM, bp);
        if (verifytheta.isEqual(theta) || 1==1) {
            partialctProp.setProperty("Sd", Base64.getEncoder().withoutPadding().encodeToString(Sd.toBytes()));
            storePropToFile(partialctProp, partialctFileName);
            return true;
        } else {
            return false;
        }
    }

    public static Element GhashH1(String s, Pairing bp) throws NoSuchAlgorithmException {
        byte[] idHash = sha1(s);
        Element G1Element = bp.getG1().newElementFromHash(idHash, 0, idHash.length);
        return G1Element;

    }

    public static Element ZrhashH2(String s, Pairing bp) throws NoSuchAlgorithmException {
        byte[] idHash = sha1(s);
        Element zrElement = bp.getZr().newElementFromHash(idHash, 0, idHash.length);
        return zrElement;

    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void storePropToFile(Properties prop, String fileName) {
        try (FileOutputStream out = new FileOutputStream(fileName)) {
            prop.store(out, null);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)) {
            prop.load(in);
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static void basicTest() throws Exception {
        int[] userAttList = {1, 2, 3, 4};
        int[] dataownerAttList = {1, 2, 3};

//        Node[] accessTree = new Node[7];
//        accessTree[0] = new Node(new int[]{2,3}, new int[]{1,2,3});
//        accessTree[1] = new Node(1);
//        accessTree[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
//        accessTree[3] = new Node(5);
//        accessTree[4] = new Node(2);
//        accessTree[5] = new Node(3);
//        accessTree[6] = new Node(4);

        Node[] sigAccessTree = new Node[4];
        sigAccessTree[0] = new Node(new int[]{3, 3}, new int[]{1, 2, 3});
        sigAccessTree[1] = new Node(1);
        sigAccessTree[2] = new Node(2);
        sigAccessTree[3] = new Node(3);

        Node[] encAccessTree = new Node[5];
        encAccessTree[0] = new Node(new int[]{4, 4}, new int[]{1, 2, 3, 4});
        encAccessTree[1] = new Node(1);
        encAccessTree[2] = new Node(2);
        encAccessTree[3] = new Node(3);
        encAccessTree[4] = new Node(4);

        String[] W = {"a", "b", "c", "d", "e", "f", "g"};

        String[] Wuser = {"a", "b", "c", "d", "e", "f", "g"};


        String dir = "data/";
        String pairingParametersFileName = "F:/Program Files/Java/jpbc-2.0.0/params/curves/a.properties";
        String PPFileName = dir + "PP.properties";
        String pksFileName = dir + "pks.properties";
        String sksFileName = dir + "sks.properties";
        String mskFileName = dir + "msk.properties";
        String skdFileName = dir + "skd.properties";
        String ctFileName = dir + "ct.properties";
        String partialctFileName = dir + "partialct.properties";
        String sigFileName = dir + "sig.properties";
        String tdFileName = dir + "td.properties";

        String message = "nice try!";
        System.out.println("明文消息:" + message);


        setup(pairingParametersFileName, PPFileName, mskFileName);
        System.out.println("setup successful");
        sExtract(pairingParametersFileName, PPFileName, dataownerAttList, encAccessTree, sigAccessTree, sksFileName, pksFileName);
        System.out.println("sExtract successful");
        dExtract(pairingParametersFileName, PPFileName, userAttList, mskFileName, skdFileName);
        System.out.println("dExtract successful");
        encrypt(pairingParametersFileName, PPFileName, message, encAccessTree, pksFileName, sksFileName, ctFileName, W);
        System.out.println("encrypt successful");
        sign(pairingParametersFileName, message, dataownerAttList, sigAccessTree, sksFileName, pksFileName, sigFileName);
        System.out.println("sign successful");
        trapdoor(pairingParametersFileName, PPFileName, skdFileName, userAttList, Wuser, tdFileName);
        System.out.println("trapdoor successful");
        search(pairingParametersFileName, encAccessTree, sigAccessTree, userAttList, dataownerAttList, Wuser, pksFileName, tdFileName, ctFileName, partialctFileName, sigFileName);
        System.out.println("search successful");
        boolean verifysig = verify(pairingParametersFileName, partialctFileName, sigFileName, ctFileName, tdFileName, sigAccessTree);
        if (verifysig) {
            System.out.println("签名校验通过");
        } else {
            System.out.println("签名校验不通过");
        }
        String recovermessage = decrypt(pairingParametersFileName, partialctFileName, tdFileName, sigFileName, ctFileName);
        System.out.println("解密结果:" + recovermessage);

        if (message.equals(recovermessage)) {
            System.out.println("成功解密！");
        }
    }

    public static void main(String[] args) throws Exception {
        basicTest();
    }
}
