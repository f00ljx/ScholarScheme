import javax.swing.*;

public class AutoGenTree {
    //属性列表、满三叉树层数
    public static Node[] tree(int[] att, int k) {
        //k不等于1，无意义
        int nodenum = (int) (Math.pow(3, k) - 1) / 2;
        int notleafnodenum = (int) (Math.pow(3, k - 1) - 1) / 2;
        //满三叉树叶子节点个数
//        int leafnodenum = (int) Math.pow(3, k - 1);
        int leafnodenum = att.length;
        Node[] actree = new Node[nodenum];
        int j = 0;
        for (int i = 0; i < nodenum; i++) {
            if (i < notleafnodenum) {
                //统一阈值门（3,2）
                actree[i] = new Node(new int[]{3, 2}, new int[]{i * 3 + 1, i * 3 + 2, i * 3 + 3});
            }
            else {
                actree[i] = new Node(att[j]);
                j++;
            }
        }
        return actree;
    }

    //    public static Node[] tree(String[] att){
//
//    }
    public static void main(String[] args) {
        int[] userAttList = {1, 2, 3, 4, 5, 6, 7, 8, 9};
        Node[] actree = tree(userAttList, 3);
        System.out.println(actree);
    }
}
