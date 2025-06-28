package top.misec.apiquery;

/**
 * @author Junzhou Liu
 * @create 2020/10/11 3:40
 */
public class ApiList {
    public static String PushPlus = "http://www.pushplus.plus/send";
    public static String ServerPushV2 = "https://sctapi.ftqq.com/";
    public static String ServerPushTelegram = "https://api.telegram.org/bot";
    public static String LOGIN = "https://api.bilibili.com/x/web-interface/nav";

    /**
     * 查询主站硬币余额
     */
    public static String getCoinBalance = "https://account.bilibili.com/site/getCoin";


    public static String queryUserName = "https://api.bilibili.com/x/space/acc/info";

    /**
     * 领取大会员福利
     */
    public static String vipPrivilegeReceive = "https://api.bilibili.com/x/vip/privilege/receive";

    public static String ServerPush = "https://sc.ftqq.com/";

    public static String videoView = "https://api.bilibili.com/x/web-interface/view";

    public static String queryQuestions = "https://api.bilibili.com/x/esports/guess/collection/question";

    public static String queryMatchInfo = "https://api.bilibili.com/x/esports/guess/collection/statis";
    public static String doAdd = "https://api.bilibili.com/x/esports/guess/add";
}
