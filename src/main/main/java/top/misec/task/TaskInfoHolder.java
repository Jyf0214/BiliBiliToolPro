package top.misec.task;

import lombok.extern.log4j.Log4j2;
import top.misec.pojo.userinfobean.Data;

/**
 * 任务信息持有类
 *
 * @author @JunzhouLiu @Kurenai
 * @since 2020-11-22 5:02
 */
@Log4j2
public class TaskInfoHolder {

    public static final String STATUS_CODE_STR = "code";
    public static Data userInfo = null;


    /**
     * 此功能依赖UserCheck
     *
     * @return 返回会员类型
     * 0:无会员（会员过期，当前不是会员）
     * 1:月会员
     * 2:年会员
     */
    public static int queryVipStatusType() {
        if (userInfo == null) {
            log.info("暂时无法查询会员状态，默认非大会员");
        }
        if (userInfo != null && userInfo.getVipStatus() == 1) {
            //只有VipStatus为1的时候获取到VipType才是有效的。
            return userInfo.getVipType();
        } else {
            return 0;
        }
    }

}
