package top.misec.task;

import lombok.extern.log4j.Log4j2;

import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * @author @JunzhouLiu @Kurenai
 * @create 2020/10/11 20:44
 */
@Log4j2
public class DailyTask {

    private final List<Task> dailyTasks = Arrays.asList(
            new UserCheck(),
            new MatchGame()
    );

    public void doDailyTask() {
        try {
            printTime();
            log.debug("任务启动中");
            for (Task task : dailyTasks) {
                log.info("------{}开始------", task.getName());
                task.run();
                log.info("------{}结束------\n", task.getName());
                taskSuspend();
            }
            log.info("本日任务已全部执行完毕");

        } catch (InterruptedException | UnsupportedEncodingException e) {
            e.printStackTrace();
        } finally {
            ServerPush.doServerPush();
        }
    }


    private void printTime() {
        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String time = sdf.format(d);
        log.info(time);
    }

    private void taskSuspend() throws InterruptedException {
        Random random = new Random();
        int sleepTime = (int) ((random.nextDouble() + 0.5) * 0);
        //default 3000
        log.info("-----随机暂停{}ms-----\n", sleepTime);
        Thread.sleep(sleepTime);
    }

}

