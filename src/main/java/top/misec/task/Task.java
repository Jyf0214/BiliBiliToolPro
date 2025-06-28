package top.misec.task;

import java.io.UnsupportedEncodingException;

/**
 * @author @Kurenai
 * @since 2020-11-22 5:22
 */
public interface Task {

    /**
     * 功能实现
     *
     * @throws UnsupportedEncodingException 异常
     * @throws InterruptedException 异常
     */
    void run() throws UnsupportedEncodingException, InterruptedException;

    /**
     * 任务名
     *
     * @return taskName
     */
    String getName();

}