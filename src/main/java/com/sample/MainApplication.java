package com.sample;

import lombok.extern.log4j.Log4j2;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * <p>
 * <p>
 * <p>
 * <p>
 *
 *
 *
 * @author cjrequena
 * @version 1.0
 * @see
 * @since JDK1.8
 */
@Log4j2
@SpringBootApplication
public class MainApplication {

  private static Class<MainApplication> mainApplicationClass = MainApplication.class;

  /**
   * @param args
   * @throws Exception
   */
  public static void main(String[] args) throws Exception {
    try {
      SpringApplication springApplication = new SpringApplication(mainApplicationClass);
      springApplication.run(args);
    } catch (Exception ex) {
      log.error("Error: " + ex);
      throw ex;
    }
  }

}

