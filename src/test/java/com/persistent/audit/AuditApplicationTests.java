package com.persistent.audit;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	void mainStartsApplication() {
		AuditApplication.main(new String[] {
				"--spring.main.web-application-type=none",
				"--spring.main.register-shutdown-hook=false",
				"--spring.datasource.url=jdbc:h2:mem:maincoverage;DB_CLOSE_DELAY=-1",
				"--audit.jwt.secret=audit-log-service-hs256-secret-key-32"
		});
	}
}
