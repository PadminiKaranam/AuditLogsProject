package com.persistent.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit-logs")
public class AuditLogsController {

    @GetMapping("/test")
    public String getAuditLogs() {
        return "Audit logs";
    }
}
