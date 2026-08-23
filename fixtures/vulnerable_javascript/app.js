/**
 * PatchForge AI - Safe Synthetic Vulnerability Test Fixture (JavaScript)
 * =====================================================================
 * Intentionally vulnerable controlled test application for AST detection.
 * DO NOT USE IN PRODUCTION.
 */

const { exec } = require('child_process');
const fs = require('fs');

class UserService {
    constructor(db) {
        this.db = db;
    }

    async findAccount(accountId) {
        // CWE-89 SQL Injection
        const query = "SELECT * FROM accounts WHERE id = " + accountId;
        return await this.db.query(query);
    }

    runSystemHealth(targetHost) {
        // CWE-78 Command Injection
        exec("ping -c 1 " + targetHost, (err, stdout) => {
            console.log(stdout);
        });
    }

    fetchDocument(docName) {
        // CWE-22 Path Traversal
        return fs.readFileSync("/var/docs/" + docName, "utf8");
    }
}

module.exports = { UserService };
