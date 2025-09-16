# Microsoft SQL Server Installation Guide

Enterprise-grade relational database management system for mission-critical applications. Full-featured database platform with advanced security, high availability, and comprehensive tooling for Linux environments.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- Linux system (RHEL 8+, Ubuntu 18.04+, SUSE 12+)
- Root or sudo access
- 4GB RAM minimum, 8GB+ recommended for production
- 6GB+ disk space for installation
- 1433/tcp port available for SQL Server
- systemd for service management


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### Ubuntu/Debian
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Import Microsoft GPG key
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# Add Microsoft SQL Server repository
sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/mssql-server-2022.list)"

# Install SQL Server
sudo apt update
sudo apt install -y mssql-server

# Configure SQL Server
sudo /opt/mssql/bin/mssql-conf setup

# Enable and start service
sudo systemctl enable --now mssql-server

# Install SQL Server command-line tools
curl https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/prod.list | sudo tee /etc/apt/sources.list.d/mssql-tools.list
sudo apt update
sudo ACCEPT_EULA=Y apt install -y mssql-tools unixodbc-dev

# Add tools to PATH
echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc
source ~/.bashrc

# Verify installation
systemctl status mssql-server
sqlcmd -S localhost -U SA
```

### RHEL/CentOS/Rocky Linux/AlmaLinux
```bash
# Add Microsoft repository
sudo curl -o /etc/yum.repos.d/mssql-server.repo https://packages.microsoft.com/config/rhel/9/mssql-server-2022.repo

# Install SQL Server
sudo yum install -y mssql-server

# Configure SQL Server
sudo /opt/mssql/bin/mssql-conf setup

# Enable and start service
sudo systemctl enable --now mssql-server

# Install command-line tools
sudo curl -o /etc/yum.repos.d/msprod.repo https://packages.microsoft.com/config/rhel/9/prod.repo
sudo yum install -y mssql-tools unixODBC-devel

# Add tools to PATH
echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc

# Configure firewall
sudo firewall-cmd --permanent --add-port=1433/tcp
sudo firewall-cmd --reload

# Verify installation
systemctl status mssql-server
sqlcmd -S localhost -U SA
```

### Docker Installation
```bash
# Create SQL Server directories
mkdir -p ~/mssql/{data,logs,secrets}

# Generate strong SA password
MSSQL_SA_PASSWORD=$(openssl rand -base64 32)
echo "$MSSQL_SA_PASSWORD" > ~/mssql/secrets/sa_password.txt
chmod 600 ~/mssql/secrets/sa_password.txt

# Run SQL Server container
docker run -d \
  --name mssql \
  --restart unless-stopped \
  -e ACCEPT_EULA=Y \
  -e MSSQL_SA_PASSWORD="$MSSQL_SA_PASSWORD" \
  -e MSSQL_PID=Developer \
  -e MSSQL_TCP_PORT=1433 \
  -p 127.0.0.1:1433:1433 \
  -v ~/mssql/data:/var/opt/mssql/data \
  -v ~/mssql/logs:/var/opt/mssql/log \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/run \
  mcr.microsoft.com/mssql/server:2022-latest

# Connect to verify
docker exec -it mssql /opt/mssql-tools/bin/sqlcmd -S localhost -U SA
```

### Kubernetes Installation
```bash
# Create SQL Server deployment
cat > mssql-k8s.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: mssql-secret
type: Opaque
data:
  SA_PASSWORD: $(echo -n "YourSecurePassword2024!" | base64)
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mssql-deployment
  labels:
    app: mssql
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mssql
  template:
    metadata:
      labels:
        app: mssql
    spec:
      securityContext:
        fsGroup: 10001
      containers:
      - name: mssql
        image: mcr.microsoft.com/mssql/server:2022-latest
        ports:
        - containerPort: 1433
        env:
        - name: MSSQL_PID
          value: "Developer"
        - name: ACCEPT_EULA
          value: "Y"
        - name: SA_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mssql-secret
              key: SA_PASSWORD
        volumeMounts:
        - name: mssqldb
          mountPath: /var/opt/mssql
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 10001
          capabilities:
            drop:
              - ALL
      volumes:
      - name: mssqldb
        persistentVolumeClaim:
          claimName: mssql-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: mssql-service
spec:
  selector:
    app: mssql
  ports:
    - protocol: TCP
      port: 1433
      targetPort: 1433
  type: ClusterIP
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: mssql-pvc
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
EOF

kubectl apply -f mssql-k8s.yaml
```

## Production Configuration

### Security Configuration
```bash
# Configure SQL Server for production security
sudo /opt/mssql/bin/mssql-conf set network.tcpport 1433
sudo /opt/mssql/bin/mssql-conf set network.ipaddress 0.0.0.0

# Configure TLS encryption
sudo /opt/mssql/bin/mssql-conf set network.forceencryption 1
sudo /opt/mssql/bin/mssql-conf set network.tlscert /opt/mssql/ssl/mssql.crt
sudo /opt/mssql/bin/mssql-conf set network.tlskey /opt/mssql/ssl/mssql.key
sudo /opt/mssql/bin/mssql-conf set network.tlsprotocols 1.2,1.3

# Generate SSL certificates
sudo mkdir -p /opt/mssql/ssl
cd /opt/mssql/ssl

sudo openssl req -x509 -nodes -newkey rsa:4096 -keyout mssql.key -out mssql.crt -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=mssql.example.com"

sudo chown mssql:mssql /opt/mssql/ssl/*
sudo chmod 600 /opt/mssql/ssl/mssql.key
sudo chmod 644 /opt/mssql/ssl/mssql.crt

# Restart SQL Server
sudo systemctl restart mssql-server
```

### Performance Optimization
```bash
# Configure SQL Server for optimal performance
sudo /opt/mssql/bin/mssql-conf set memory.memorylimitmb 6144  # 6GB
sudo /opt/mssql/bin/mssql-conf set sqlagent.enabled true
sudo /opt/mssql/bin/mssql-conf set telemetry.userrequestedlocalauditdirectory /var/opt/mssql/audit

# Configure Linux for SQL Server performance
echo 'mssql   soft  nofile  65536' | sudo tee -a /etc/security/limits.conf
echo 'mssql   hard  nofile  65536' | sudo tee -a /etc/security/limits.conf

# Kernel optimization
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# SQL Server optimizations
vm.max_map_count = 262144
vm.swappiness = 1
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
EOF

sudo sysctl -p
sudo systemctl restart mssql-server
```

### Database and User Setup
```bash
# Connect and create production database setup
sqlcmd -S localhost -U SA <<EOF
-- Create application database
CREATE DATABASE [MyAppDB];
GO

-- Create application login
CREATE LOGIN [appuser] WITH PASSWORD = 'AppUserSecurePassword2024!', 
    DEFAULT_DATABASE = [MyAppDB],
    CHECK_POLICY = ON,
    CHECK_EXPIRATION = ON;
GO

-- Switch to application database
USE [MyAppDB];
GO

-- Create database user
CREATE USER [appuser] FOR LOGIN [appuser];
GO

-- Grant necessary permissions
ALTER ROLE [db_datareader] ADD MEMBER [appuser];
ALTER ROLE [db_datawriter] ADD MEMBER [appuser];
GO

-- Create backup user
CREATE LOGIN [backup_user] WITH PASSWORD = 'BackupUserPassword2024!';
GO

CREATE USER [backup_user] FOR LOGIN [backup_user];
GO

-- Grant backup permissions
ALTER ROLE [db_backupoperator] ADD MEMBER [backup_user];
GO

-- Create monitoring user
CREATE LOGIN [monitor_user] WITH PASSWORD = 'MonitorUserPassword2024!';
GO

-- Grant view server state for monitoring
GRANT VIEW SERVER STATE TO [monitor_user];
GRANT VIEW ANY DEFINITION TO [monitor_user];
GO

-- Disable SA account for security (after creating admin user)
-- ALTER LOGIN [SA] DISABLE;
-- GO

-- Show users
SELECT name, type_desc, create_date, modify_date FROM sys.server_principals WHERE type IN ('S', 'U');
GO
EXIT
EOF
```

## High Availability and Backup

### Always On Availability Groups
```bash
# Enable Always On Availability Groups
sudo /opt/mssql/bin/mssql-conf set hadr.hadrenabled 1
sudo systemctl restart mssql-server

# Configure database for Always On
sqlcmd -S localhost -U SA <<EOF
-- Set database to full recovery model
ALTER DATABASE [MyAppDB] SET RECOVERY FULL;
GO

-- Create full backup (required for AG)
BACKUP DATABASE [MyAppDB] 
TO DISK = '/var/opt/mssql/data/MyAppDB_Full.bak'
WITH FORMAT, INIT;
GO

-- Create log backup
BACKUP LOG [MyAppDB] 
TO DISK = '/var/opt/mssql/data/MyAppDB_Log.trn'
WITH FORMAT, INIT;
GO
EXIT
EOF
```

### Automated Backup Strategy
```bash
sudo tee /usr/local/bin/mssql-backup.sh > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="/backup/mssql"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p ${BACKUP_DIR}/{full,differential,transaction_log}

echo "Starting SQL Server backup..."

# Full backup (weekly)
if [ "$(date +%u)" -eq 7 ]; then
    sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -Q "
    BACKUP DATABASE [MyAppDB] 
    TO DISK = '${BACKUP_DIR}/full/MyAppDB_Full_${DATE}.bak'
    WITH COMPRESSION, CHECKSUM, FORMAT, INIT;
    "
    echo "Full backup completed"
fi

# Differential backup (daily)
sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -Q "
BACKUP DATABASE [MyAppDB] 
TO DISK = '${BACKUP_DIR}/differential/MyAppDB_Diff_${DATE}.bak'
WITH COMPRESSION, CHECKSUM, DIFFERENTIAL, FORMAT, INIT;
"

# Transaction log backup (every 15 minutes)
sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -Q "
BACKUP LOG [MyAppDB] 
TO DISK = '${BACKUP_DIR}/transaction_log/MyAppDB_Log_${DATE}.trn'
WITH COMPRESSION, CHECKSUM, FORMAT, INIT;
"

# Upload to cloud storage
aws s3 cp ${BACKUP_DIR}/ s3://mssql-backups/ --recursive

# Keep backups based on retention policy
find ${BACKUP_DIR}/full -name "*.bak" -mtime +30 -delete
find ${BACKUP_DIR}/differential -name "*.bak" -mtime +7 -delete  
find ${BACKUP_DIR}/transaction_log -name "*.trn" -mtime +3 -delete

echo "SQL Server backup completed: ${DATE}"
EOF

sudo chmod +x /usr/local/bin/mssql-backup.sh

# Schedule backups
echo "*/15 * * * * root /usr/local/bin/mssql-backup.sh" | sudo tee -a /etc/crontab  # Transaction log
echo "0 2 * * * root /usr/local/bin/mssql-backup.sh" | sudo tee -a /etc/crontab     # Daily differential
echo "0 1 * * 0 root /usr/local/bin/mssql-backup.sh" | sudo tee -a /etc/crontab     # Weekly full
```

## Monitoring and Health Checks

### SQL Server Health Monitoring
```bash
sudo tee /usr/local/bin/mssql-health.sh > /dev/null <<'EOF'
#!/bin/bash
HEALTH_LOG="/var/log/mssql-health.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a ${HEALTH_LOG}
}

# Check service status
if systemctl is-active mssql-server >/dev/null 2>&1; then
    log_message "✓ SQL Server service is running"
else
    log_message "✗ SQL Server service is not running"
    exit 1
fi

# Check connectivity
if sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -Q "SELECT @@VERSION;" >/dev/null 2>&1; then
    log_message "✓ SQL Server connectivity test passed"
else
    log_message "✗ SQL Server connectivity test failed"
fi

# Check database status
DB_STATUS=$(sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -h -1 -Q "
SELECT state_desc FROM sys.databases WHERE name = 'MyAppDB';" | tr -d ' \n')

if [ "$DB_STATUS" = "ONLINE" ]; then
    log_message "✓ Application database is online"
else
    log_message "⚠ Application database status: ${DB_STATUS}"
fi

# Check memory usage
MEMORY_MB=$(sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -h -1 -Q "
SELECT (physical_memory_kb/1024) FROM sys.dm_os_sys_info;" | tr -d ' ')
log_message "ℹ SQL Server memory: ${MEMORY_MB}MB"

# Check connection count
CONNECTION_COUNT=$(sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -h -1 -Q "
SELECT COUNT(*) FROM sys.dm_exec_sessions WHERE is_user_process = 1;" | tr -d ' ')
log_message "ℹ Active connections: ${CONNECTION_COUNT}"

# Check backup status
LAST_BACKUP=$(sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" -h -1 -Q "
SELECT TOP 1 backup_finish_date FROM msdb.dbo.backupset 
WHERE database_name = 'MyAppDB' AND type = 'D' 
ORDER BY backup_finish_date DESC;" | tr -d ' ')
log_message "ℹ Last full backup: ${LAST_BACKUP}"

# Check error log for issues
ERROR_COUNT=$(sudo tail -100 /var/opt/mssql/log/errorlog | grep -i error | wc -l)
if [ ${ERROR_COUNT} -gt 0 ]; then
    log_message "⚠ ${ERROR_COUNT} errors in recent log entries"
else
    log_message "✓ No recent errors in log"
fi

log_message "SQL Server health check completed"
EOF

sudo chmod +x /usr/local/bin/mssql-health.sh

# Schedule health checks every 10 minutes
echo "*/10 * * * * root /usr/local/bin/mssql-health.sh" | sudo tee -a /etc/crontab
```

### Performance Monitoring
```bash
sudo tee /usr/local/bin/mssql-performance.sh > /dev/null <<'EOF'
#!/bin/bash
PERF_LOG="/var/log/mssql-performance.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a ${PERF_LOG}
}

# Get performance metrics
sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" <<TSQL > /tmp/mssql-perf.txt
-- CPU usage
SELECT 
    'CPU_Percent' as metric,
    AVG(signal_wait_time_ms) * 100.0 / AVG(signal_wait_time_ms + wait_time_ms) as value
FROM sys.dm_os_wait_stats;

-- Memory usage
SELECT 
    'Memory_MB' as metric,
    (physical_memory_kb/1024) as value
FROM sys.dm_os_sys_info;

-- Database file sizes
SELECT 
    DB_NAME(database_id) as database_name,
    type_desc,
    size * 8 / 1024 as size_mb
FROM sys.master_files 
WHERE database_id > 4;

-- Wait statistics
SELECT TOP 10
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    max_wait_time_ms,
    signal_wait_time_ms
FROM sys.dm_os_wait_stats
WHERE wait_time_ms > 0
ORDER BY wait_time_ms DESC;
GO
EXIT
TSQL

log_message "SQL Server performance metrics collected"
cat /tmp/mssql-perf.txt >> ${PERF_LOG}
EOF

sudo chmod +x /usr/local/bin/mssql-performance.sh

# Schedule performance monitoring
echo "0 */6 * * * root /usr/local/bin/mssql-performance.sh" | sudo tee -a /etc/crontab
```

## Security Hardening

### Advanced Security Configuration
```bash
# Configure advanced security features
sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" <<EOF
-- Enable advanced security features
sp_configure 'show advanced options', 1;
RECONFIGURE;
GO

-- Configure security settings
sp_configure 'clr enabled', 0;  -- Disable CLR integration
sp_configure 'cross db ownership chaining', 0;  -- Disable cross-database ownership chaining
sp_configure 'database mail xps', 0;  -- Disable database mail if not needed
sp_configure 'remote access', 0;  -- Disable remote access
sp_configure 'remote admin connections', 0;  -- Disable remote admin connections
sp_configure 'scan for startup procs', 0;  -- Disable scan for startup procedures

RECONFIGURE;
GO

-- Configure audit
USE [master];
GO

CREATE SERVER AUDIT [SecurityAudit]
TO FILE 
(   FILEPATH = '/var/opt/mssql/audit/'
    ,MAXSIZE = 100 MB
    ,MAX_ROLLOVER_FILES = 10
    ,RESERVE_DISK_SPACE = OFF
)
WITH
(   QUEUE_DELAY = 1000
    ,ON_FAILURE = CONTINUE
);
GO

ALTER SERVER AUDIT [SecurityAudit] WITH (STATE = ON);
GO

-- Create audit specification for failed logins
CREATE SERVER AUDIT SPECIFICATION [FailedLogins_Audit]
FOR SERVER AUDIT [SecurityAudit]
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP),
ADD (LOGOUT_GROUP)
WITH (STATE = ON);
GO

-- Enable SQL Server Agent
EXEC sp_configure 'Agent XPs', 1;
RECONFIGURE;
GO
EXIT
EOF

# Create audit directory
sudo mkdir -p /var/opt/mssql/audit
sudo chown mssql:mssql /var/opt/mssql/audit
```

### Firewall Configuration
```bash
# Configure UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 1433 comment 'SQL Server - internal network only'
sudo ufw deny 1433 comment 'Block SQL Server from public internet'

# Configure firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --new-zone=mssql
sudo firewall-cmd --permanent --zone=mssql --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=mssql --add-port=1433/tcp
sudo firewall-cmd --reload

# Fail2ban configuration for SQL Server
sudo tee /etc/fail2ban/filter.d/mssql.conf > /dev/null <<EOF
[Definition]
failregex = Login failed for user.*<HOST>
ignoreregex =
EOF

sudo tee /etc/fail2ban/jail.d/mssql.conf > /dev/null <<EOF
[mssql]
enabled = true
port = 1433
filter = mssql
logpath = /var/opt/mssql/log/errorlog
maxretry = 5
bantime = 3600
findtime = 600
action = iptables[name=MSSQL, port=1433, protocol=tcp]
EOF

sudo systemctl restart fail2ban
```

## Maintenance and Administration

### Automated Maintenance
```bash
sudo tee /usr/local/bin/mssql-maintenance.sh > /dev/null <<'EOF'
#!/bin/bash
MAINTENANCE_LOG="/var/log/mssql-maintenance.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a ${MAINTENANCE_LOG}
}

log_message "Starting SQL Server maintenance..."

# Database maintenance
sqlcmd -S localhost -U SA -P "${MSSQL_SA_PASSWORD}" <<TSQL
-- Update statistics
USE [MyAppDB];
GO

EXEC sp_updatestats;
GO

-- Rebuild indexes with high fragmentation
DECLARE @sql NVARCHAR(MAX) = '';
SELECT @sql = @sql + 'ALTER INDEX ' + i.name + ' ON ' + OBJECT_SCHEMA_NAME(i.object_id) + '.' + OBJECT_NAME(i.object_id) + ' REBUILD;' + CHAR(13)
FROM sys.indexes i
INNER JOIN sys.dm_db_index_physical_stats(DB_ID(), NULL, NULL, NULL, 'LIMITED') ps
    ON i.object_id = ps.object_id AND i.index_id = ps.index_id
WHERE ps.avg_fragmentation_in_percent > 30 AND ps.page_count > 1000;

EXEC sp_executesql @sql;
GO

-- Shrink log file if necessary
DBCC SHRINKFILE (MyAppDB_Log, 1024);  -- Shrink to 1GB
GO

-- Check database integrity
DBCC CHECKDB ('MyAppDB') WITH NO_INFOMSGS;
GO
EXIT
TSQL

# Clean up old backup files on disk
find /var/opt/mssql/data -name "*.bak" -mtime +7 -delete
find /var/opt/mssql/data -name "*.trn" -mtime +1 -delete

log_message "SQL Server maintenance completed"
EOF

sudo chmod +x /usr/local/bin/mssql-maintenance.sh

# Schedule weekly maintenance
echo "0 1 * * 0 root /usr/local/bin/mssql-maintenance.sh" | sudo tee -a /etc/crontab
```

### Log Management
```bash
# Configure log rotation for SQL Server
sudo tee /etc/logrotate.d/mssql > /dev/null <<EOF
/var/opt/mssql/log/errorlog {
    daily
    rotate 30
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 644 mssql mssql
}

/var/opt/mssql/audit/*.sqlaudit {
    daily  
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    create 644 mssql mssql
}
EOF
```

## 6. Troubleshooting

### Common Issues and Solutions
```bash
# Check SQL Server service status
sudo systemctl status mssql-server
sudo journalctl -u mssql-server -f

# Check SQL Server error log
sudo tail -f /var/opt/mssql/log/errorlog

# Test connectivity
sqlcmd -S localhost -U SA
telnet localhost 1433

# Check SQL Server configuration
sudo /opt/mssql/bin/mssql-conf list

# Check processes and memory
ps aux | grep sqlservr
pmap -x $(pgrep sqlservr)

# Check network connectivity
ss -tulpn | grep 1433
netstat -tulpn | grep mssql

# Database connectivity test
sqlcmd -S localhost -U SA -P password -Q "SELECT @@VERSION;"

# Check disk space
df -h /var/opt/mssql
du -sh /var/opt/mssql/data

# Performance troubleshooting
sqlcmd -S localhost -U SA -P password <<EOF
-- Check blocking processes
SELECT 
    session_id,
    blocking_session_id,
    wait_type,
    wait_resource,
    wait_time,
    cpu_time,
    logical_reads,
    reads,
    writes
FROM sys.dm_exec_requests 
WHERE blocking_session_id <> 0;
GO

-- Check expensive queries
SELECT TOP 10
    qs.sql_handle,
    qs.execution_count,
    qs.total_worker_time / qs.execution_count AS avg_cpu_time,
    qs.total_elapsed_time / qs.execution_count AS avg_elapsed_time,
    qs.total_logical_reads / qs.execution_count AS avg_logical_reads,
    SUBSTRING(qt.text, (qs.statement_start_offset/2)+1, 
        ((CASE WHEN qs.statement_end_offset = -1 
            THEN LEN(CONVERT(NVARCHAR(MAX), qt.text)) * 2 
            ELSE qs.statement_end_offset END - qs.statement_start_offset)/2) + 1) AS query_text
FROM sys.dm_exec_query_stats qs
CROSS APPLY sys.dm_exec_sql_text(qs.sql_handle) qt
ORDER BY qs.total_worker_time / qs.execution_count DESC;
GO

-- Check wait statistics
SELECT TOP 10 
    wait_type,
    waiting_tasks_count,
    wait_time_ms,
    max_wait_time_ms,
    signal_wait_time_ms
FROM sys.dm_os_wait_stats 
WHERE wait_time_ms > 0
ORDER BY wait_time_ms DESC;
GO
EXIT
EOF

# Reset SA password if forgotten
sudo /opt/mssql/bin/mssql-conf set-sa-password

# Restart SQL Server service
sudo systemctl restart mssql-server

# Check SQL Server agent status
sqlcmd -S localhost -U SA -P password -Q "
SELECT @@SERVERNAME as server_name, 
       SERVERPROPERTY('IsAdvancedAnalyticsInstalled') as advanced_analytics,
       SERVERPROPERTY('IsClustered') as is_clustered;"

# Force configuration refresh
sudo /opt/mssql/bin/mssql-conf validate
```

### Advanced Debugging
```bash
# Enable detailed logging
sudo /opt/mssql/bin/mssql-conf set control.loglevel all
sudo systemctl restart mssql-server

# Check SQL Server process details
cat /proc/$(pgrep sqlservr)/status
cat /proc/$(pgrep sqlservr)/limits

# Monitor SQL Server activity in real-time
sqlcmd -S localhost -U SA -P password <<EOF
-- Monitor active sessions
SELECT 
    s.session_id,
    s.login_name,
    s.host_name,
    s.program_name,
    s.status,
    r.command,
    r.cpu_time,
    r.total_elapsed_time
FROM sys.dm_exec_sessions s
LEFT JOIN sys.dm_exec_requests r ON s.session_id = r.session_id
WHERE s.is_user_process = 1;
GO

-- Monitor lock waits
SELECT 
    tl.resource_type,
    tl.resource_database_id,
    tl.resource_associated_entity_id,
    tl.request_mode,
    tl.request_session_id,
    wt.blocking_session_id
FROM sys.dm_tran_locks tl
INNER JOIN sys.dm_os_waiting_tasks wt
    ON tl.lock_owner_address = wt.resource_address;
GO
EXIT
EOF

# Check system compatibility
sudo /opt/mssql/bin/mssql-conf validate
```

## Additional Resources

- [SQL Server on Linux Documentation](https://docs.microsoft.com/en-us/sql/linux/)
- [SQL Server Security Best Practices](https://docs.microsoft.com/en-us/sql/relational-databases/security/)
- [Performance Tuning Guide](https://docs.microsoft.com/en-us/sql/linux/sql-server-linux-performance-best-practices)
- [Always On Availability Groups](https://docs.microsoft.com/en-us/sql/database-engine/availability-groups/)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection.