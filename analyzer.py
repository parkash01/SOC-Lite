import re
import csv
from collections import Counter

LOG_FILE = "sample_logs/auth.log"
REPORT_FILE = "reports/security_report.csv"

failed_ips = []
failed_users = []
success_logins = 0

with open(LOG_FILE, "r") as file:
    for line in file:

        # Failed login
        failed = re.search(
            r"FAILED_LOGIN IP=([\d.]+) USER=(\S+)",
            line
        )

        if failed:
            failed_ips.append(failed.group(1))
            failed_users.append(failed.group(2))

        # Successful login
        if "SUCCESS_LOGIN" in line:
            success_logins += 1


ip_counts = Counter(failed_ips)
user_counts = Counter(failed_users)


def get_severity(attempts):
    if attempts >= 10:
        return "CRITICAL"
    elif attempts >= 5:
        return "HIGH"
    elif attempts >= 3:
        return "MEDIUM"
    else:
        return "LOW"


print("\n========================================")
print("        SOC-Lite Security Report")
print("========================================\n")

print(f"Total Failed Logins : {len(failed_ips)}")
print(f"Successful Logins   : {success_logins}")

print("\nSuspicious IPs:")

report_data = []

for ip, count in ip_counts.items():

    severity = get_severity(count)

    if count >= 3:
        print(f"[{severity}] {ip} -> {count} failed attempts")

        report_data.append({
            "IP Address": ip,
            "Attempts": count,
            "Severity": severity
        })


print("\nTargeted Users:")

for user, count in user_counts.most_common():
    print(f"{user} -> {count} failed attempts")


# Save CSV report
with open(REPORT_FILE, "w", newline="") as file:

    writer = csv.DictWriter(
        file,
        fieldnames=["IP Address", "Attempts", "Severity"]
    )

    writer.writeheader()
    writer.writerows(report_data)


print("\n----------------------------------------")
print(f"Report saved to: {REPORT_FILE}")
print("----------------------------------------")