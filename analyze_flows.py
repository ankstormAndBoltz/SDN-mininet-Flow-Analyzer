import subprocess
import re
import time

SWITCHES = ['s1', 's2', 's3']

def parse_flows(switch):
    result = subprocess.run(
        ['sudo', 'ovs-ofctl', 'dump-flows', switch],
        capture_output=True, text=True
    )
    return result.stdout.splitlines()

def analyze(switch, lines):
    print(f"\n{'='*50}")
    print(f"  SWITCH: {switch}")
    print(f"{'='*50}")

    active = 0
    unused = 0

    for line in lines:
        if 'n_packets' not in line:
            continue

        pkts_match = re.search(r'n_packets=(\d+)', line)
        bytes_match = re.search(r'n_bytes=(\d+)', line)
        priority_match = re.search(r'priority=(\d+)', line)

        pkts = int(pkts_match.group(1)) if pkts_match else 0
        byts = int(bytes_match.group(1)) if bytes_match else 0
        priority = int(priority_match.group(1)) if priority_match else 0

        status = "ACTIVE" if pkts > 0 else "UNUSED"

        if pkts > 0:
            active += 1
        else:
            unused += 1

        # Identify firewall rules (priority 100)
        rule_type = "FIREWALL-DROP" if priority == 100 else \
                    "TABLE-MISS" if priority == 0 else "LEARNED"

        print(f"  [{status}] [{rule_type}] priority={priority} "
              f"packets={pkts} bytes={byts}")
        print(f"    {line.strip()}")

    print(f"\n  Summary: {active} active, {unused} unused flows")

def main():
    print("\n*** SDN Flow Table Analyzer ***")
    print(f"*** Time: {time.strftime('%Y-%m-%d %H:%M:%S')} ***\n")

    for switch in SWITCHES:
        lines = parse_flows(switch)
        if not lines:
            print(f"\n[WARNING] No data for {switch} — is Mininet running?")
            continue
        analyze(switch, lines)

    print(f"\n{'='*50}")
    print("Analysis complete.")
    print(f"{'='*50}\n")

if __name__ == '__main__':
    main()
