#!/usr/bin/env python3
"""
EC2 Security Group Security Analyzer
Analyzes all EC2 instances in a specified region and flags suspicious security group rules.
"""

import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from collections import defaultdict

class EC2SecurityAnalyzer:
    def __init__(self, region_name='us-east-1'):
        """Initialize the analyzer with AWS region."""
        self.region_name = region_name
        try:
            self.ec2_client = boto3.client('ec2', region_name=region_name)
            self.ec2_resource = boto3.resource('ec2', region_name=region_name)
        except NoCredentialsError:
            print("❌ AWS credentials not found. Please configure your credentials.")
            raise
        except Exception as e:
            print(f"❌ Error initializing AWS client: {e}")
            raise

    def is_suspicious_rule(self, rule):
        """
        Identify suspicious security group rules.
        Returns tuple: (is_suspicious, reason)
        """
        suspicious_reasons = []
        
        # Check for 0.0.0.0/0 (any IPv4) access
        if rule.get('CidrBlocks'):
            for cidr in rule['CidrBlocks']:
                if cidr.get('CidrIp') == '0.0.0.0/0':
                    suspicious_reasons.append("Open to all IPv4 (0.0.0.0/0)")
        
        # Check for ::/0 (any IPv6) access
        if rule.get('Ipv6Ranges'):
            for ipv6 in rule['Ipv6Ranges']:
                if ipv6.get('CidrIpv6') == '::/0':
                    suspicious_reasons.append("Open to all IPv6 (::/0)")
        
        # Check for wide port ranges
        from_port = rule.get('FromPort', 0)
        to_port = rule.get('ToPort', 0)
        if from_port == 0 and to_port == 65535:
            suspicious_reasons.append("All ports open (0-65535)")
        elif to_port - from_port > 1000:
            suspicious_reasons.append(f"Wide port range ({from_port}-{to_port})")
        
        # Check for common risky ports open to 0.0.0.0/0
        risky_ports = {22: 'SSH', 3389: 'RDP', 23: 'Telnet', 21: 'FTP', 1433: 'SQL Server', 
                      3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB'}
        
        if rule.get('CidrBlocks'):
            for cidr in rule['CidrBlocks']:
                if cidr.get('CidrIp') == '0.0.0.0/0':
                    if from_port in risky_ports:
                        suspicious_reasons.append(f"Risky port {from_port} ({risky_ports[from_port]}) open to internet")
                    elif from_port <= 22 <= to_port:
                        suspicious_reasons.append("SSH port (22) potentially open to internet")
                    elif from_port <= 3389 <= to_port:
                        suspicious_reasons.append("RDP port (3389) potentially open to internet")
        
        return len(suspicious_reasons) > 0, suspicious_reasons

    def format_rule(self, rule, rule_type="inbound"):
        """Format a security group rule for display."""
        protocol = rule.get('IpProtocol', 'Unknown')
        from_port = rule.get('FromPort', 'N/A')
        to_port = rule.get('ToPort', 'N/A')
        
        # Format port range
        if from_port == to_port:
            port_range = str(from_port)
        elif from_port == 'N/A':
            port_range = 'All'
        else:
            port_range = f"{from_port}-{to_port}"
        
        # Format sources/destinations
        sources = []
        
        # CIDR blocks
        if rule.get('CidrBlocks'):
            for cidr in rule['CidrBlocks']:
                desc = cidr.get('Description', '')
                cidr_ip = cidr.get('CidrIp', '')
                sources.append(f"{cidr_ip}" + (f" ({desc})" if desc else ""))
        
        # IPv6 ranges
        if rule.get('Ipv6Ranges'):
            for ipv6 in rule['Ipv6Ranges']:
                desc = ipv6.get('Description', '')
                cidr_ipv6 = ipv6.get('CidrIpv6', '')
                sources.append(f"{cidr_ipv6}" + (f" ({desc})" if desc else ""))
        
        # Security group references
        if rule.get('UserIdGroupPairs'):
            for sg_ref in rule['UserIdGroupPairs']:
                group_id = sg_ref.get('GroupId', '')
                desc = sg_ref.get('Description', '')
                sources.append(f"sg:{group_id}" + (f" ({desc})" if desc else ""))
        
        # Prefix lists
        if rule.get('PrefixListIds'):
            for prefix in rule['PrefixListIds']:
                prefix_id = prefix.get('PrefixListId', '')
                desc = prefix.get('Description', '')
                sources.append(f"pl:{prefix_id}" + (f" ({desc})" if desc else ""))
        
        if not sources:
            sources = ['No sources specified']
        
        return {
            'type': rule_type,
            'protocol': protocol,
            'port_range': port_range,
            'sources': sources,
            'raw_rule': rule
        }

    def analyze_security_group(self, sg):
        """Analyze a single security group."""
        sg_info = {
            'group_id': sg.id,
            'group_name': sg.group_name,
            'description': sg.description,
            'vpc_id': sg.vpc_id,
            'inbound_rules': [],
            'outbound_rules': [],
            'suspicious_rules': [],
            'total_rules': 0
        }
        
        # Analyze inbound rules
        for rule in sg.ip_permissions:
            formatted_rule = self.format_rule(rule, "inbound")
            sg_info['inbound_rules'].append(formatted_rule)
            
            is_suspicious, reasons = self.is_suspicious_rule(rule)
            if is_suspicious:
                sg_info['suspicious_rules'].append({
                    'rule': formatted_rule,
                    'reasons': reasons,
                    'direction': 'inbound'
                })
        
        # Analyze outbound rules
        for rule in sg.ip_permissions_egress:
            formatted_rule = self.format_rule(rule, "outbound")
            sg_info['outbound_rules'].append(formatted_rule)
            
            is_suspicious, reasons = self.is_suspicious_rule(rule)
            if is_suspicious:
                sg_info['suspicious_rules'].append({
                    'rule': formatted_rule,
                    'reasons': reasons,
                    'direction': 'outbound'
                })
        
        sg_info['total_rules'] = len(sg_info['inbound_rules']) + len(sg_info['outbound_rules'])
        
        return sg_info

    def get_ec2_instances_and_security_groups(self):
        """Get all EC2 instances and their associated security groups."""
        try:
            print(f"🔍 Scanning EC2 instances in region: {self.region_name}")
            
            # Get all instances
            instances = list(self.ec2_resource.instances.all())
            print(f"📊 Found {len(instances)} EC2 instances")
            
            # Collect all unique security group IDs
            sg_ids = set()
            instance_info = {}
            
            for instance in instances:
                instance_name = 'Unnamed'
                if instance.tags:
                    for tag in instance.tags:
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                
                instance_sg_ids = [sg['GroupId'] for sg in instance.security_groups]
                sg_ids.update(instance_sg_ids)
                
                instance_info[instance.id] = {
                    'name': instance_name,
                    'state': instance.state['Name'],
                    'instance_type': instance.instance_type,
                    'security_groups': instance_sg_ids
                }
            
            print(f"🛡️  Found {len(sg_ids)} unique security groups")
            
            # Get all security group details
            security_groups = {}
            if sg_ids:
                sg_resources = self.ec2_resource.security_groups.filter(GroupIds=list(sg_ids))
                for sg in sg_resources:
                    security_groups[sg.id] = self.analyze_security_group(sg)
            
            return {
                'instances': instance_info,
                'security_groups': security_groups,
                'region': self.region_name,
                'scan_time': datetime.now().isoformat()
            }
            
        except ClientError as e:
            print(f"❌ AWS API Error: {e}")
            raise
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            raise

    def print_results(self, results):
        """Print results to console in a nice format."""
        print("\n" + "="*80)
        print(f"🔒 EC2 SECURITY GROUP ANALYSIS - {results['region'].upper()}")
        print("="*80)
        print(f"📅 Scan Time: {results['scan_time']}")
        print(f"🖥️  Total Instances: {len(results['instances'])}")
        print(f"🛡️  Total Security Groups: {len(results['security_groups'])}")
        
        # Count suspicious rules
        total_suspicious = 0
        for sg_id, sg_info in results['security_groups'].items():
            total_suspicious += len(sg_info['suspicious_rules'])
        
        print(f"⚠️  Suspicious Rules Found: {total_suspicious}")
        print("\n")
        
        # Print instance summary
        print("📋 EC2 INSTANCES SUMMARY")
        print("-" * 50)
        for instance_id, info in results['instances'].items():
            status_emoji = "🟢" if info['state'] == 'running' else "🔴" if info['state'] == 'stopped' else "🟡"
            print(f"{status_emoji} {instance_id} ({info['name']}) - {info['instance_type']} - {info['state']}")
            print(f"   Security Groups: {', '.join(info['security_groups'])}")
        
        print("\n")
        
        # Print security group details
        for sg_id, sg_info in results['security_groups'].items():
            print(f"🛡️  SECURITY GROUP: {sg_info['group_name']} ({sg_id})")
            print(f"   Description: {sg_info['description']}")
            print(f"   VPC: {sg_info['vpc_id']}")
            print(f"   Total Rules: {sg_info['total_rules']}")
            
            if sg_info['suspicious_rules']:
                print(f"   ⚠️  SUSPICIOUS RULES: {len(sg_info['suspicious_rules'])}")
                for susp_rule in sg_info['suspicious_rules']:
                    rule = susp_rule['rule']
                    print(f"      🚨 {susp_rule['direction'].upper()}: {rule['protocol']} port {rule['port_range']}")
                    print(f"         Sources: {', '.join(rule['sources'])}")
                    for reason in susp_rule['reasons']:
                        print(f"         ❌ {reason}")
            
            # Print all inbound rules
            if sg_info['inbound_rules']:
                print(f"   📥 INBOUND RULES ({len(sg_info['inbound_rules'])}):")
                for rule in sg_info['inbound_rules']:
                    suspicious_marker = "🚨" if any(r['rule'] == rule for r in sg_info['suspicious_rules']) else "✅"
                    print(f"      {suspicious_marker} {rule['protocol']} port {rule['port_range']} from {', '.join(rule['sources'])}")
            
            # Print all outbound rules
            if sg_info['outbound_rules']:
                print(f"   📤 OUTBOUND RULES ({len(sg_info['outbound_rules'])}):")
                for rule in sg_info['outbound_rules']:
                    suspicious_marker = "🚨" if any(r['rule'] == rule for r in sg_info['suspicious_rules']) else "✅"
                    print(f"      {suspicious_marker} {rule['protocol']} port {rule['port_range']} to {', '.join(rule['sources'])}")
            
            print("\n" + "-" * 50 + "\n")

    def save_results(self, results, filename=None):
        """Save results to a file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ec2_security_analysis_{results['region']}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"💾 Results saved to: {filename}")
            
            # Also create a readable text report
            text_filename = filename.replace('.json', '_report.txt')
            with open(text_filename, 'w') as f:
                f.write(f"EC2 Security Group Analysis Report - {results['region'].upper()}\n")
                f.write("=" * 60 + "\n")
                f.write(f"Scan Time: {results['scan_time']}\n")
                f.write(f"Total Instances: {len(results['instances'])}\n")
                f.write(f"Total Security Groups: {len(results['security_groups'])}\n\n")
                
                # Summary of suspicious rules
                total_suspicious = sum(len(sg['suspicious_rules']) for sg in results['security_groups'].values())
                f.write(f"SUSPICIOUS RULES SUMMARY: {total_suspicious} total\n")
                f.write("-" * 40 + "\n")
                
                for sg_id, sg_info in results['security_groups'].items():
                    if sg_info['suspicious_rules']:
                        f.write(f"\nSecurity Group: {sg_info['group_name']} ({sg_id})\n")
                        for susp_rule in sg_info['suspicious_rules']:
                            rule = susp_rule['rule']
                            f.write(f"  - {susp_rule['direction'].upper()}: {rule['protocol']} port {rule['port_range']}\n")
                            f.write(f"    Sources: {', '.join(rule['sources'])}\n")
                            for reason in susp_rule['reasons']:
                                f.write(f"    WARNING: {reason}\n")
                
                # Detailed security group information
                f.write(f"\n\nDETAILED SECURITY GROUP ANALYSIS\n")
                f.write("=" * 40 + "\n")
                
                for sg_id, sg_info in results['security_groups'].items():
                    f.write(f"\nSecurity Group: {sg_info['group_name']} ({sg_id})\n")
                    f.write(f"Description: {sg_info['description']}\n")
                    f.write(f"VPC: {sg_info['vpc_id']}\n")
                    f.write(f"Total Rules: {sg_info['total_rules']}\n")
                    
                    if sg_info['inbound_rules']:
                        f.write(f"\nInbound Rules ({len(sg_info['inbound_rules'])}):\n")
                        for rule in sg_info['inbound_rules']:
                            f.write(f"  - {rule['protocol']} port {rule['port_range']} from {', '.join(rule['sources'])}\n")
                    
                    if sg_info['outbound_rules']:
                        f.write(f"\nOutbound Rules ({len(sg_info['outbound_rules'])}):\n")
                        for rule in sg_info['outbound_rules']:
                            f.write(f"  - {rule['protocol']} port {rule['port_range']} to {', '.join(rule['sources'])}\n")
                    
                    f.write("\n" + "-" * 50 + "\n")
            
            print(f"📄 Text report saved to: {text_filename}")
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")

def main():
    """Main function to run the security analysis."""
    print("🚀 EC2 Security Group Analyzer")
    print("=" * 40)
    
    # Get region from user
    region = input("Enter AWS region (default: us-east-1): ").strip()
    if not region:
        region = 'us-east-1'
    
    try:
        # Initialize analyzer
        analyzer = EC2SecurityAnalyzer(region)
        
        # Perform analysis
        results = analyzer.get_ec2_instances_and_security_groups()
        
        # Print results to console
        analyzer.print_results(results)
        
        # Save results to file
        analyzer.save_results(results)
        
        print("\n✅ Analysis complete!")
        
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
