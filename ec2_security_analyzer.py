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

    def get_sg_name_by_id(self, sg_id, security_groups):
        """Get security group name by ID."""
        if sg_id in security_groups:
            return security_groups[sg_id]['group_name']
        return 'Unknown SG'

    def format_source_with_names(self, source, security_groups):
        """Format source with security group names where applicable."""
        if source.startswith('sg:'):
            sg_id = source.replace('sg:', '').split(' ')[0]
            sg_name = self.get_sg_name_by_id(sg_id, security_groups)
            return f"{source} [{sg_name}]"
        return source

    def print_results(self, results):
        """Print results to console in a nice format organized by EC2 instance."""
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
        
        # Print detailed analysis by EC2 instance
        print("📋 DETAILED EC2 SECURITY ANALYSIS")
        print("="*80)
        
        for instance_id, instance_info in results['instances'].items():
            status_emoji = "🟢" if instance_info['state'] == 'running' else "🔴" if instance_info['state'] == 'stopped' else "🟡"
            print(f"\n{status_emoji} EC2 {instance_id} [{instance_info['name']}]:")
            print(f"    Instance Type: {instance_info['instance_type']} | State: {instance_info['state']}")
            
            # Analyze each security group attached to this instance
            open_ports_summary = []
            
            for sg_id in instance_info['security_groups']:
                if sg_id in results['security_groups']:
                    sg_info = results['security_groups'][sg_id]
                    print(f"\n    🛡️  Security Group {sg_id} [{sg_info['group_name']}]:")
                    print(f"        Description: {sg_info['description']}")
                    
                    # Inbound rules
                    if sg_info['inbound_rules']:
                        print(f"        📥 Inbound Rules ({len(sg_info['inbound_rules'])}):")
                        for rule in sg_info['inbound_rules']:
                            suspicious_marker = "🚨" if any(r['rule'] == rule and r['direction'] == 'inbound' for r in sg_info['suspicious_rules']) else "✅"
                            
                            # Format sources with SG names
                            formatted_sources = []
                            for source in rule['sources']:
                                formatted_source = self.format_source_with_names(source, results['security_groups'])
                                formatted_sources.append(formatted_source)
                            
                            rule_desc = f"{rule['protocol']} port {rule['port_range']} from {', '.join(formatted_sources)}"
                            print(f"            {suspicious_marker} {rule_desc}")
                            
                            # Add to open ports summary
                            for source in formatted_sources:
                                port_info = f"Port {rule['port_range']} ({rule['protocol']}) from {source}"
                                if suspicious_marker == "🚨":
                                    port_info += " ⚠️ SUSPICIOUS"
                                open_ports_summary.append(port_info)
                    
                    # Outbound rules
                    if sg_info['outbound_rules']:
                        print(f"        📤 Outbound Rules ({len(sg_info['outbound_rules'])}):")
                        for rule in sg_info['outbound_rules']:
                            suspicious_marker = "🚨" if any(r['rule'] == rule and r['direction'] == 'outbound' for r in sg_info['suspicious_rules']) else "✅"
                            
                            # Format destinations with SG names
                            formatted_destinations = []
                            for dest in rule['sources']:  # Note: 'sources' contains destinations for outbound rules
                                formatted_dest = self.format_source_with_names(dest, results['security_groups'])
                                formatted_destinations.append(formatted_dest)
                            
                            rule_desc = f"{rule['protocol']} port {rule['port_range']} to {', '.join(formatted_destinations)}"
                            print(f"            {suspicious_marker} {rule_desc}")
                    
                    # Show suspicious rules for this SG
                    if sg_info['suspicious_rules']:
                        print(f"        ⚠️  SUSPICIOUS RULES IN THIS SG:")
                        for susp_rule in sg_info['suspicious_rules']:
                            rule = susp_rule['rule']
                            formatted_sources = []
                            for source in rule['sources']:
                                formatted_source = self.format_source_with_names(source, results['security_groups'])
                                formatted_sources.append(formatted_source)
                            
                            print(f"            🚨 {susp_rule['direction'].upper()}: {rule['protocol']} port {rule['port_range']}")
                            print(f"               Sources/Destinations: {', '.join(formatted_sources)}")
                            for reason in susp_rule['reasons']:
                                print(f"               ❌ {reason}")
            
            # Summary for this EC2 instance
            print(f"\n    📊 SUMMARY for EC2 {instance_id} [{instance_info['name']}]:")
            if open_ports_summary:
                print(f"        This instance has the following open ports:")
                for i, port_info in enumerate(open_ports_summary, 1):
                    print(f"        {i}. {port_info}")
            else:
                print(f"        ✅ No inbound rules found (or no security groups attached)")
            
            print("\n" + "-" * 80)

    def save_results(self, results, filename=None):
        """Save results to a file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ec2_security_analysis_{results['region']}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"💾 Results saved to: {filename}")
            
            # Also create a readable text report with the new format
            text_filename = filename.replace('.json', '_report.txt')
            with open(text_filename, 'w') as f:
                f.write(f"EC2 Security Group Analysis Report - {results['region'].upper()}\n")
                f.write("=" * 80 + "\n")
                f.write(f"Scan Time: {results['scan_time']}\n")
                f.write(f"Total Instances: {len(results['instances'])}\n")
                f.write(f"Total Security Groups: {len(results['security_groups'])}\n")
                
                # Count suspicious rules
                total_suspicious = sum(len(sg['suspicious_rules']) for sg in results['security_groups'].values())
                f.write(f"Suspicious Rules Found: {total_suspicious}\n\n")
                
                # Detailed analysis by EC2 instance
                f.write("DETAILED EC2 SECURITY ANALYSIS\n")
                f.write("=" * 80 + "\n")
                
                for instance_id, instance_info in results['instances'].items():
                    status_indicator = "[RUNNING]" if instance_info['state'] == 'running' else "[STOPPED]" if instance_info['state'] == 'stopped' else f"[{instance_info['state'].upper()}]"
                    f.write(f"\nEC2 {instance_id} [{instance_info['name']}] {status_indicator}:\n")
                    f.write(f"    Instance Type: {instance_info['instance_type']} | State: {instance_info['state']}\n")
                    
                    # Analyze each security group attached to this instance
                    open_ports_summary = []
                    
                    for sg_id in instance_info['security_groups']:
                        if sg_id in results['security_groups']:
                            sg_info = results['security_groups'][sg_id]
                            f.write(f"\n    Security Group {sg_id} [{sg_info['group_name']}]:\n")
                            f.write(f"        Description: {sg_info['description']}\n")
                            
                            # Inbound rules
                            if sg_info['inbound_rules']:
                                f.write(f"        Inbound Rules ({len(sg_info['inbound_rules'])}):\n")
                                for rule in sg_info['inbound_rules']:
                                    suspicious_marker = "[SUSPICIOUS]" if any(r['rule'] == rule and r['direction'] == 'inbound' for r in sg_info['suspicious_rules']) else "[OK]"
                                    
                                    # Format sources with SG names
                                    formatted_sources = []
                                    for source in rule['sources']:
                                        formatted_source = self.format_source_with_names(source, results['security_groups'])
                                        formatted_sources.append(formatted_source)
                                    
                                    rule_desc = f"{rule['protocol']} port {rule['port_range']} from {', '.join(formatted_sources)}"
                                    f.write(f"            {suspicious_marker} {rule_desc}\n")
                                    
                                    # Add to open ports summary
                                    for source in formatted_sources:
                                        port_info = f"Port {rule['port_range']} ({rule['protocol']}) from {source}"
                                        if suspicious_marker == "[SUSPICIOUS]":
                                            port_info += " [SUSPICIOUS]"
                                        open_ports_summary.append(port_info)
                            
                            # Outbound rules
                            if sg_info['outbound_rules']:
                                f.write(f"        Outbound Rules ({len(sg_info['outbound_rules'])}):\n")
                                for rule in sg_info['outbound_rules']:
                                    suspicious_marker = "[SUSPICIOUS]" if any(r['rule'] == rule and r['direction'] == 'outbound' for r in sg_info['suspicious_rules']) else "[OK]"
                                    
                                    # Format destinations with SG names
                                    formatted_destinations = []
                                    for dest in rule['sources']:  # Note: 'sources' contains destinations for outbound rules
                                        formatted_dest = self.format_source_with_names(dest, results['security_groups'])
                                        formatted_destinations.append(formatted_dest)
                                    
                                    rule_desc = f"{rule['protocol']} port {rule['port_range']} to {', '.join(formatted_destinations)}"
                                    f.write(f"            {suspicious_marker} {rule_desc}\n")
                            
                            # Show suspicious rules for this SG
                            if sg_info['suspicious_rules']:
                                f.write(f"        SUSPICIOUS RULES IN THIS SG:\n")
                                for susp_rule in sg_info['suspicious_rules']:
                                    rule = susp_rule['rule']
                                    formatted_sources = []
                                    for source in rule['sources']:
                                        formatted_source = self.format_source_with_names(source, results['security_groups'])
                                        formatted_sources.append(formatted_source)
                                    
                                    f.write(f"            [ALERT] {susp_rule['direction'].upper()}: {rule['protocol']} port {rule['port_range']}\n")
                                    f.write(f"                   Sources/Destinations: {', '.join(formatted_sources)}\n")
                                    for reason in susp_rule['reasons']:
                                        f.write(f"                   WARNING: {reason}\n")
                    
                    # Summary for this EC2 instance
                    f.write(f"\n    SUMMARY for EC2 {instance_id} [{instance_info['name']}]:\n")
                    if open_ports_summary:
                        f.write(f"        This instance has the following open ports:\n")
                        for i, port_info in enumerate(open_ports_summary, 1):
                            f.write(f"        {i}. {port_info}\n")
                    else:
                        f.write(f"        No inbound rules found (or no security groups attached)\n")
                    
                    f.write("\n" + "-" * 80 + "\n")
                
                # Global suspicious rules summary at the end
                f.write(f"\nGLOBAL SUSPICIOUS RULES SUMMARY\n")
                f.write("=" * 40 + "\n")
                
                suspicious_count = 0
                for sg_id, sg_info in results['security_groups'].items():
                    if sg_info['suspicious_rules']:
                        f.write(f"\nSecurity Group: {sg_info['group_name']} ({sg_id})\n")
                        for susp_rule in sg_info['suspicious_rules']:
                            suspicious_count += 1
                            rule = susp_rule['rule']
                            formatted_sources = []
                            for source in rule['sources']:
                                formatted_source = self.format_source_with_names(source, results['security_groups'])
                                formatted_sources.append(formatted_source)
                            
                            f.write(f"  {suspicious_count}. {susp_rule['direction'].upper()}: {rule['protocol']} port {rule['port_range']}\n")
                            f.write(f"     Sources/Destinations: {', '.join(formatted_sources)}\n")
                            for reason in susp_rule['reasons']:
                                f.write(f"     WARNING: {reason}\n")
                            f.write("\n")
                
                if suspicious_count == 0:
                    f.write("No suspicious rules found! Your security groups look good.\n")
            
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
