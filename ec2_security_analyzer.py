import boto3
import json
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError
from collections import defaultdict

class EC2SecurityAnalyzer:
    def __init__(self, region_name='il-central-1'):
        """Initialize the analyzer with AWS region."""
        self.region_name = region_name
        try:
            self.ec2_client = boto3.client('ec2', region_name=region_name)
            self.ec2_resource = boto3.resource('ec2', region_name=region_name)
            self.iam_client = boto3.client('iam')
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
                
                # Analyze IAM instance profile
                instance_profile_arn = None
                if instance.iam_instance_profile:
                    instance_profile_arn = instance.iam_instance_profile['Arn']
                
                print(f"🔍 Analyzing IAM and IMDS for instance {instance.id}...")
                
                # Analyze trust policy
                trust_suspicious, trust_info, trust_reasons = self.analyze_instance_profile_trust_policy(instance_profile_arn)
                
                # Analyze IMDS configuration
                imds_suspicious, imds_info, imds_reasons = self.analyze_imds_configuration(instance)
                
                instance_info[instance.id] = {
                    'name': instance_name,
                    'state': instance.state['Name'],
                    'instance_type': instance.instance_type,
                    'security_groups': instance_sg_ids,
                    'instance_profile': {
                        'arn': instance_profile_arn,
                        'is_suspicious': trust_suspicious,
                        'trust_policy_info': trust_info,
                        'trust_policy_reasons': trust_reasons
                    },
                    'imds': {
                        'is_suspicious': imds_suspicious,
                        'configuration': imds_info,
                        'reasons': imds_reasons
                    }
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

    def analyze_instance_profile_trust_policy(self, instance_profile_arn):
        """
        Analyze IAM instance profile trust policy for suspicious configurations.
        Returns tuple: (is_suspicious, trust_policy_info, reasons)
        """
        if not instance_profile_arn:
            return False, None, []
        
        try:
            # Extract instance profile name from ARN
            profile_name = instance_profile_arn.split('/')[-1]
            
            # Get instance profile details
            response = self.iam_client.get_instance_profile(InstanceProfileName=profile_name)
            roles = response['InstanceProfile']['Roles']
            
            if not roles:
                return True, {'profile_name': profile_name, 'roles': []}, ['No roles attached to instance profile']
            
            trust_policy_info = {
                'profile_name': profile_name,
                'profile_arn': instance_profile_arn,
                'roles': []
            }
            
            suspicious_reasons = []
            
            for role in roles:
                role_name = role['RoleName']
                
                # Get role trust policy
                role_response = self.iam_client.get_role(RoleName=role_name)
                trust_policy = role_response['Role']['AssumeRolePolicyDocument']
                
                role_info = {
                    'role_name': role_name,
                    'role_arn': role['Arn'],
                    'trust_policy': trust_policy
                }
                
                # Analyze trust policy for suspicious configurations
                if 'Statement' in trust_policy:
                    for statement in trust_policy['Statement']:
                        if statement.get('Effect') == 'Allow':
                            principal = statement.get('Principal', {})
                            
                            # Check for service principals
                            if 'Service' in principal:
                                services = principal['Service']
                                if isinstance(services, str):
                                    services = [services]
                                
                                # Flag if services other than EC2 are allowed
                                non_ec2_services = [s for s in services if s != 'ec2.amazonaws.com']
                                if non_ec2_services:
                                    suspicious_reasons.append(f"Role {role_name} allows non-EC2 services: {', '.join(non_ec2_services)}")
                            
                            # Check for AWS account principals
                            if 'AWS' in principal:
                                aws_principals = principal['AWS']
                                if isinstance(aws_principals, str):
                                    aws_principals = [aws_principals]
                                
                                for aws_principal in aws_principals:
                                    if aws_principal == '*':
                                        suspicious_reasons.append(f"Role {role_name} allows ANY AWS account (*)")
                                    elif ':root' in aws_principal:
                                        # Extract account ID
                                        account_id = aws_principal.split(':')[4]
                                        suspicious_reasons.append(f"Role {role_name} allows cross-account access from account {account_id}")
                            
                            # Check for federated principals
                            if 'Federated' in principal:
                                federated_principals = principal['Federated']
                                if isinstance(federated_principals, str):
                                    federated_principals = [federated_principals]
                                suspicious_reasons.append(f"Role {role_name} allows federated access: {', '.join(federated_principals)}")
                
                trust_policy_info['roles'].append(role_info)
            
            return len(suspicious_reasons) > 0, trust_policy_info, suspicious_reasons
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchEntity':
                return True, None, [f'Instance profile or role not found: {instance_profile_arn}']
            elif error_code == 'AccessDenied':
                return True, None, [f'Access denied when checking instance profile: {instance_profile_arn}']
            else:
                return True, None, [f'Error checking instance profile {instance_profile_arn}: {str(e)}']
        except Exception as e:
            return True, None, [f'Unexpected error checking instance profile {instance_profile_arn}: {str(e)}']

    def analyze_imds_configuration(self, instance):
        """
        Analyze Instance Metadata Service (IMDS) configuration for security issues.
        Returns tuple: (is_suspicious, imds_info, reasons)
        """
        try:
            imds_info = {
                'http_tokens': 'Not configured',
                'http_put_response_hop_limit': 'Not configured',
                'http_endpoint': 'Not configured',
                'instance_metadata_tags': 'Not configured'
            }
            
            suspicious_reasons = []
            
            if hasattr(instance, 'metadata_options') and instance.metadata_options:
                metadata_options = instance.metadata_options
                
                # Check HTTP tokens (IMDSv1 vs IMDSv2)
                http_tokens = metadata_options.get('HttpTokens', 'optional')
                imds_info['http_tokens'] = http_tokens
                
                if http_tokens == 'optional':
                    suspicious_reasons.append('IMDSv1 is enabled (HttpTokens=optional) - allows unauthorized metadata access')
                
                # Check hop limit
                hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
                imds_info['http_put_response_hop_limit'] = hop_limit
                
                if hop_limit != 1:
                    suspicious_reasons.append(f'IMDS hop limit is {hop_limit} (should be 1) - may allow metadata access from containers/services')
                
                # Check if IMDS is enabled
                http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
                imds_info['http_endpoint'] = http_endpoint
                
                # Check instance metadata tags
                instance_metadata_tags = metadata_options.get('InstanceMetadataTags', 'disabled')
                imds_info['instance_metadata_tags'] = instance_metadata_tags
                
            else:
                # If no metadata options are configured, assume defaults (which are insecure)
                suspicious_reasons.append('No IMDS configuration found - likely using default insecure settings (IMDSv1 enabled)')
            
            return len(suspicious_reasons) > 0, imds_info, suspicious_reasons
            
        except Exception as e:
            return True, {'error': str(e)}, [f'Error checking IMDS configuration: {str(e)}']
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
        total_iam_suspicious = 0
        total_imds_suspicious = 0
        
        for sg_id, sg_info in results['security_groups'].items():
            total_suspicious += len(sg_info['suspicious_rules'])
        
        for instance_id, instance_info in results['instances'].items():
            if instance_info['instance_profile']['is_suspicious']:
                total_iam_suspicious += 1
            if instance_info['imds']['is_suspicious']:
                total_imds_suspicious += 1
        
        print(f"⚠️  Security Group Suspicious Rules: {total_suspicious}")
        print(f"⚠️  IAM Instance Profile Issues: {total_iam_suspicious}")
        print(f"⚠️  IMDS Configuration Issues: {total_imds_suspicious}")
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
            iam_issues_summary = []
            imds_issues_summary = []
            
            # IAM Instance Profile Analysis
            instance_profile = instance_info['instance_profile']
            if instance_profile['arn']:
                print(f"    🔑 IAM Instance Profile: {instance_profile['arn']}")
                if instance_profile['is_suspicious']:
                    print(f"        ⚠️  SUSPICIOUS IAM CONFIGURATION:")
                    for reason in instance_profile['trust_policy_reasons']:
                        print(f"            🚨 {reason}")
                        iam_issues_summary.append(reason)
                else:
                    print(f"        ✅ IAM trust policy looks secure")
                
                if instance_profile['trust_policy_info']:
                    trust_info = instance_profile['trust_policy_info']
                    print(f"        📋 Profile: {trust_info['profile_name']}")
                    for role in trust_info['roles']:
                        print(f"        📝 Role: {role['role_name']}")
            else:
                print(f"    🔑 IAM Instance Profile: None attached")
                iam_issues_summary.append("No IAM instance profile attached")
            
            # IMDS Configuration Analysis
            imds_config = instance_info['imds']
            print(f"    🛡️  IMDS Configuration:")
            if imds_config['is_suspicious']:
                print(f"        ⚠️  SUSPICIOUS IMDS CONFIGURATION:")
                for reason in imds_config['reasons']:
                    print(f"            🚨 {reason}")
                    imds_issues_summary.append(reason)
            else:
                print(f"        ✅ IMDS configuration looks secure")
            
            # Display IMDS details
            imds_info = imds_config['configuration']
            if 'error' not in imds_info:
                print(f"        📊 HTTP Tokens: {imds_info.get('http_tokens', 'N/A')}")
                print(f"        📊 Hop Limit: {imds_info.get('http_put_response_hop_limit', 'N/A')}")
                print(f"        📊 HTTP Endpoint: {imds_info.get('http_endpoint', 'N/A')}")
                print(f"        📊 Instance Metadata Tags: {imds_info.get('instance_metadata_tags', 'N/A')}")
            else:
                print(f"        ❌ Error reading IMDS config: {imds_info['error']}")
            
            print()  # Add space before security groups
            
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
            print(f"\n    📊 SECURITY SUMMARY for EC2 {instance_id} [{instance_info['name']}]:")
            
            # Network security summary
            if open_ports_summary:
                print(f"        🌐 Network Access - This instance has the following open ports:")
                for i, port_info in enumerate(open_ports_summary, 1):
                    print(f"        {i}. {port_info}")
            else:
                print(f"        🌐 Network Access - No inbound rules found (or no security groups attached)")
            
            # IAM security summary
            if iam_issues_summary:
                print(f"        🔑 IAM Issues - This instance has the following IAM security concerns:")
                for i, issue in enumerate(iam_issues_summary, 1):
                    print(f"        {i}. {issue}")
            else:
                print(f"        🔑 IAM Security - No IAM security issues detected")
            
            # IMDS security summary
            if imds_issues_summary:
                print(f"        🛡️  IMDS Issues - This instance has the following IMDS security concerns:")
                for i, issue in enumerate(imds_issues_summary, 1):
                    print(f"        {i}. {issue}")
            else:
                print(f"        🛡️  IMDS Security - No IMDS security issues detected")
            
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
                
                # Count suspicious items
                total_suspicious = sum(len(sg['suspicious_rules']) for sg in results['security_groups'].values())
                total_iam_suspicious = sum(1 for instance in results['instances'].values() if instance['instance_profile']['is_suspicious'])
                total_imds_suspicious = sum(1 for instance in results['instances'].values() if instance['imds']['is_suspicious'])
                
                f.write(f"Security Group Suspicious Rules: {total_suspicious}\n")
                f.write(f"IAM Instance Profile Issues: {total_iam_suspicious}\n")
                f.write(f"IMDS Configuration Issues: {total_imds_suspicious}\n\n")
                
                # Detailed analysis by EC2 instance
                f.write("DETAILED EC2 SECURITY ANALYSIS\n")
                f.write("=" * 80 + "\n")
                
                for instance_id, instance_info in results['instances'].items():
                    status_indicator = "[RUNNING]" if instance_info['state'] == 'running' else "[STOPPED]" if instance_info['state'] == 'stopped' else f"[{instance_info['state'].upper()}]"
                    f.write(f"\nEC2 {instance_id} [{instance_info['name']}] {status_indicator}:\n")
                    f.write(f"    Instance Type: {instance_info['instance_type']} | State: {instance_info['state']}\n")
                    
                    # Analyze each security group attached to this instance
                    open_ports_summary = []
                    iam_issues_summary = []
                    imds_issues_summary = []
                    
                    # IAM Instance Profile Analysis
                    instance_profile = instance_info['instance_profile']
                    if instance_profile['arn']:
                        f.write(f"    IAM Instance Profile: {instance_profile['arn']}\n")
                        if instance_profile['is_suspicious']:
                            f.write(f"        [SUSPICIOUS] IAM CONFIGURATION:\n")
                            for reason in instance_profile['trust_policy_reasons']:
                                f.write(f"            [ALERT] {reason}\n")
                                iam_issues_summary.append(reason)
                        else:
                            f.write(f"        [OK] IAM trust policy looks secure\n")
                        
                        if instance_profile['trust_policy_info']:
                            trust_info = instance_profile['trust_policy_info']
                            f.write(f"        Profile: {trust_info['profile_name']}\n")
                            for role in trust_info['roles']:
                                f.write(f"        Role: {role['role_name']}\n")
                    else:
                        f.write(f"    IAM Instance Profile: None attached\n")
                        iam_issues_summary.append("No IAM instance profile attached")
                    
                    # IMDS Configuration Analysis
                    imds_config = instance_info['imds']
                    f.write(f"    IMDS Configuration:\n")
                    if imds_config['is_suspicious']:
                        f.write(f"        [SUSPICIOUS] IMDS CONFIGURATION:\n")
                        for reason in imds_config['reasons']:
                            f.write(f"            [ALERT] {reason}\n")
                            imds_issues_summary.append(reason)
                    else:
                        f.write(f"        [OK] IMDS configuration looks secure\n")
                    
                    # Display IMDS details
                    imds_info = imds_config['configuration']
                    if 'error' not in imds_info:
                        f.write(f"        HTTP Tokens: {imds_info.get('http_tokens', 'N/A')}\n")
                        f.write(f"        Hop Limit: {imds_info.get('http_put_response_hop_limit', 'N/A')}\n")
                        f.write(f"        HTTP Endpoint: {imds_info.get('http_endpoint', 'N/A')}\n")
                        f.write(f"        Instance Metadata Tags: {imds_info.get('instance_metadata_tags', 'N/A')}\n")
                    else:
                        f.write(f"        [ERROR] Error reading IMDS config: {imds_info['error']}\n")
                    
                    f.write("\n")  # Add space before security groups
                    
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
                    f.write(f"\n    SECURITY SUMMARY for EC2 {instance_id} [{instance_info['name']}]:\n")
                    
                    # Network security summary
                    if open_ports_summary:
                        f.write(f"        Network Access - This instance has the following open ports:\n")
                        for i, port_info in enumerate(open_ports_summary, 1):
                            f.write(f"        {i}. {port_info}\n")
                    else:
                        f.write(f"        Network Access - No inbound rules found (or no security groups attached)\n")
                    
                    # IAM security summary
                    if iam_issues_summary:
                        f.write(f"        IAM Issues - This instance has the following IAM security concerns:\n")
                        for i, issue in enumerate(iam_issues_summary, 1):
                            f.write(f"        {i}. {issue}\n")
                    else:
                        f.write(f"        IAM Security - No IAM security issues detected\n")
                    
                    # IMDS security summary
                    if imds_issues_summary:
                        f.write(f"        IMDS Issues - This instance has the following IMDS security concerns:\n")
                        for i, issue in enumerate(imds_issues_summary, 1):
                            f.write(f"        {i}. {issue}\n")
                    else:
                        f.write(f"        IMDS Security - No IMDS security issues detected\n")
                    
                    f.write("\n" + "-" * 80 + "\n")
                
                
                if imds_issue_count == 0:
                    f.write("No IMDS configuration issues found!\n")
                
                # Overall security score
                f.write(f"\n4. OVERALL SECURITY ASSESSMENT\n")
                f.write("-" * 40 + "\n")
                
                total_instances = len(results['instances'])
                total_issues = sg_suspicious_count + iam_issue_count + imds_issue_count
                
                f.write(f"Total EC2 Instances Analyzed: {total_instances}\n")
                f.write(f"Total Security Issues Found: {total_issues}\n")
                f.write(f"  - Security Group Issues: {sg_suspicious_count}\n")
                f.write(f"  - IAM Profile Issues: {iam_issue_count}\n")
                f.write(f"  - IMDS Configuration Issues: {imds_issue_count}\n\n")
                
                if total_issues == 0:
                    f.write("🎉 EXCELLENT! No security issues found across all categories!\n")
                elif total_issues <= 3:
                    f.write("⚠️  GOOD - Only minor security issues found. Review and address when possible.\n")
                elif total_issues <= 10:
                    f.write("⚠️  MODERATE - Several security issues found. Recommended to address soon.\n")
                else:
                    f.write("🚨 HIGH RISK - Many security issues found. Immediate attention recommended!\n")
                
                # Recommendations
                f.write(f"\nRECOMMENDATIONS:\n")
                f.write("-" * 20 + "\n")
                
                if sg_suspicious_count > 0:
                    f.write("• Review and restrict overly permissive security group rules\n")
                    f.write("• Replace 0.0.0.0/0 access with specific IP ranges where possible\n")
                    f.write("• Use security groups references instead of CIDR blocks for internal access\n")
                
                if iam_issue_count > 0:
                    f.write("• Review IAM instance profile trust policies\n")
                    f.write("• Ensure only ec2.amazonaws.com can assume EC2 instance roles\n")
                    f.write("• Remove unnecessary cross-account or federated access\n")
                
                if imds_issue_count > 0:
                    f.write("• Enable IMDSv2 (set HttpTokens=required) on all instances\n")
                    f.write("• Set IMDS hop limit to 1 to prevent container/service metadata access\n")
                    f.write("• Consider disabling IMDS if not needed for your applications\n")
            
            print(f"📄 Text report saved to: {text_filename}")
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")

def main():
    """Main function to run the security analysis."""
    print("🚀 EC2 Comprehensive Security Analyzer")
    print("=" * 50)
    print("This tool analyzes:")
    print("• Security Groups and Network Rules")
    print("• IAM Instance Profile Trust Policies") 
    print("• IMDS (Instance Metadata Service) Configuration")
    print("=" * 50)
    
    # Get region from user
    region = input("Enter AWS region (default: il-central-1): ").strip()
    if not region:
        region = 'il-central-1'
    
    print(f"\n🌍 Starting analysis in region: {region}")
    print("⚠️  Note: This tool requires the following AWS permissions:")
    print("   • ec2:DescribeInstances")
    print("   • ec2:DescribeSecurityGroups") 
    print("   • iam:GetInstanceProfile")
    print("   • iam:GetRole")
    print()
    
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
        print("📊 Check the generated files for detailed reports")
        
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        print("\n🔧 Troubleshooting tips:")
        print("• Ensure AWS credentials are configured")
        print("• Verify you have the required IAM permissions")
        print("• Check if the specified region is correct")
        print("• Try running 'aws sts get-caller-identity' to test credentials")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
