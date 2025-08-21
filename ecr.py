import boto3
from botocore.exceptions import ClientError

def list_regions():
    """Get all AWS regions that support ECR"""
    ec2 = boto3.client("ec2")
    return [region["RegionName"] for region in ec2.describe_regions()["Regions"]]

def check_ecr_policies():
    """Iterate through all regions and ECR repos to check for policies"""
    results = {}

    for region in list_regions():
        print(f"\n🔎 Checking region: {region}")
        ecr = boto3.client("ecr", region_name=region)

        try:
            paginator = ecr.get_paginator("describe_repositories")
            for page in paginator.paginate():
                for repo in page["repositories"]:
                    repo_name = repo["repositoryName"]
                    arn = repo["repositoryArn"]

                    try:
                        policy = ecr.get_repository_policy(repositoryName=repo_name)
                        results[arn] = policy["policyText"]
                        print(f"✅ Policy found for {repo_name}")
                    except ClientError as e:
                        if e.response["Error"]["Code"] == "RepositoryPolicyNotFoundException":
                            results[arn] = None
                            print(f"❌ No policy for {repo_name}")
                        else:
                            print(f"⚠️ Error fetching policy for {repo_name}: {e}")
        except Exception as e:
            print(f"⚠️ Error in region {region}: {e}")

    return results


if __name__ == "__main__":
    policies = check_ecr_policies()

    print("\n====== SUMMARY ======")
    for repo_arn, policy in policies.items():
        if policy:
            print(f"{repo_arn}: HAS POLICY")
        else:
            print(f"{repo_arn}: NO POLICY")
