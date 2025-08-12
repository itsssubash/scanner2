import boto3
import datetime
import csv
import io
import json
from functools import partial

DEFAULT_AGE_DAYS = 90

def scan_s3_bucket_logging(s3_client):
    results = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            try:
                logging_status = s3_client.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' in logging_status:
                    results.append({"service": "S3", "resource": bucket_name, "status": "OK", "issue": "Server access logging is enabled."})
                else:
                    results.append({"service": "S3", "resource": bucket_name, "status": "CRITICAL", "issue": "Server access logging is not enabled.", "remediation": "Enable server access logging to record all requests made to your S3 bucket.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html"})
            except Exception:
                results.append({"service": "S3", "resource": bucket_name, "status": "CRITICAL", "issue": "Could not determine server access logging status.", "remediation": "Ensure your IAM user has `s3:GetBucketLogging` permissions for this bucket."})
    except Exception as e:
        results.append({"service": "S3", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan S3 buckets for logging status: {str(e)}"})
    return results

def scan_s3_buckets(s3_client):
    results = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']
            is_public = False
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                if not (pab.get('BlockPublicAcls') and pab.get('IgnorePublicAcls') and pab.get('BlockPublicPolicy') and pab.get('RestrictPublicBuckets')):
                    is_public = True
            except Exception:
                try:
                    policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                    if '"Principal":"*"' in policy.get('Policy', '') or '"Principal":{"AWS":"*"}' in policy.get('Policy', ''):
                        is_public = True
                except Exception:
                    pass
            result = {"service": "S3", "resource": bucket_name, "status": "CRITICAL" if is_public else "OK", "issue": "Bucket may be publicly accessible." if is_public else "Bucket is private."}
            if is_public:
                result["remediation"] = "Block all public access at the bucket level to prevent accidental data exposure."
                result["doc_url"] = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
            results.append(result)
    except Exception as e:
        results.append({"service": "S3", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan S3 buckets: {str(e)}"})
    return results

def scan_s3_versioning(s3_client):
    results = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get('Buckets', []):
            name = bucket['Name']
            try:
                v = s3_client.get_bucket_versioning(Bucket=name)
                if v.get('Status') == 'Enabled':
                    results.append({"service": "S3", "resource": name, "status": "OK", "issue": "Versioning is enabled."})
                else:
                    results.append({"service": "S3", "resource": name, "status": "WARNING", "issue": "Versioning is not enabled.", "remediation": "Enable S3 versioning to protect against accidental overwrites and deletions.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"})
            except Exception:
                results.append({"service": "S3", "resource": name, "status": "ERROR", "issue": "Could not determine versioning status."})
    except Exception as e:
        results.append({"service": "S3", "resource": "N/A", "status": "ERROR", "issue": f"Could not list buckets for versioning check: {str(e)}"})
    return results

def scan_s3_lifecycle(s3_client):
    results = []
    try:
        response = s3_client.list_buckets()
        for bucket in response.get('Buckets', []):
            name = bucket['Name']
            try:
                lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=name)
                rules = lifecycle.get('Rules', [])
                if rules:
                    results.append({"service": "S3", "resource": name, "status": "OK", "issue": "Bucket has lifecycle rules."})
                else:
                    results.append({"service": "S3", "resource": name, "status": "WARNING", "issue": "No lifecycle rules configured.", "remediation": "Create lifecycle rules to transition/delete objects and save cost.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html"})
            except s3_client.exceptions.NoSuchLifecycleConfiguration:
                results.append({"service": "S3", "resource": name, "status": "WARNING", "issue": "No lifecycle rules configured.", "remediation": "Create lifecycle rules to transition/delete objects and save cost.", "doc_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html"})
            except Exception:
                results.append({"service": "S3", "resource": name, "status": "ERROR", "issue": "Could not determine lifecycle configuration."})
    except Exception as e:
        results.append({"service": "S3", "resource": "N/A", "status": "ERROR", "issue": f"Could not list buckets for lifecycle check: {str(e)}"})
    return results

def scan_iam_root_mfa(iam_client):
    try:
        summary = iam_client.get_account_summary()
        mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0) == 1
        result = {"service": "IAM", "resource": "Root Account", "status": "OK" if mfa_enabled else "CRITICAL", "issue": "MFA is enabled for the root account." if mfa_enabled else "MFA is NOT enabled for the root account."}
        if not mfa_enabled:
            result["remediation"] = "Enable multi-factor authentication (MFA) for your root user to add an extra layer of protection to your AWS account."
            result["doc_url"] = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#root-user-mfa"
        return [result]
    except Exception as e:
        return [{"service": "IAM", "resource": "Root Account", "status": "ERROR", "issue": f"Could not check root account MFA status: {str(e)}"}]

# --- NEW SCANNER ---
def scan_iam_password_policy(iam_client):
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        weaknesses = []
        if not policy.get('RequireUppercaseCharacters'): weaknesses.append("no uppercase requirement")
        if not policy.get('RequireLowercaseCharacters'): weaknesses.append("no lowercase requirement")
        if not policy.get('RequireNumbers'): weaknesses.append("no number requirement")
        if not policy.get('RequireSymbols'): weaknesses.append("no symbol requirement")
        if policy.get('MinimumPasswordLength', 0) < 14: weaknesses.append("length less than 14")
        
        if weaknesses:
            issue = f"Password policy is weak: {', '.join(weaknesses)}."
            return [{"service": "IAM", "resource": "Account Password Policy", "status": "CRITICAL", "issue": issue, "remediation": "Enforce a stronger password policy for all IAM users.", "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"}]
        else:
            return [{"service": "IAM", "resource": "Account Password Policy", "status": "OK", "issue": "A strong password policy is enforced."}]
    except iam_client.exceptions.NoSuchEntityException:
        return [{"service": "IAM", "resource": "Account Password Policy", "status": "CRITICAL", "issue": "No password policy is set for the account.", "remediation": "Set an account password policy to enforce strong passwords for IAM users."}]
    except Exception as e:
        return [{"service": "IAM", "resource": "Account Password Policy", "status": "ERROR", "issue": f"Could not retrieve password policy: {str(e)}"}]

def scan_iam_overly_permissive_roles(iam_client):
    # ... (existing function is unchanged)
    results = []
    try:
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page.get('Roles', []):
                role_name = role['RoleName']
                is_admin = False
                try:
                    attached = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                    for p in attached:
                        if p.get('PolicyName') == 'AdministratorAccess' or p.get('PolicyArn', '').endswith(':AdministratorAccess'):
                            is_admin = True
                            break
                    if not is_admin:
                        inline = iam_client.list_role_policies(RoleName=role_name).get('PolicyNames', [])
                        for pname in inline:
                            doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=pname)['PolicyDocument']
                            doc_str = json.dumps(doc)
                            if ('"Action": "*"' in doc_str) or ('"Resource": "*"' in doc_str) or ("Action': '*'" in doc_str):
                                is_admin = True
                                break
                except Exception:
                    results.append({"service": "IAM", "resource": role_name, "status": "WARNING", "issue": "Could not fully inspect role policies. Manual review recommended."})
                    continue

                result = {"service": "IAM", "resource": role_name, "status": "CRITICAL" if is_admin else "OK", "issue": "Role has Administrator-like privileges." if is_admin else "Role appears scoped."}
                if is_admin:
                    result["remediation"] = "Review the role and apply the principle of least privilege; avoid attaching full AdministratorAccess where possible."
                    result["doc_url"] = "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                results.append(result)
    except Exception as e:
        results.append({"service": "IAM", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan IAM roles: {str(e)}"})
    return results

def scan_iam_users_and_keys(iam_client):
    # ... (existing function is unchanged)
    results = []
    try:
        try:
            iam_client.generate_credential_report()
        except Exception:
            pass
        report = iam_client.get_credential_report()
        content = report.get('Content')
        if content:
            csvfile = io.StringIO(content.decode('utf-8'))
            reader = csv.DictReader(csvfile)
            for row in reader:
                user = row.get('user')
                last_used_dates = []
                if row.get('password_last_used') and row.get('password_last_used') != 'N/A':
                    last_used_dates.append(row.get('password_last_used'))
                if row.get('access_key_1_last_used_date') and row.get('access_key_1_last_used_date') != 'N/A':
                    last_used_dates.append(row.get('access_key_1_last_used_date'))
                if row.get('access_key_2_last_used_date') and row.get('access_key_2_last_used_date') != 'N/A':
                    last_used_dates.append(row.get('access_key_2_last_used_date'))
                if last_used_dates:
                    most_recent = max(last_used_dates)
                    try:
                        dt = datetime.datetime.fromisoformat(most_recent.replace('Z', '+00:00'))
                        age_days = (datetime.datetime.now(datetime.timezone.utc) - dt).days
                        if age_days > DEFAULT_AGE_DAYS:
                            results.append({"service": "IAM", "resource": user, "status": "WARNING", "issue": f"User appears inactive for {age_days} days.", "remediation": "If user is inactive, consider deactivating credentials or removing the user."})
                        else:
                            results.append({"service": "IAM", "resource": user, "status": "OK", "issue": f"User active within {age_days} days."})
                    except Exception:
                        results.append({"service": "IAM", "resource": user, "status": "WARNING", "issue": "Could not parse last activity timestamp for user."})
                else:
                    results.append({"service": "IAM", "resource": user, "status": "WARNING", "issue": "No recorded activity for user. Manual review recommended.", "remediation": "Check console logins / access key usage and remove unused credentials."})
    except Exception as e:
        results.append({"service": "IAM", "resource": "N/A", "status": "ERROR", "issue": f"Could not generate/parse IAM credential report: {str(e)}"})
    return results

def scan_iam_users(iam_client):
    # ... (existing function is unchanged)
    results = []
    try:
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page.get('Users', []):
                username = user['UserName']
                try:
                    keys = iam_client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                    for key in keys:
                        key_id = key['AccessKeyId']
                        create_date = key['CreateDate']
                        age = (datetime.datetime.now(datetime.timezone.utc) - create_date).days
                        if age > DEFAULT_AGE_DAYS:
                            results.append({"service": "IAM", "resource": f"{username}/{key_id}", "status": "CRITICAL", "issue": f"Access key is older than {DEFAULT_AGE_DAYS} days ({age} days).", "remediation": "Rotate IAM user access keys every 90 days or less.", "doc_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#rotate-access-keys"})
                        else:
                            results.append({"service": "IAM", "resource": f"{username}/{key_id}", "status": "OK", "issue": f"Access key age: {age} days."})
                except Exception:
                    results.append({"service": "IAM", "resource": username, "status": "WARNING", "issue": "Could not inspect access keys for this user."})
    except Exception as e:
        results.append({"service": "IAM", "resource": "N/A", "status": "ERROR", "issue": f"Could not list IAM users for access key checks: {str(e)}"})
    return results

def scan_rds_encryption_and_public(rds_client):
    # ... (existing function is unchanged)
    results = []
    try:
        response = rds_client.describe_db_instances()
        if not response.get('DBInstances'):
            return [{"service": "RDS", "resource": "N/A", "status": "OK", "issue": "No RDS instances found."}]
        for db in response['DBInstances']:
            is_encrypted = db.get('StorageEncrypted', False)
            public = db.get('PubliclyAccessible', False)
            identifier = db.get('DBInstanceIdentifier')
            if is_encrypted:
                results.append({"service": "RDS", "resource": identifier, "status": "OK", "issue": "Database storage is encrypted."})
            else:
                results.append({"service": "RDS", "resource": identifier, "status": "CRITICAL", "issue": "Database storage is not encrypted.", "remediation": "Encrypt your RDS database instances at rest.", "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"})
            if public:
                results.append({"service": "RDS", "resource": identifier, "status": "CRITICAL", "issue": "RDS instance is publicly accessible.", "remediation": "Disable public accessibility unless required.", "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ConnectToInstance.html"})
            else:
                results.append({"service": "RDS", "resource": identifier, "status": "OK", "issue": "RDS instance is not publicly accessible."})
    except Exception as e:
        results.append({"service": "RDS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan RDS instances: {str(e)}"})
    return results

# --- NEW SCANNER ---
def scan_rds_backup_retention(rds_client):
    results = []
    try:
        response = rds_client.describe_db_instances()
        for db in response.get('DBInstances', []):
            identifier = db.get('DBInstanceIdentifier')
            retention_period = db.get('BackupRetentionPeriod', 0)
            if retention_period >= 7:
                results.append({"service": "RDS", "resource": identifier, "status": "OK", "issue": f"Automated backups enabled with {retention_period}-day retention."})
            elif 0 < retention_period < 7:
                results.append({"service": "RDS", "resource": identifier, "status": "WARNING", "issue": f"Backup retention period is only {retention_period} days.", "remediation": "Increase the backup retention period to 7 days or more for better data recovery options."})
            else:
                results.append({"service": "RDS", "resource": identifier, "status": "CRITICAL", "issue": "Automated backups are disabled.", "remediation": "Enable automated backups for your RDS instances to ensure point-in-time recovery.", "doc_url": "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"})
    except Exception as e:
        results.append({"service": "RDS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan RDS backup retention: {str(e)}"})
    return results

def scan_ebs_encryption(ec2_client):
    # ... (existing function is unchanged)
    results = []
    try:
        instances_response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping', 'pending']}])
        volume_ids = [device['Ebs']['VolumeId'] for res in instances_response.get('Reservations', []) for inst in res.get('Instances', []) for device in inst.get('BlockDeviceMappings', []) if 'Ebs' in device]
        if not volume_ids:
            return [{"service": "EBS", "resource": "N/A", "status": "OK", "issue": "No attached EBS volumes found."}]
        volumes_response = ec2_client.describe_volumes(VolumeIds=list(set(volume_ids)))
        for volume in volumes_response.get('Volumes', []):
            is_encrypted = volume.get('Encrypted', False)
            result = {"service": "EBS", "resource": volume['VolumeId'], "status": "OK" if is_encrypted else "CRITICAL", "issue": "EBS volume is encrypted." if is_encrypted else "EBS volume is not encrypted."}
            if not is_encrypted:
                result["remediation"] = "Encrypt your EBS volumes to protect the data at rest on your EC2 instances."
                result["doc_url"] = "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html"
            results.append(result)
    except Exception as e:
        results.append({"service": "EBS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan EBS volumes: {str(e)}"})
    return results

def scan_ebs_snapshot_public(ec2_client):
    # ... (existing function is unchanged)
    results = []
    try:
        snaps = ec2_client.describe_snapshots(OwnerIds=['self']).get('Snapshots', [])
        if not snaps:
            return [{"service": "EBS Snapshot", "resource": "N/A", "status": "OK", "issue": "No owned snapshots found."}]
        for s in snaps:
            sid = s['SnapshotId']
            try:
                attr = ec2_client.describe_snapshot_attribute(SnapshotId=sid, Attribute='createVolumePermission')
                perms = attr.get('CreateVolumePermissions', [])
                if any(p.get('Group') == 'all' for p in perms):
                    results.append({"service": "EBS Snapshot", "resource": sid, "status": "CRITICAL", "issue": "Snapshot is publicly shared.", "remediation": "Remove public createVolumePermission on snapshot.", "doc_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html"})
                else:
                    results.append({"service": "EBS Snapshot", "resource": sid, "status": "OK", "issue": "Snapshot is not publicly shared."})
            except Exception:
                results.append({"service": "EBS Snapshot", "resource": sid, "status": "WARNING", "issue": "Could not determine snapshot permissions."})
    except Exception as e:
        results.append({"service": "EBS Snapshot", "resource": "N/A", "status": "ERROR", "issue": f"Could not list snapshots: {str(e)}"})
    return results

# --- NEW SCANNER ---
def scan_orphaned_ebs_volumes(ec2_client):
    results = []
    try:
        orphaned_volumes = ec2_client.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}]).get('Volumes', [])
        if not orphaned_volumes:
            return [{"service": "EC2/EBS", "resource": "N/A", "status": "OK", "issue": "No orphaned (unattached) EBS volumes found."}]
        for vol in orphaned_volumes:
            results.append({"service": "EC2/EBS", "resource": vol['VolumeId'], "status": "WARNING", "issue": "EBS volume is unattached (orphaned).", "remediation": "Review unattached EBS volumes. Delete them if they are no longer needed to reduce costs."})
    except Exception as e:
        results.append({"service": "EC2/EBS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan for orphaned EBS volumes: {str(e)}"})
    return results

# --- NEW SCANNER ---
def scan_unassociated_elastic_ips(ec2_client):
    results = []
    try:
        addresses = ec2_client.describe_addresses().get('Addresses', [])
        unassociated_ips = [addr for addr in addresses if 'AssociationId' not in addr]
        if not unassociated_ips:
            return [{"service": "EC2/VPC", "resource": "N/A", "status": "OK", "issue": "No unassociated Elastic IPs found."}]
        for ip in unassociated_ips:
            results.append({"service": "EC2/VPC", "resource": ip['PublicIp'], "status": "WARNING", "issue": "Elastic IP is not associated with an instance.", "remediation": "Disassociate and release unused Elastic IPs to reduce costs."})
    except Exception as e:
        results.append({"service": "EC2/VPC", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan for unassociated Elastic IPs: {str(e)}"})
    return results

def scan_ec2_public_access(ec2_client):
    # ... (existing function is unchanged)
    results = []
    try:
        response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'stopping', 'pending']}])
        if not any(res.get('Instances') for res in response.get('Reservations', [])):
            return [{"service": "EC2", "resource": "N/A", "status": "OK", "issue": "No EC2 instances found."}]
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                is_public = False
                reasons = []
                for sg in instance.get('SecurityGroups', []):
                    try:
                        sg_response = ec2_client.describe_security_groups(GroupIds=[sg['GroupId']])
                        perms = sg_response['SecurityGroups'][0].get('IpPermissions', [])
                        for ip_permission in perms:
                            for ip_range in ip_permission.get('IpRanges', []):
                                cidr = ip_range.get('CidrIp')
                                if cidr == '0.0.0.0/0':
                                    from_p = ip_permission.get('FromPort')
                                    to_p = ip_permission.get('ToPort')
                                    if from_p is None:
                                        port_descr = "all ports"
                                    elif from_p == to_p:
                                        port_descr = f"port {from_p}"
                                    else:
                                        port_descr = f"ports {from_p}-{to_p}"
                                    reasons.append(f"SG {sg['GroupId']} allows {port_descr} from 0.0.0.0/0")
                                    if (from_p in (22, 3389)) or (to_p in (22, 3389)) or (from_p is None):
                                        is_public = True
                    except Exception:
                        reasons.append(f"Could not inspect security group {sg.get('GroupId')}")
                result = {"service": "EC2", "resource": instance['InstanceId'], "status": "CRITICAL" if is_public else ("WARNING" if reasons else "OK"), "issue": ", ".join(reasons) if reasons else "Instance security groups are private or non-public."}
                if is_public or reasons:
                    result["remediation"] = "Avoid security group rules that allow unrestricted inbound traffic (0.0.0.0/0)."
                    result["doc_url"] = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"
                results.append(result)
    except Exception as e:
        results.append({"service": "EC2", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan EC2 instances: {str(e)}"})
    return results

def scan_security_groups(ec2_client):
    # ... (existing function is unchanged)
    results = []
    try:
        sgs = ec2_client.describe_security_groups().get('SecurityGroups', [])
        for sg in sgs:
            sgid = sg['GroupId']
            too_open = False
            notes = []
            for perm in sg.get('IpPermissions', []):
                for ip_range in perm.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        too_open = True
                        fp = perm.get('FromPort')
                        tp = perm.get('ToPort')
                        if fp is None:
                            notes.append("Allows all ports from 0.0.0.0/0")
                        else:
                            notes.append(f"Allows ports {fp}-{tp} from 0.0.0.0/0")
            status = "CRITICAL" if too_open else "OK"
            results.append({"service": "VPC", "resource": sgid, "status": status, "issue": "; ".join(notes) if notes else "No overly permissive rules found."})
            if too_open:
                results[-1]["remediation"] = "Tighten security group ingress rules to limit sources and ports."
    except Exception as e:
        results.append({"service": "VPC", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan security groups: {str(e)}"})
    return results

def scan_lambda_permissions(iam_client, lambda_client):
    # ... (existing function is unchanged)
    results = []
    try:
        functions = lambda_client.list_functions().get('Functions', [])
        if not functions:
            return [{"service": "Lambda", "resource": "N/A", "status": "OK", "issue": "No Lambda functions found."}]
        for func in functions:
            role_arn = func.get('Role')
            if not role_arn:
                results.append({"service": "Lambda", "resource": func.get('FunctionName'), "status": "WARNING", "issue": "Lambda has no attached execution role."})
                continue
            role_name = role_arn.split('/')[-1]
            try:
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                is_admin = any(p['PolicyArn'].endswith(':AdministratorAccess') or p['PolicyName'] == 'AdministratorAccess' for p in attached_policies)
                result = {"service": "Lambda", "resource": func.get('FunctionName'), "status": "CRITICAL" if is_admin else "OK", "issue": "Function has 'AdministratorAccess' role." if is_admin else "Function has a scoped execution role."}
                if is_admin:
                    result["remediation"] = "Follow the principle of least privilege for Lambda execution roles."
                    result["doc_url"] = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html"
                results.append(result)
            except Exception:
                results.append({"service": "Lambda", "resource": func.get('FunctionName'), "status": "WARNING", "issue": "Could not inspect Lambda execution role policies."})
    except Exception as e:
        results.append({"service": "Lambda", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan Lambda functions: {str(e)}"})
    return results

def scan_ecs_task_role_admin(iam_client, ecs_client):
    # ... (existing function is unchanged)
    results = []
    try:
        clusters = ecs_client.list_clusters().get('clusterArns', [])
        if not clusters:
            return [{"service": "ECS", "resource": "N/A", "status": "OK", "issue": "No ECS clusters found."}]
        for cluster in clusters:
            tasks = ecs_client.list_tasks(cluster=cluster).get('taskArns', [])
            if not tasks:
                continue
            described = ecs_client.describe_tasks(cluster=cluster, tasks=tasks).get('tasks', [])
            for t in described:
                td_arn = t.get('taskDefinitionArn')
                if not td_arn:
                    continue
                td = ecs_client.describe_task_definition(taskDefinition=td_arn).get('taskDefinition', {})
                task_role = td.get('taskRoleArn')
                if not task_role:
                    results.append({"service": "ECS", "resource": td_arn, "status": "WARNING", "issue": "Task definition has no taskRoleArn."})
                    continue
                role_name = task_role.split('/')[-1]
                try:
                    attached = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
                    is_admin = any(p['PolicyArn'].endswith(':AdministratorAccess') or p['PolicyName'] == 'AdministratorAccess' for p in attached)
                    res = {"service": "ECS", "resource": role_name, "status": "CRITICAL" if is_admin else "OK", "issue": "ECS task role has Administrator access." if is_admin else "ECS task role appears scoped."}
                    if is_admin:
                        res["remediation"] = "Reduce ECS task role privileges and follow least privilege."
                        res["doc_url"] = "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
                    results.append(res)
                except Exception:
                    results.append({"service": "ECS", "resource": role_name, "status": "WARNING", "issue": "Could not inspect ECS task role policies."})
    except Exception as e:
        results.append({"service": "ECS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan ECS tasks: {str(e)}"})
    return results

def scan_cloudtrail_logs(cloudtrail_client):
    # ... (existing function is unchanged)
    results = []
    try:
        response = cloudtrail_client.describe_trails()
        is_enabled = any(trail.get('IsMultiRegionTrail', False) and trail.get('IsLogging', False) for trail in response.get('trailList', []))
        result = {"service": "CloudTrail", "resource": "All Regions", "status": "OK" if is_enabled else "CRITICAL", "issue": "A multi-region CloudTrail is enabled." if is_enabled else "A multi-region CloudTrail is not enabled."}
        if not is_enabled:
            result["remediation"] = "Ensure at least one CloudTrail trail is enabled for all regions."
            result["doc_url"] = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-a-trail-for-all-regions.html"
        results.append(result)
    except Exception as e:
        results.append({"service": "CloudTrail", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan CloudTrail: {str(e)}"})
    return results

# --- NEW SCANNER ---
def scan_cloudtrail_log_file_validation(cloudtrail_client):
    results = []
    try:
        trails = cloudtrail_client.describe_trails().get('trailList', [])
        if not trails:
            return [{"service": "CloudTrail", "resource": "N/A", "status": "OK", "issue": "No CloudTrail trails found."}]
        for trail in trails:
            if trail.get('LogFileValidationEnabled'):
                results.append({"service": "CloudTrail", "resource": trail['Name'], "status": "OK", "issue": "Log file integrity validation is enabled."})
            else:
                results.append({"service": "CloudTrail", "resource": trail['Name'], "status": "CRITICAL", "issue": "Log file integrity validation is disabled.", "remediation": "Enable log file validation to ensure CloudTrail logs are not tampered with.", "doc_url": "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-enabling.html"})
    except Exception as e:
        results.append({"service": "CloudTrail", "resource": "N/A", "status": "ERROR", "issue": f"Could not check CloudTrail log file validation: {str(e)}"})
    return results

def scan_guardduty_status(guardduty_client):
    # ... (existing function is unchanged)
    results = []
    try:
        detectors = guardduty_client.list_detectors().get('DetectorIds', [])
        if detectors:
            results.append({"service": "GuardDuty", "resource": "Region", "status": "OK", "issue": "GuardDuty detector(s) active."})
        else:
            results.append({"service": "GuardDuty", "resource": "Region", "status": "CRITICAL", "issue": "GuardDuty is not enabled in this region.", "remediation": "Enable GuardDuty for threat detection.", "doc_url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_setup.html"})
    except Exception as e:
        results.append({"service": "GuardDuty", "resource": "N/A", "status": "ERROR", "issue": f"Could not query GuardDuty: {str(e)}"})
    return results

# --- NEW SCANNER ---
def scan_config_status(config_client):
    results = []
    try:
        status = config_client.describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])
        if not status:
            results.append({"service": "AWS Config", "resource": "Region", "status": "CRITICAL", "issue": "AWS Config is not enabled in this region.", "remediation": "Enable AWS Config to record and evaluate the configurations of your AWS resources.", "doc_url": "https://docs.aws.amazon.com/config/latest/developerguide/setting-up-aws-config.html"})
        elif not status[0].get('recording', False):
            results.append({"service": "AWS Config", "resource": "Region", "status": "CRITICAL", "issue": "AWS Config recorder is currently stopped.", "remediation": "Start the AWS Config recorder to resume configuration tracking."})
        else:
            results.append({"service": "AWS Config", "resource": "Region", "status": "OK", "issue": "AWS Config is enabled and recording."})
    except Exception as e:
        results.append({"service": "AWS Config", "resource": "N/A", "status": "ERROR", "issue": f"Could not check AWS Config status: {str(e)}"})
    return results

def scan_secrets_manager(secrets_client):
    # ... (existing function is unchanged)
    results = []
    try:
        secrets = secrets_client.list_secrets().get('SecretList', [])
        if not secrets:
            return [{"service": "SecretsManager", "resource": "N/A", "status": "OK", "issue": "No secrets found."}]
        for s in secrets:
            name = s.get('Name')
            try:
                val = secrets_client.get_secret_value(SecretId=name)
                if 'SecretString' in val and val['SecretString']:
                    results.append({"service": "SecretsManager", "resource": name, "status": "WARNING", "issue": "Secret contains a SecretString (may contain plaintext). Manual review recommended.", "remediation": "Ensure secrets are stored correctly and rotated."})
                else:
                    results.append({"service": "SecretsManager", "resource": name, "status": "OK", "issue": "Secret stored as binary or not exposed as a string."})
            except Exception:
                results.append({"service": "SecretsManager", "resource": name, "status": "WARNING", "issue": "Could not retrieve secret value (insufficient permissions)."})
    except Exception as e:
        results.append({"service": "SecretsManager", "resource": "N/A", "status": "ERROR", "issue": f"Could not list secrets: {str(e)}"})
    return results

def scan_ssm_parameters(ssm_client):
    # ... (existing function is unchanged)
    results = []
    try:
        paginator = ssm_client.get_paginator('describe_parameters')
        for page in paginator.paginate():
            for p in page.get('Parameters', []):
                name = p.get('Name')
                ptype = p.get('Type')
                if ptype and ptype.lower() == 'string':
                    results.append({"service": "SSM", "resource": name, "status": "WARNING", "issue": "Parameter is stored as String (potential plaintext).", "remediation": "Use SecureString with KMS to encrypt sensitive parameters.", "doc_url": "https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-security.html"})
                else:
                    results.append({"service": "SSM", "resource": name, "status": "OK", "issue": f"Parameter type: {ptype}"})
    except Exception as e:
        results.append({"service": "SSM", "resource": "N/A", "status": "ERROR", "issue": f"Could not list SSM parameters: {str(e)}"})
    return results

def get_all_scan_functions(aws_access_key_id, aws_secret_access_key):
    """
    Prepares and returns a list of all scan functions ready to be executed.
    """
    functions_to_run = []
    
    session = boto3.Session(aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
    iam_client = session.client('iam')
    s3_client = session.client('s3')
    cloudtrail_client = session.client('cloudtrail', region_name='us-east-1')

    # --- ADD GLOBAL SCANS (including new ones) ---
    functions_to_run.extend([
        ("IAM Root MFA", partial(scan_iam_root_mfa, iam_client)),
        ("IAM Password Policy", partial(scan_iam_password_policy, iam_client)),
        ("IAM Overly Permissive Roles", partial(scan_iam_overly_permissive_roles, iam_client)),
        ("IAM User Activity (Credential Report)", partial(scan_iam_users_and_keys, iam_client)),
        ("IAM Access Key Age", partial(scan_iam_users, iam_client)),
        ("S3 Public Buckets", partial(scan_s3_buckets, s3_client)),
        ("S3 Bucket Logging", partial(scan_s3_bucket_logging, s3_client)),
        ("S3 Versioning", partial(scan_s3_versioning, s3_client)),
        ("S3 Lifecycle Policies", partial(scan_s3_lifecycle, s3_client)),
        ("CloudTrail Multi-Region Logging", partial(scan_cloudtrail_logs, cloudtrail_client)),
        ("CloudTrail Log File Validation", partial(scan_cloudtrail_log_file_validation, cloudtrail_client)),
    ])

    # --- PREPARE REGIONAL SCANS (including new ones) ---
    try:
        ec2_global_client = session.client('ec2', region_name='us-east-1')
        regions = [r['RegionName'] for r in ec2_global_client.describe_regions(AllRegions=False).get('Regions', [])]
    except Exception as e:
        print(f"Could not list regions, defaulting to us-east-1. Error: {e}")
        regions = ['us-east-1']

    for region in regions:
        try:
            ec2_client = session.client('ec2', region_name=region)
            rds_client = session.client('rds', region_name=region)
            lambda_client = session.client('lambda', region_name=region)
            ecs_client = session.client('ecs', region_name=region)
            guardduty_client = session.client('guardduty', region_name=region)
            secrets_client = session.client('secretsmanager', region_name=region)
            ssm_client = session.client('ssm', region_name=region)
            config_client = session.client('config', region_name=region)
            
            functions_to_run.extend([
                (f"[{region}] EBS Encryption", partial(scan_ebs_encryption, ec2_client)),
                (f"[{region}] EBS Public Snapshots", partial(scan_ebs_snapshot_public, ec2_client)),
                (f"[{region}] EC2 Public Access", partial(scan_ec2_public_access, ec2_client)),
                (f"[{region}] VPC Security Groups", partial(scan_security_groups, ec2_client)),
                (f"[{region}] RDS Public & Encrypted", partial(scan_rds_encryption_and_public, rds_client)),
                (f"[{region}] RDS Backup Retention", partial(scan_rds_backup_retention, rds_client)),
                (f"[{region}] Lambda Permissions", partial(scan_lambda_permissions, iam_client, lambda_client)),
                (f"[{region}] ECS Task Permissions", partial(scan_ecs_task_role_admin, iam_client, ecs_client)),
                (f"[{region}] GuardDuty Status", partial(scan_guardduty_status, guardduty_client)),
                (f"[{region}] AWS Config Status", partial(scan_config_status, config_client)),
                (f"[{region}] Secrets Manager Plaintext", partial(scan_secrets_manager, secrets_client)),
                (f"[{region}] SSM Parameter Plaintext", partial(scan_ssm_parameters, ssm_client)),
                (f"[{region}] Orphaned EBS Volumes", partial(scan_orphaned_ebs_volumes, ec2_client)),
                (f"[{region}] Unassociated Elastic IPs", partial(scan_unassociated_elastic_ips, ec2_client)),
            ])
        except Exception as e:
            print(f"Could not initialize clients or add scans for region {region}. Error: {e}")

    return functions_to_run