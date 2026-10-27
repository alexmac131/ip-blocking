# Optional AWS subnet blocking (no load balancer)

The AWS helper uses an existing Network ACL. NACLs apply to every resource in
all associated subnets, not just one EC2 instance, and are stateless.

## Requirements

- Bash, jq, AWS CLI v2, and AWS API connectivity.
- A configured profile/Region for the intended AWS account.
- IAM `ec2:DescribeNetworkAcls` and, for apply, `ec2:CreateNetworkAclEntry`.
- An existing VPC/subnet/ACL and an independent administrative recovery route.

No AWS calls are needed for the log tools or Nginx blocking.

## Setup

1. In EC2, note the instance's subnet. In VPC -> Network ACLs, find its associated
   ACL and inspect **all** subnet associations and existing inbound/outbound rules.
2. Verify actual source IPs, especially behind a CDN/proxy.
3. Inspect the currently approved rule quota in Service Quotas. The helper uses
   a maximum of 40 inbound entries, but does not check your approved quota;
   the default may be lower. Check current AWS documentation before requesting
   an increase: [VPC quotas](https://docs.aws.amazon.com/vpc/latest/userguide/amazon-vpc-limits.html#vpc-limits-nacls).
4. Populate `config/aws-nacl-blocked-ip-rules.json`. It is initially empty, and
   the helper refuses to run until it contains reviewed rules.
   Each rule must have a unique unused number evaluated before relevant allows:

   ```text
   RuleNumber: 1
   Protocol: "-1"
   RuleAction: "deny"
   Egress: false
   CidrBlock: a reviewed real IPv4 CIDR
   ```

   Add these fields as a JSON object in `Rules`. Do not copy documentation-only
   ranges `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24` as real bans.
5. Confirm account identity and Region:

   ```bash
   aws sts get-caller-identity
   aws configure get region
   ```

6. Preview with your real ACL ID:

   ```bash
   bash scripts/apply-aws-nacl-denies.sh acl-0123456789abcdef0
   ```

7. Review rule ordering, capacity, and affected subnets. Only then apply:

   ```bash
   bash scripts/apply-aws-nacl-denies.sh acl-0123456789abcdef0 --apply
   ```

Rules deny inbound traffic on all protocols/ports from listed sources. Preserve
existing outbound rules and necessary inbound permits. Entries are added one
at a time: an error can leave a partial update, with no automatic rollback.
Inspect before retrying.

Verify allowed traffic and the new entries in the console. To undo, remove only
the new numbered entries after checking their CIDRs. AWS rules are separate from
Nginx and Express; no automatic synchronization is provided.
