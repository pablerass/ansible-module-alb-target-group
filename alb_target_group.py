#!/usr/bin/python
# TODO: Add tagging support

DOCUMENTATION = '''
---
module: alb_target_group
short_description: create or delete a target group
description:
  - Creates or deletes target groups.
author:
    - "Pablo Munoz"
requirements: [ json, botocore, boto3 ]
options:
    state:
        description:
          - The desired state of the target group
        required: false
        default: present
        choices: ["present", "absent"]
    name:
        description:
          - The name of the target group
        required: true
    vpc_id:
        description:
          - The VPC ID for the VPC in which to create the target group
        required: false
    port:
        description:
          - The port of the target group
        required: false
    protocol:
        description:
          - The protocol of the target group
        required: false
        choices: ["HTTP", "HTTPS"]
    health_check_protocol:
        description:
          - The protocl of the target group health check
        required: false
        choices: ["HTTP", "HTTPS"]
    health_check_port:
        description:
          - The port of the target group health check
        required: false
    health_check_interval_seconds:
        description:
          - The interval in seconds of target group health checks
        required: false
    health_check_timeout_seconds:
        description:
          - The timeout in seconds of target group health check
        required: false
    healthy_threshold_count:
        description:
          - The healthy threshold of target group health check
        required: false
    unhealthy_threshold_count:
        description:
          - The unhealthy threshold of target group health check
        required: false
    health_check_path:
        description:
          - The path of target group health check
        required: false
    health_check_http_code:
        description:
          - The http code of target group health check
        required: false
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.
- alb_target_group:
    state: "present"
    name: "test-service"
    vpc_id: "vpc-abcdefgh"
    port: 80
    protocol: "HTTP"
# Simple example to delete
- alb_target_group:
    name: "test-service"
    vpc_id: "vpc-abcdefgh"
    state: "absent"
'''

RETURN = '''
target_group:
    description: Details of created or deleted target group.
    returned: when creating, deleting or modifying a target group
    type: complex
    contains:
        TargetGroupArn:
            description: The Amazon Resource Name (ARN) of the target group.
            returned: always
            type: string
        TargetGroupName:
            description: The name of the target group.
            returned: always
            type: string
        Protocol:
            description:
            returned: always
            type: string
        Port:
            description:
            returned: always
            type: int
        VpcID:
            description:
            returned: always
            type: string
        HealthCheckIntervalSeconds:
            description:
            returned: always
            type: int
        HealthCheckPath:
            description:
            returned: always
            type: string
        HealthCheckPort:
            description:
            returned: always
            type: string
        HealthCheckProtocol:
            description:
            returned: always
            type: string
        HealthCheckTimeoutSeconds:
            description:
            returned: always
            type: int
        HealthyThresholdCount:
            description:
            returned: always
            type: int
        UnhealthyThersholdCount:
            description:
            returned: always
            type: int
        Matcher:
            description:
            returned: always
            type: complex
            contains:
                HttpCode:
                    description:
                    returned: always
                    type: string
'''
try:
    import boto3
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info


class TargetGroupManager:
    """Handles TargetGroups"""

    def __init__(self, module):
        self.module = module

        try:
            region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
            if not region:
                module.fail_json(msg="Region must be specified as a parameter, in EC2_REGION or AWS_REGION environment variables or in boto configuration file")
            self.elbv2 = boto3_conn(module, conn_type='client', resource='elbv2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
        except boto.exception.NoAuthHandlerFound as e:
            self.module.fail_json(msg="Can't authorize connection - %s" % str(e))

    def find_in_array(self, array_of_target_groups, target_group_name, field_name='TargetGroupName'):
        for c in array_of_target_groups:
            if c[field_name].endswith(target_group_name):
                return c
        return None

    def describe_target_group(self, target_group_name):
        try:
            response = self.elbv2.describe_target_groups(
                Names=[target_group_name])
            if len(response['TargetGroups']) > 0:
                c = self.find_in_array(response['TargetGroups'], target_group_name)
                if c:
                    return c
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'TargetGroupNotFound':
                return None

        raise StandardError("Unknown problem describing target group %s." % target_group_name)

    def is_matching_target_group(self, expected, existing):
        if expected['name'] != existing['TargetGroupName']:
            return False

        # TODO: Refactor this, unmodifiable variables should not be checked also here
        if expected['vpc_id'] != existing['VpcId']:
            return False
        if expected['protocol'] != existing['Protocol']:
            return False
        if expected['port'] != existing['Port']:
            return False

        if expected['health_check_protocol'] and expected['health_check_protocol'] != existing['HealthCheckProtocol']:
            return False

        if expected['health_check_port'] and expected['health_check_port'] != existing['HealthCheckPort']:
            return False

        if expected['health_check_interval_seconds'] and expected['health_check_interval_seconds'] != existing['HealthCheckIntervalSeconds']:
            return False

        if expected['health_check_timeout_seconds'] and expected['health_check_timeout_seconds'] != existing['HealthCheckTimeoutSeconds']:
            return False

        if expected['healthy_threshold_count'] and expected['healthy_threshold_count'] != existing['HealthyThresholdCount']:
            return False

        if expected['unhealthy_threshold_count'] and expected['unhealthy_threshold_count'] != existing['UnhealthyThresholdCount']:
            return False

        if expected['health_check_path'] and expected['health_check_path'] != existing['HealthCheckPath']:
            return False

        if expected['health_check_http_code'] and expected['health_check_http_code'] != existing['Matcher']['HttpCode']:
            return False

        return True

    def create_target_group(self, **args):
        response = self.elbv2.create_target_group(**args)
        return self.jsonize(response['TargetGroups'][0])

    def modify_target_group(self, **args):
        response = self.elbv2.modify_target_group(**args)
        return self.jsonize(response['TargetGroups'][0])

    def jsonize(self, target_group):
        # some fields are datetime which is not JSON serializable
        # make them strings
        return target_group

    def delete_target_group(self, target_group_arn):
        return self.elbv2.delete_target_group(TargetGroupArn=target_group_arn)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(required=False, choices=['present', 'absent'], default='present'),
        name=dict(required=True, type='str'),
        vpc_id=dict(required=False, type='str'),
        protocol=dict(required=False, type='str', choices=['HTTP', 'HTTPS']),
        port=dict(required=False, type='int'),
        health_check_protocol=dict(required=False, type='str', choices=['HTTP', 'HTTPS']),
        health_check_port=dict(required=False, type='str'),
        health_check_interval_seconds=dict(required=False, type='int'),
        health_check_timeout_seconds=dict(required=False, type='int'),
        healthy_threshold_count=dict(required=False, type='int'),
        unhealthy_threshold_count=dict(required=False, type='int'),
        health_check_path=dict(required=False, type='str'),
        health_check_http_code=dict(required=False, type='str')
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required.')

    if module.params['state'] == 'present':
        if 'vpc_id' not in module.params and module.params['vpc_id'] is None:
            module.fail_json(msg="To use create a target group, a VPC id must be specified")
        if 'port' not in module.params and module.params['port'] is None:
            module.fail_json(msg="To use create a target group, a port must be specified")
        if 'protocol' not in module.params and module.params['protocol'] is None:
            module.fail_json(msg="To use create a target group, a protocol must be specified")

    target_group_mgr = TargetGroupManager(module)
    try:
        existing = target_group_mgr.describe_target_group(module.params['name'])
    except Exception as e:
        module.fail_json(msg="Exception describing target group '"+module.params['name']+"' in VPC '"+module.params['vpc_id']+"': "+str(e))

    results = dict(changed=False)
    if module.params['state'] == 'present':
        matching = False
        update = False
        if existing:
            if target_group_mgr.is_matching_target_group(module.params, existing):
                matching = True
                results['TargetGroup'] = target_group_mgr.jsonize(existing)
            else:
                update = True

        if not matching:
            if not module.check_mode:
                args = {}
                if module.params['health_check_protocol']:
                    args['HealthCheckProtocol'] = module.params['health_check_protocol']
                if module.params['health_check_port']:
                    args['HealthCheckPort'] = module.params['health_check_port']
                if module.params['health_check_interval_seconds']:
                    args['HealthCheckIntervalSeconds'] = module.params['health_check_interval_seconds']
                if module.params['health_check_timeout_seconds']:
                    args['HealthCheckTimeoutSeconds'] = module.params['health_check_timeout_seconds']
                if module.params['healthy_threshold_count']:
                    args['HealthtyThresholdCount'] = module.params['healthy_threshold_count']
                if module.params['unhealthy_threshold_count']:
                    args['UnhealthyThresholdCount'] = module.params['unhealthy_threshold_count']
                if module.params['health_check_path']:
                    args['HealthCheckPath'] = module.params['health_check_path']
                if module.params['health_check_http_code']:
                    args['Matcher'] = {'HttpCode': module.params['health_check_http_code']}

                if update:
                    if module.params['vpc_id'] != existing['VpcId']:
                        module.fail_json(msg="Vpc Id can not be modified for an existing target group '"+module.params['name']+"'")
                    if module.params['protocol'] != existing['Protocol']:
                        module.fail_json(msg="Protocol can not be modified for an existing target group '"+module.params['name']+"'")
                    if module.params['port'] != existing['Port']:
                        module.fail_json(msg="Port can not be modified for an existing target group '"+module.params['name']+"'")

                    args['TargetGroupArn'] = existing['TargetGroupArn']

                    # update required
                    response = target_group_mgr.modify_target_group(**args)
                else:
                    # doesn't exist. create it.
                    args.update({
                        'Name': module.params['name'],
                        'VpcId': module.params['vpc_id'],
                        'Protocol': module.params['protocol'],
                        'Port': module.params['port']
                    })
                    response = target_group_mgr.create_target_group(**args)

                results['target_group'] = response

            results['changed'] = True

    elif module.params['state'] == 'absent':
        if not existing:
            pass
        else:
            # it exists, so we should delete it and mark changed.
            # return info about the cluster deleted
            results['target_group'] = existing["TargetGroupNa,e
            if not module.check_mode:
                try:
                    target_group_mgr.delete_target_group(
                       existing['TargetGroupArn'])
                except botocore.exceptions.ClientError as e:
                    module.fail_json(msg=e.message)
            results['changed'] = True

    module.exit_json(**results)


if __name__ == '__main__':
    main()