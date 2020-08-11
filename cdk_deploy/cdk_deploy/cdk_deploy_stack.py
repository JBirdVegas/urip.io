import os
import pathlib
import shutil
import subprocess

from aws_cdk import (core,
                     aws_ec2 as ec2,
                     aws_s3 as s3,
                     aws_lambda as lambda_,
                     aws_apigateway as apigateway,
                     aws_kms as kms,
                     aws_iam as iam,
                     aws_certificatemanager as cert_manager,
                     aws_route53 as route53,
                     aws_route53_targets as targets)

_domain_name = 'urip.io'
_cors_preflight = {
    "allow_origins": ["*"],
    "allow_methods": ["*"],
    "allow_headers": ['*'],
    "status_code": 204
}


class CdkDeployStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        key = kms.Key(self, 'key',
                      alias=f'{_domain_name.replace(".", "_")}-key',
                      description='Encryption key for urip.io apis')
        vpc = ec2.Vpc(self, 'vpc', vpn_gateway=True)
        bucket = s3.Bucket(self, "api_code_bucket",
                           block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                           encryption=s3.BucketEncryption.KMS,
                           encryption_key=key)

        principal = iam.CompositePrincipal(iam.ServicePrincipal("lambda.amazonaws.com"),
                                           iam.ServicePrincipal('apigateway.amazonaws.com'))
        role = iam.Role(self, 'role', assumed_by=principal)
        security_group = ec2.SecurityGroup(self, 'sg',
                                           allow_all_outbound=True,
                                           vpc=vpc)
        role.add_to_policy(iam.PolicyStatement(actions=[
            'ec2:CreateNetworkInterface',
            'ec2:DescribeNetworkInterfaces',
            'ec2:DeleteNetworkInterface',
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "lambda:InvokeFunction"
        ],
            effect=iam.Effect.ALLOW,
            resources=['*']))

        root = pathlib.Path(os.path.abspath(__file__)).parent.parent.parent
        code_path = os.path.join(root, 'lambda_handlers')
        deployment_path = os.path.abspath('deployment')
        if os.path.exists(deployment_path):
            print(f'Deployment path existed, deleting: {deployment_path}')
            shutil.rmtree(deployment_path, onerror=print)
        shutil.copytree(src=code_path, dst=deployment_path)
        subprocess.check_call(
            f"pip3 install -r {root}/runtime_requirements.txt -t {deployment_path} --upgrade".split()
        )

        env = {
            'BUCKET': bucket.bucket_name,
            'kms_key_id': key.key_arn,
            'geoip_user': 'AQICAHip0LWdHFaFMi3m/aW5g+UiX6bGO4oWVs8kmjO4Lm4ypAEY5MDXldEC7bW66NLbZmX/AAAAZDBiBgkqhkiG9w0BBwagVTBTAgEAME4GCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMjwzHQVbSiGybI79qAgEQgCHYl7RS1si2nupwIn3fTAzwUlHGuJeYauDikm+ybtYFqcA=',
            'geoip_pass': 'AQICAHip0LWdHFaFMi3m/aW5g+UiX6bGO4oWVs8kmjO4Lm4ypAEbJnXUG5oZx65f8IxVij9gAAAAbjBsBgkqhkiG9w0BBwagXzBdAgEAMFgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMOHSx+qkp2R+2J3KiAgEQgCvk6Xfz8cSGu8UxHVmxyHQugcQtk+8XnRj+ejFw/m3uZNo2NJzs85XyvrOR'
        }

        root_handler = self.make_lambda_function(
            handler='handlers.root_handler',
            code=lambda_.Code.asset(deployment_path),
            function_name='urip-io-root',
            env=env,
            security_group=security_group,
            role=role,
            vpc=vpc,
        )
        geo_handler = self.make_lambda_function(
            handler='handlers.geo_handler',
            code=lambda_.Code.asset(deployment_path),
            function_name='urip-io-geo',
            env=env,
            security_group=security_group,
            role=role,
            vpc=vpc,
        )
        api_handler = self.make_lambda_function(
            handler='handlers.api_handler',
            code=lambda_.Code.asset(deployment_path),
            function_name='urip-io-apis',
            env=env,
            security_group=security_group,
            role=role,
            vpc=vpc,
        )

        bucket.grant_read(root_handler)
        bucket.grant_read(geo_handler)
        bucket.grant_read(api_handler)

        zone = route53.HostedZone.from_hosted_zone_attributes(
            self, 'hosted_zone', hosted_zone_id='Z0514506V6L1TV8QIR10', zone_name=_domain_name)
        cert = cert_manager.DnsValidatedCertificate(
            self,
            'domain_cert',
            domain_name=_domain_name,
            hosted_zone=zone,
            validation_method=cert_manager.ValidationMethod.DNS)
        domain_name_options = apigateway.DomainNameOptions(certificate=cert,
                                                           domain_name=_domain_name,
                                                           security_policy=apigateway.SecurityPolicy.TLS_1_2)
        api = apigateway.RestApi(self, "restapi",
                                 rest_api_name='urip-io-apigateway',
                                 domain_name=domain_name_options,
                                 deploy=True,
                                 description="This service serves urip.io's apis")

        html_integration = apigateway.IntegrationResponse(
            status_code=str(200),
            response_templates={
                'text/html': '$input.body',
                'application/html': '$input("$")',
                'application/json': '$input("$")'
            })
        error_integration = apigateway.IntegrationResponse(
            status_code=str(500),
            response_templates={
                'text/html': '$input("$")',
                'application/html': '$input("$")',
                'application/json': '$input("$")',
                'application/xml': '$input("$")'
            })

        html_template = """
#set($inputRoot = $input.path('$'))
{
  "ip" : "$context.identity.sourceIp",
  "user_agent": "$context.identity.userAgent",
  "accept": "$input.params('accept')"
}"""
        root_integration = apigateway.LambdaIntegration(
            root_handler,
            allow_test_invoke=True,
            passthrough_behavior=apigateway.PassthroughBehavior.WHEN_NO_MATCH,
            integration_responses=[html_integration, error_integration],
            proxy=True,
            credentials_role=role,
            request_templates={
                'text/html': html_template
            }
        )

        geo_integration = apigateway.LambdaIntegration(geo_handler)
        api_integration = apigateway.LambdaIntegration(api_handler)

        geo_resource = api.root.add_resource('geo')
        json_resource = api.root.add_resource('json')
        xml_resource = api.root.add_resource('xml')
        csv_resource = api.root.add_resource('csv')

        api.root.add_method("GET", root_integration)
        geo_resource.add_method("GET", geo_integration)
        json_resource.add_method('GET', api_integration)
        xml_resource.add_method('GET', api_integration)
        csv_resource.add_method('GET', api_integration)

        # add cors
        api.root.add_cors_preflight(**_cors_preflight)
        geo_resource.add_cors_preflight(**_cors_preflight)
        json_resource.add_cors_preflight(**_cors_preflight)
        xml_resource.add_cors_preflight(**_cors_preflight)
        csv_resource.add_cors_preflight(**_cors_preflight)

        key.grant_encrypt_decrypt(role)
        key.grant_encrypt_decrypt(root_handler)
        key.grant_encrypt_decrypt(geo_handler)
        key.grant_encrypt_decrypt(api_handler)

        a_record = route53.ARecord(self,
                                   'arecord',
                                   target=route53.RecordTarget.from_alias(targets.ApiGatewayDomain(api.domain_name)),
                                   zone=zone,
                                   record_name=_domain_name)
        core.CfnOutput(self, 'kms_key_id', value=key.key_arn)
        core.CfnOutput(self, 'domain_name', value=a_record.domain_name)

    def make_lambda_function(self, handler, code, function_name, env, vpc, security_group, role):
        return lambda_.Function(self, id=function_name,
                                runtime=lambda_.Runtime.PYTHON_3_8,
                                function_name=function_name,
                                code=code,
                                handler=handler,
                                environment=env,
                                vpc=vpc,
                                security_group=security_group,
                                role=role)
