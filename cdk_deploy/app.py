#!/usr/bin/env python3

from aws_cdk import core

from cdk_deploy.cdk_deploy_stack import CdkDeployStack


def main():
    app = core.App()
    CdkDeployStack(app, "urip-stack")

    app.synth()


if __name__ == '__main__':
    main()
