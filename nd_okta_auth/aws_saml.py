# -*- coding: utf-8 -*-
#
# Credits: This code base was entirely stolen from
# https://github.com/ThoughtWorksInc/aws_role_credentials. It continues to be
# modified from the original code, but thanks a ton to the original writers at
# Thought Works Inc.

import base64
import xml.etree.ElementTree as ET


class SamlAssertion:

    def __init__(self, assertion):
        self.assertion = assertion

    @staticmethod
    def split_roles(roles):
        return [(y.strip())
                for y
                in roles.text.split(',')]

    @staticmethod
    def sort_roles(roles):
        return sorted(roles,
                      key=lambda role: 'saml-provider' in role)

    def roles(self):
        attributes = ET.fromstring(self.assertion).getiterator(
            '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute')

        name = 'https://aws.amazon.com/SAML/Attributes/Role'
        roles_attributes = [x for x
                            in attributes
                            if x.get('Name') == name]

        roles_values = [(x.getiterator(
            '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'))
                        for x
                        in roles_attributes]

        return [(dict(zip(['role', 'principle'],
                          self.sort_roles(self.split_roles(x)))))
                for x
                in roles_values[0]]

    def encode(self):
        return base64.b64encode(self.assertion).decode()
