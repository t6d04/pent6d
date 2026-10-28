---
name: ldap-xpath-injection
description: LDAP and XPath query-construction testing for authentication, search, and directory-backed APIs
---

# LDAP and XPath Injection

Directory and XML query injections occur when user input changes filter or
expression structure instead of remaining a bound value.

## Surface

- Login, user lookup, group search, directory sync, SSO mapping, and legacy
  XML-backed search endpoints.
- Attribute names, filters, wildcard handling, distinguished names, and
  XML/XPath predicates assembled from user-controlled values.

## Method

First identify the directory/XML technology and establish a benign baseline.
Use paired, minimal structural probes against an authorized test identity and
compare stable authorization or result-set behavior. Do not enumerate real
directory users or groups merely to increase impact. In source review, trace
input through escaping/binding APIs to the final query constructor.
