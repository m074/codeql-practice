/**
 * @id py/aws_key
 * @name AWS expressions
 * @description Finds AWS id, inspired with the pattern in Trufflehog https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/aws.go
 * @kind problem
 */

 import python

 from StrConst c
 where (c.getText().regexpMatch("((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})")) 
 select c, "Potential AWS key hardcoded"