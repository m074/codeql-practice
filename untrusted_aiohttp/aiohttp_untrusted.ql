/**
 * @id py/aiohttp
 * @name aiohttp insecured request
 * @description Check if the aiohttp session haces certificate validation disabled, insipired: https://github.com/github/codeql/blob/main/python/ql/src/Security/CWE-295/MissingHostKeyValidation.ql
 * @kind problem
 * @tags security
 *       external/cwe/cwe-295
 */

 import python
 import semmle.python.dataflow.new.DataFlow
 import semmle.python.ApiGraphs


from DataFlow::CallCfgNode  call, DataFlow::Node arg
where
  call = API::moduleImport("aiohttp").getMember("ClientSession").getACall() and
  arg = call.getArgByName("verify_ssl")
  
select call, "Verify SSL certificates"