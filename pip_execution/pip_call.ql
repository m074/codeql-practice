/**
 * @id py/pip_call
 * @name PIP call in code
 * @description Check if using process call to pip, commonly used by malicious packets like colorsapi  https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-pypi-packages/
 * @kind problem
 * @tags security
 */

 import python
 import semmle.python.dataflow.new.DataFlow
 import semmle.python.ApiGraphs


from DataFlow::CallCfgNode  call, StrConst c
where
  call = API::moduleImport("os").getMember("system").getACall()
  and c.getText().regexpMatch("pip install.*")
select c, "Pip call"


