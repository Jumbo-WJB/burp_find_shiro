#coding:utf-8
#author:Jumbo
import re
from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue,ITab,ICookie

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("burp_find_shiro")
        print('burp_find_shiro')
        self._callbacks.registerScannerCheck(self)


    def doPassiveScan(self,messageInfo): # 被动检测
        # print('okkkkkkk')
        resquest = messageInfo.getRequest()
        httpService = messageInfo.getHttpService()
        protocol = httpService.getProtocol()
        port = httpService.getPort()
        host = httpService.getHost()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        analyzedRequest = self._helpers.analyzeRequest(resquest)
        request_header = analyzedRequest.getHeaders()
        reqParameters = analyzedRequest.getParameters()
        # print('11111')
        parameterDirect = []
        for parameter in reqParameters:
            # print(parameter.getType())
            if parameter.getType() == 2:
                parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
                # print('ok')
                # print(parameterName, parameterValue, parameterType)
                parameterDirect.append(['rememberMe', 'Jumbo',parameterType])
        for directPayload in parameterDirect:
            parameterName, parameterValue, parameterType = directPayload
        self.NewRquests(resquest, protocol, host, port, ishttps, parameterName, parameterValue, parameterType,messageInfo)
            



    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)  
        reqHeaders = analyzedRequest.getHeaders()  
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring() 
        reqMethod = analyzedRequest.getMethod()
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters

    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType



    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)
        resHeaders = analyzedResponse.getHeaders()
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()
        resStatusCode = analyzedResponse.getStatusCode()  
        rescookies = analyzedResponse.getCookies()
        return resHeaders, resBodys, resStatusCode,rescookies


    def NewRquests(self, resquest, protocol, host, port, ishttps, parameterName, parameterValue,
                           parameterType,messageInfo):
        resquest = messageInfo.getRequest() 
        analyzedRequest = self._helpers.analyzeRequest(resquest) 
        request_header = analyzedRequest.getHeaders()
        if not re.search("\/.*?\.js(\?|\s)",request_header[0])  and not re.search("\/.*?\.(css|jpg|png|mp4|avi|ico|gif|pdf|jpeg|bm4|mp3|rmvb|txt|html)",request_header[0]):
            try:
                # 构造参数
                newParameter = self._helpers.buildParameter(parameterName, parameterValue, parameterType)
                # 更新参数，并发送请求
                newRequest = self._helpers.updateParameter(resquest, newParameter)
                newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                    newRequest)

                # 新的响应
                newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                newResHeaders, newResBodys, newResStatusCode,rescookies = self.get_response_info(newResponse)
                # print(rescookies)
                for rescookie in rescookies:
                    cookieName = rescookie.getName()
                    cookieValue = rescookie.getValue()
                    print(cookieName,cookieValue)
                    if cookieName == 'rememberMe':
                        if cookieValue == 'deleteMe':
                            print('find shiro!')
                            httpService = messageInfo.getHttpService()
                            attack = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequest)
                            url = self._helpers.analyzeRequest(attack).getUrl()
                            issue=CustomScanIssue(httpService, url,
                                                                [attack],
                                                                'find shiro',
                                                                'find shiro',
                                                                'Certain', 'Low')
                            self._callbacks.addScanIssue(issue)
                            return True


                # print('okokokokokokokoko')
            except Exception, e:
                print(e)
                pass


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: " + name + " on " + str(url)+'\n'+"payload:"+detail
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService
