#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
from mitmproxy import ctx, http
import json
import requests
from requests import Response

class bilibili_rules:

    def __need_hijack(self, flow: http.HTTPFlow, filter_dict: dict):
        if flow.request.host not in filter_dict.keys():
            return False
        if 0 == len(list(filter(lambda p: flow.request.path.startswith(p), filter_dict[flow.request.host]))):
            return False
        return True

    def enable_download(self, flow: http.HTTPFlow):
        filter_dict = {
            "api.bilibili.com": [
                "/pgc/view/app/season"
            ]
        }

        if not self.__need_hijack(flow, filter_dict):
            return
        if "allow_download" not in flow.response.text:
            return
        jdata = json.loads(flow.response.text)
        jdata["result"]["rights"]["allow_download"] = 1
        flow.response.text = json.dumps(jdata)

    def __request_proxy(self, flow: http.HTTPFlow):
        func = {
            "GET": requests.get
        }.get(flow.request.method.upper())
        # TODO : 自动获取tw的开放代理
        proxies = {
            "https": "socks4://220.133.218.213:58340"
        }
        resp:Response = func(flow.request.url, headers=flow.request.headers, proxies=proxies)
        flow.response = http.HTTPResponse.make(status_code=int(resp.status_code), content=resp.content, headers=dict(resp.headers))

    def tw_only(self, flow: http.HTTPFlow):
        filter_dict = {
            "api.bilibili.com": [
                "/pgc/player/api/playurl",
                "/pgc/view/app/season"
            ],
            "bangumi.bilibili.com": [
                "/view/api/season",
            ]
        }

        if not self.__need_hijack(flow, filter_dict):
            return

        if 100 < len(flow.response.text):
            return
        jdata = json.loads(flow.response.text)
        if "success" == jdata["message"]:
            return
        self.__request_proxy(flow)

    def response(self, flow:http.HTTPFlow):
        if flow.do_not_inject:
            return
        if "bilibili.com" not in flow.request.host:
            return

        self.tw_only(flow)
        self.enable_download(flow)

    def requestheaders(self, flow:http.HTTPFlow):
        # TODO: mitmproxy采用的是预加载机制，比如下载flv超大文件，下载文件没下载完成前不会返回，只能一直卡在代理的内容加载上，目前没找到好的办法，先拦截已观测到的超大的flv文件下载，目前测试不影响客户端下载（不确定是否影响下载速度）
        flow.do_not_inject = False
        real_path = flow.request.path.split("?")[0]
        if real_path.startswith("/upgcxcode/") and real_path.endswith(".flv"):
            flow.do_not_inject = True
            flow.response = http.HTTPResponse.make(status_code=int(404), content="", headers=dict())


addons = [
    bilibili_rules(),
]
