#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
from mitmproxy import ctx, http
import json
import requests
from requests import Response


depid_response = dict()

def get_arg(url, name):
    from urllib import parse
    urldata = parse.unquote(url)
    result = parse.urlparse(urldata)
    query_dict = parse.parse_qs(result.query)
    return query_dict.get(name)


class bilibili_rules:


    def ip_handler(self, flow:http.HTTPFlow):
        flow.response.text = """{"code":0,"message":"0","ttl":1,"data":{"addr":"220.135.2.247","country":"台湾","province":"台北市","city":"","isp":"cht.com.tw"}}"""

    def tw_handler(self, flow:http.HTTPFlow):
        # ep_id = get_arg(flow.request.url, "ep_id")[0]
        # if ep_id in depid_response:
        #     flow.response.text = depid_response[ep_id]
        #     return
        proxies = {
            "https": "socks4://220.135.2.247:59171"
        }
        resp:Response = requests.get(flow.request.url, headers=flow.request.headers, proxies=proxies)
        flow.response.text = resp.text
        if "allow_download" in flow.response.text:
            jdata = json.loads(flow.response.text)
            jdata["result"]["rights"]["allow_download"] = 1
            flow.response.text = json.dumps(jdata)
        # depid_response[ep_id] = flow.response.text
        # print(flow.request.url)
        # print(flow.response.text)

    def check_host_urls(self, flow:http.HTTPFlow, host_suffix, *path_prefixes):
        if not flow.request.host.endswith(host_suffix):
            return False
        for pp in path_prefixes:
            if flow.request.path.startswith(pp):
                return True
        return False

    def response(self, flow:http.HTTPFlow):
        if flow.do_not_inject:
            return
        if "bilibili.com" not in flow.request.host:
            return
        # 开始处理
        if self.check_host_urls(flow, "app.bilibili.com", "/x/resource/ip"):
            self.ip_handler(flow)
        if self.check_host_urls(flow, "api.bilibili.com", "/pgc/view/app/season", "/pgc/player/api/playurl"):
            self.tw_handler(flow)

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
