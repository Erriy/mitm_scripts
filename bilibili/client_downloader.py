#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
from mitmproxy import ctx, http
import json


class rule_broker:

    def response(self, flow: http.HTTPFlow):
        if "/pgc/view/app/season" not in flow.request.path:
            return
        if "allow_download" not in flow.response.text:
            return
        jdata = json.loads(flow.response.text)
        jdata["result"]["rights"]["allow_download"] = 1
        flow.response.text = json.dumps(jdata)


addons = [
    rule_broker(),
]
