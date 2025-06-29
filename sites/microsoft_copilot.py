from proxy import Site, EmailNotFoundException, decode_jwt, pad_b64
from mitmproxy import http, ctx
from mitmproxy.http import Response

import json
import base64
import uuid
import re
import os
import gzip
from io import BytesIO

class Microsoft_Copilot(Site):

    def __init__(self, name, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback):
        super().__init__(name, urls, account_login_callback, account_check_callback, conversation_callback, attached_file_callback)
        self.uploaded_files = {}
        
    def on_request_handle(self, flow):
        
        if flow.request.method == "PUT" and "sharepoint.com/personal" in flow.request.pretty_url and "uploadSession" in flow.request.pretty_url:
            
            user_email = None

            tempauth = flow.request.query.get("tempauth")
            if tempauth.startswith("v1."):
                #tempauth = tempauth[3:]
                tempauth = tempauth.removeprefix("v1.")
                #ctx.log.info(f"Tempauth extracted: {tempauth}")
                

                decoded = decode_special_microsoft_token(tempauth)

                if not decoded:
                    ctx.log.error("Failed to decode tempauth token")
                    return

                if "app_displayname" in decoded['header'] and decoded['header']["app_displayname"] == "M365ChatClient" and 'Emails' in decoded['payload_strings'] and len(decoded['payload_strings']['Emails']) > 0:
                    emails = decoded['payload_strings']['Emails']

                    for email in emails:
                        if not 'live.comz' in email:
                            ctx.log.info(f"Email extracted from tempauth: {email}")
                            user_email = email
                            break
                    

            if not user_email or not self.account_check_callback(user_email):

                flow.response = Response.make(
                    403,
                    b"Blocked by proxy",  # Body
                    {"Content-Type": "text/plain"}  # Headers
                )

                return

            content_type = flow.request.headers.get("Content-Type", "")
            
            if "application/octet-stream" in content_type:
                unique_id = uuid.uuid4().hex

                filename = f"{unique_id}"

                filepath = os.path.join("/uploads", filename)

                with open(filepath, "wb") as f:
                    f.write(flow.request.raw_content)

                if user_email in self.uploaded_files:

                    self.attached_file_callback(user_email, self.uploaded_files[email]['filename'], filepath, self.uploaded_files[email]['filetype'])
                    del self.uploaded_files[email]


                #ctx.log.info(f"Decoded tempauth: {json.dumps(tempauth, indent=2)}")

        """
        if flow.request.method == "GET" and "graph.microsoft.com/v1.0/me/drive/special/copilotuploads:" in flow.request.pretty_url:
            
            auth_header = flow.request.headers.get("authorization")

            if auth_header.startswith("Bearer "):
            
                jwt_token = auth_header[len("Bearer "):].strip()

                email = get_email_from_auth_header(jwt_token)
                #ctx.log.info(f"JWT Token extracted: {jwt_token}")

                ctx.log.info(f"GET EMAIL: {email}")

                match = re.search(r'[^/]+$', flow.request.pretty_url)

                if match:
                    filename = match.group()

                    ctx.log.info(f"Filename: {filename}")

                    #self.uploaded_files[email] = {"filename": filename}
        """

    def on_response_handle(self, flow):

        #ctx.log.info(f"On response handle for {flow.request.pretty_url}")

        if flow.request.method == "GET" and "graph.microsoft.com/v1.0/me/drive/special/copilotuploads:" in flow.request.pretty_url:
            
            content_type = flow.response.headers.get("Content-Type", "")

            #ctx.log.info(f"Content-Type: {content_type}")

            #ctx.log.info(f"Response : {flow.response.content}")

            if "application/json" in content_type.lower():

                try:

                    # Try to parse as JSON
                    content = json.loads(flow.response.content.decode('utf-8'))
                    #ctx.log.info("Parsed JSON Response:")
                    #ctx.log.info(json.dumps(content, indent=2))  # pretty-print

                    email = content['lastModifiedBy']['user']['email']
                    filename = content['name']
                    file_type = content['file']['mimeType']

                    #ctx.log.info(f"Email: {email}, Filename: {filename}, File Type: {file_type}")

                    self.uploaded_files[email] = {"filename": filename, "filetype": file_type}

                except Exception as e:
                    ctx.log.error(f"[Error] Failed to decompress or parse JSON: {e}")
          

    def on_ws_from_client_to_server(self, flow, message):
        if flow.request.method == "GET" and "substrate.office.com/m365Copilot/Chathub" in flow.request.pretty_url:
            #ctx.log.info(f"\n[WS Message from Client to Server]")
            #ctx.log.info(f"URL: {flow.request.pretty_url}")
            #ctx.log.info(f"Message: {message.content}")

            auth_query_param = flow.request.query.get("access_token", "")
            #ctx.log.info(f"auth_header: {auth_header}")

            try :
                email = get_email_from_auth_header(auth_query_param)

                if self.account_check_callback(email):
                    ctx.log.info(f"Email address belongs to the organization")

                    message_contents = message.content.split(b'\x1e')

                    message_contents = [part for part in message_contents if part]

                    json_messages = [json.loads(part.decode('utf-8')) for part in message_contents]

                    for json_content in json_messages:
                        #ctx.log.info(f"JSON Content: {json.dumps(json_content, indent=2)}")
                    
                        if "arguments" in json_content:
                            for argument in json_content["arguments"]:
                                if "message" in argument and "text" in argument["message"]:
                                    conversation_text = argument["message"]["text"]
                                    #ctx.log.info(f'Conversation: {conversation_text}')
                                    self.conversation_callback(email, conversation_text)

                    return
                
            except EmailNotFoundException as e:
                ctx.log.error(f"Email not properly decoded: {e}")

            ctx.log.info("JWT token checks failed!")
            # Prevent the message from being sent to the server
            message.kill()
            # Optionally, you can send a close frame to the client
            #flow.websocket.close(403, reason="Blocked by proxy")

def get_email_from_auth_header(auth_query_param):
    
    if auth_query_param:
            
        jwt_token = auth_query_param.strip()
        #ctx.log.info(f"JWT Token extracted: {jwt_token}")

        jwt_data = decode_jwt(jwt_token)

        if jwt_data:
            #ctx.log.info(f"JWT Header: {json.dumps(jwt_data['header'], indent=2)}")
            #ctx.log.info(f"JWT Payload: {json.dumps(jwt_data['payload'], indent=2)}")

            jwt_payload = jwt_data['payload']

            #Let's check only the email address from the JWT token, 
            #as the rest of fields are already validated by Copilot to 
            #perform the request (correctly signed, not expired, etc).

            if "unique_name" in jwt_payload:

                email = jwt_payload["unique_name"]
                return email

    raise EmailNotFoundException("JWT", "Email not found on jwt token")

def decode_special_microsoft_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(pad_b64(parts[0])).decode())

        encoded_payload = parts[1].strip().split(".")[0]

        missing_padding = len(encoded_payload) % 4
        if missing_padding:
            encoded_payload += "=" * (4 - missing_padding)

        raw_payload = base64.urlsafe_b64decode(encoded_payload)

        payload_text = raw_payload.decode('latin1', errors='ignore')  # latin1 avoids decode errors

        patterns = {
            "Emails": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "UUIDs": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            "IP addresses": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "Readable strings": r"[a-zA-Z0-9\.\-_\@\s]{4,}",
        }

        payload_strings = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, payload_text)
            payload_strings[name] = list(set(matches))  # remove duplicates

        return {"header": header, "payload_strings": payload_strings}
    
    except Exception as e:
        ctx.log.warn(f"JWT decoding error: {str(e)}")
        return None
